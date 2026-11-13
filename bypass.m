// aqaw_probe.m —— aqaw.dylib 运行时只读诊断（作业用）
//
// 目的：把「卡密校验到底改了哪些内存 / 面板有没有被创建」如实打出来。
//       全程只读：不改内存、不改界面、不改变任何业务状态，
//       因此不会出现「从后台线程改 UI 导致闪退」那类副作用。
//
// 编译（Theos 示例）：
//       TARGET = iphone:clang:latest:14.0
//       ARCHS = arm64 arm64e
//       aqaw_probe_FILES = aqaw_probe.m
//       aqaw_probe_FRAMEWORKS = UIKit Foundation
//   也可以把本文件加进你自己的 dylib 工程，随注入包一起加载。
//
// 输出位置（按优先级）：
//       App Documents 目录/aqaw_probe.log
//       NSTemporaryDirectory()/aqaw_probe.log
//   同时用 NSLog 输出，Xcode / 系统控制台可直接查看。
//   日志里的前几行会打印完整落盘路径。
//
// 关键地址（均为 aqaw.dylib 内部偏移，运行时要加镜像 slide）：
//       0x7F8988   密钥流随机化函数（补丁 P1 目标）
//       0x7EEC04   卡密输入弹窗构建函数（补丁 P2 目标）
//       0x7F70E8   附属提示弹窗（补丁 P3 目标）
//       0x1644048 / 0x1644050 / 0x1644054 / 0x1644058
//                  字符串/逻辑解密用的密钥流全局
//       0xA19EE0   面板创建前的密钥流一致性自检（返回 1 = 通过）
//
// 判读方法：
//   * 未打补丁：启动几秒后 0x1644050 变 0（或四个值整体变动），
//     说明卡密状态机走了「未授权」分支、把密钥流随机化/清零了。
//   * 打过补丁：0x1644050 保持非零且不再变化；0x7F8988 的首 4 字节
//     应为 c0 03 5f d6（ret）。
//   * 日志中「判定: 已打补丁」即四处机器码全部符合预期。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <stdint.h>
#import <string.h>

static intptr_t g_slide = 0;
static BOOL g_found = NO;
static NSMutableString *g_log = nil;
static NSString *g_logPath = nil;
static dispatch_queue_t g_q;

static void plog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[aqaw-probe] %@", s);
    @synchronized (g_log) {
        if (g_log) {
            [g_log appendString:s];
            [g_log appendString:@"\n"];
        }
    }
}

static void flush_log(void) {
    if (!g_log || !g_logPath) return;
    NSData *d;
    @synchronized (g_log) {
        d = [g_log dataUsingEncoding:NSUTF8StringEncoding];
    }
    [d writeToFile:g_logPath atomically:YES];
}

static uint32_t rd32(uint64_t off) {
    uint32_t v = 0;
    memcpy(&v, (const void *)(g_slide + (intptr_t)off), sizeof(v));
    return v;
}

static uint64_t rd64(uint64_t off) {
    uint64_t v = 0;
    memcpy(&v, (const void *)(g_slide + (intptr_t)off), sizeof(v));
    return v;
}

// 找到 aqaw.dylib 在进程里的镜像并记录 slide
static void locate_image(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "aqaw") || strstr(name, "AQaw") || strstr(name, "AQAR")) {
            g_slide = _dyld_get_image_vmaddr_slide(i);
            g_found = YES;
            plog(@"镜像命中: %s  index=%u  slide=0x%llX", name, i,
                 (unsigned long long)g_slide);
            return;
        }
    }
    plog(@"未找到名为 aqaw 的镜像（共 %u 个镜像）", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) plog(@"  镜像[%u] %s", i, name);
    }
}

static void dump_keystream(NSString *tag) {
    if (!g_found) return;
    plog(@"[%@] 密钥流: 4048=0x%016llX  4050=0x%08X  4054=0x%08X  4058=0x%08X",
         tag,
         (unsigned long long)rd64(0x1644048),
         rd32(0x1644050), rd32(0x1644054), rd32(0x1644058));
}

static void dump_patch_bytes(void) {
    if (!g_found) return;
    uint32_t p1  = rd32(0x7F8988);
    uint32_t p2  = rd32(0x7EEC04);
    uint32_t p2b = rd32(0x7EEC08);
    uint32_t p3  = rd32(0x7F70E8);
    plog(@"补丁点字节: 0x7F8988=%08X  0x7EEC04=%08X  0x7EEC08=%08X  0x7F70E8=%08X",
         p1, p2, p2b, p3);
    BOOL ok = (p1 == 0xD65F03C0 && p2 == 0xD2800000 &&
               p2b == 0xD65F03C0 && p3 == 0xD65F03C0);
    plog(@"判定: %@", ok ? @"已打补丁" : @"未打补丁（或版本不同）");
    if (!ok) {
        plog(@"期望:   0x7F8988=D65F03C0  0x7EEC04=D2800000  "
             @"0x7EEC08=D65F03C0  0x7F70E8=D65F03C0");
    }
}

// ---------------- 方法埋点：替换实现，只记录，再调用原实现 ----------------
// 签名来自类的方法表，均已核对：
//   -[_0x2F9C7E14 va2429730c25654]              v16@0:8      （无参，void）
//   -[_0x2F9C7E14 v59341b48b7a63c:]             v24@0:8@16   （1 个 id）
//   -[_0x2F9C7E14 v470d683f8c0e8f:endTime:]     v32@0:8@16@24（2 个 id）
static IMP g_orig_a = NULL;
static IMP g_orig_b = NULL;
static IMP g_orig_c = NULL;

static void hook_a(id self, SEL _cmd) {
    plog(@"调用 -[_0x2F9C7E14 va2429730c25654]（读卡密 / 触发输入）");
    if (g_orig_a) ((void (*)(id, SEL))g_orig_a)(self, _cmd);
}

static void hook_b(id self, SEL _cmd, id arg) {
    plog(@"调用 -[_0x2F9C7E14 v59341b48b7a63c:] arg=%@", arg);
    if (g_orig_b) ((void (*)(id, SEL, id))g_orig_b)(self, _cmd, arg);
}

static void hook_c(id self, SEL _cmd, id a, id b) {
    plog(@"调用 -[_0x2F9C7E14 v470d683f8c0e8f:endTime:] a=%@ b=%@", a, b);
    if (g_orig_c) ((void (*)(id, SEL, id, id))g_orig_c)(self, _cmd, a, b);
}

static BOOL hook_method(Class cls, const char *selName, IMP newImp, IMP *origOut) {
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return YES;
}

static void install_hooks(void) {
    Class c = objc_getClass("_0x2F9C7E14");
    if (!c) {
        plog(@"未找到卡密类 _0x2F9C7E14，跳过方法埋点");
        return;
    }
    BOOL a = hook_method(c, "va2429730c25654", (IMP)hook_a, &g_orig_a);
    BOOL b = hook_method(c, "v59341b48b7a63c:", (IMP)hook_b, &g_orig_b);
    BOOL d = hook_method(c, "v470d683f8c0e8f:endTime:", (IMP)hook_c, &g_orig_c);
    plog(@"方法埋点: 读卡密=%@  单参=%@  双参=%@",
         a ? @"成功" : @"缺失", b ? @"成功" : @"缺失", d ? @"成功" : @"缺失");
}

// ---------------- 界面状态（只读，必须主线程） ----------------
static void dump_ui_state(void) {
    if (!g_found) return;
    Class panelCls = objc_getClass("_0x1E6B7A93");
    Class winCls   = objc_getClass("_0x8C2F4D71");
    Class iconCls  = objc_getClass("_0xD4E9A3C7");
    plog(@"类存在性: 面板=%@ 悬浮窗=%@ 图标=%@",
         panelCls ? @"有" : @"无", winCls ? @"有" : @"无", iconCls ? @"有" : @"无");

    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (winCls && [w isKindOfClass:winCls]) {
            plog(@"发现悬浮窗: level=%.0f hidden=%d alpha=%.2f frame=%@ 子视图=%lu",
                 w.windowLevel, (int)w.hidden, (double)w.alpha,
                 NSStringFromCGRect(w.frame), (unsigned long)w.subviews.count);
            for (UIView *v in w.subviews) {
                plog(@"  子视图 %@ frame=%@ hidden=%d alpha=%.2f",
                     NSStringFromClass([v class]), NSStringFromCGRect(v.frame),
                     (int)v.hidden, (double)v.alpha);
            }
        }
    }

    UIWindow *kw = nil;
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (w.isKeyWindow) { kw = w; break; }
    }
    if (kw) {
        plog(@"关键窗口: %@", NSStringFromClass([kw class]));
        for (UIView *v in kw.subviews) {
            if (panelCls && [v isKindOfClass:panelCls]) {
                plog(@"  关键窗口内发现面板: frame=%@ hidden=%d alpha=%.2f 子视图=%lu",
                     NSStringFromCGRect(v.frame), (int)v.hidden, (double)v.alpha,
                     (unsigned long)v.subviews.count);
            }
        }
    }
}

__attribute__((constructor))
static void aqaw_probe_start(void) {
    g_q = dispatch_queue_create("aqaw.probe", DISPATCH_QUEUE_SERIAL);
    g_log = [NSMutableString string];
    [g_log appendString:@"========== aqaw 运行时诊断 ==========\n"];

    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES);
    if (dirs.count) {
        g_logPath = [dirs[0] stringByAppendingPathComponent:@"aqaw_probe.log"];
    } else {
        g_logPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"aqaw_probe.log"];
    }
    plog(@"日志文件: %@", g_logPath);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   g_q, ^{
        locate_image();
        dump_patch_bytes();
        dump_keystream(@"1s");
        install_hooks();
        flush_log();
    });

    // 2s 起每秒采一次密钥流，共 29 次；纯读内存，不碰界面
    for (int i = 2; i <= 30; i++) {
        NSString *tag = [NSString stringWithFormat:@"%ds", i];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * NSEC_PER_SEC)),
                       g_q, ^{
            if (!g_found) return;
            dump_keystream(tag);
            flush_log();
        });
    }

    // 界面状态只在主线程查，且只读
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ dump_ui_state(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ dump_ui_state(); flush_log(); });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(32.0 * NSEC_PER_SEC)),
                   g_q, ^{ plog(@"诊断结束。"); flush_log(); });
}
