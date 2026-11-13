// aqaw_runtime_patch.m —— aqaw 卡密弹窗接管 + 让解密密钥保持“已激活”（注入用）
//
// 为什么不再改文件、也不在内存里改代码：
//   iOS 18 对代码页有签名校验。只要某个代码页的指令被改过（替换文件后没有
//   重新签名，或者运行时用 vm_protect 改写代码页），这个页就会变成不可执行，
//   App 一旦执行到这一页就闪退（崩溃日志里是 CODESIGNING / Invalid Page /
//   KERN_PROTECTION_FAILURE）。上一版运行时补丁正是踩了这个坑。
//
//   本文件完全不碰任何代码页，只做三件事：
//     1. 用 Objective-C 运行时把卡密类里“只负责弹窗”的三个方法换成空函数，
//        弹窗就不会再出现（方法表在数据段，不触发代码签名校验）；
//     2. 调用 aqaw 自带的密钥安装函数 0x814F44，把设备号推导出的正确解密
//        密钥装回去，相当于“已激活”的状态；
//     3. 每 0.1 秒检查一次那组密钥，一旦被卡密失败流程改乱，立刻恢复，
//        并写日志。
//
// 使用前提：App 里的 aqaw.dylib 必须是【原版】。如果之前替换成了打过补丁的
//   文件，请先换回原版，否则那个被改过的代码页仍然会闪退。
//
// 编译（Theos）：
//       TARGET = iphone:clang:latest:14.0
//       ARCHS = arm64 arm64e
//       aqaw_runtime_patch_FILES = aqaw_runtime_patch.m
//       aqaw_runtime_patch_FRAMEWORKS = UIKit Foundation
//
// 日志：App 的 Documents 目录/aqaw_hook.log（第一行打印完整路径），同时 NSLog。
//
// 判读：
//   「钩子: … 已接管」= 弹窗入口已经失效；
//   「密钥: 快照 …」= 已装回正确密钥；
//   「密钥: 被改乱，已恢复」= 卡密失败流程动过密钥，已被秒级恢复。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

// ---------------- 关键地址（文件偏移 = 虚拟地址） ----------------
static const uint64_t OFF_INSTALL = 0x814F44;   // 由设备号推导并写入解密密钥
static const uint64_t OFF_K48     = 0x1644048;  // 8 字节密钥
static const uint64_t OFF_K50     = 0x1644050;  // 4 字节密钥
static const uint64_t OFF_K54     = 0x1644054;  // 4 字节密钥
static const uint64_t OFF_K58     = 0x1644058;  // 4 字节密钥

typedef void (*AqawInstallFn)(void);

static intptr_t g_slide = 0;
static BOOL g_found = NO;
static BOOL g_hooked = NO;
static BOOL g_snap = NO;
static int g_tick = 0;
static int g_restores = 0;
static uint64_t g_k48 = 0;
static uint32_t g_k50 = 0, g_k54 = 0, g_k58 = 0;

static NSMutableString *g_log = nil;
static NSString *g_logPath = nil;
static dispatch_queue_t g_q = nil;
static dispatch_source_t g_timer = nil;
static NSString *g_lastAlert = nil;

static void plog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[aqaw-hook] %@", s);
    @synchronized (g_log) {
        if (g_log) { [g_log appendString:s]; [g_log appendString:@"\n"]; }
    }
}

static void flush_log(void) {
    if (!g_log || !g_logPath) return;
    NSData *d;
    @synchronized (g_log) { d = [g_log dataUsingEncoding:NSUTF8StringEncoding]; }
    [d writeToFile:g_logPath atomically:YES];
}

// ---------------- 定位 aqaw 镜像 ----------------
static BOOL locate_image(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "aqaw") || strstr(name, "AQaw") ||
            strstr(name, "Aqaw") || strstr(name, "AQAR")) {
            g_slide = _dyld_get_image_vmaddr_slide(i);
            g_found = YES;
            plog(@"镜像: %s  slide=0x%llX", name, (unsigned long long)g_slide);
            flush_log();
            return YES;
        }
    }
    return NO;
}

// ---------------- 读取 / 写入密钥（数据页，安全） ----------------
static uint64_t rd64(uint64_t off) {
    uint64_t v = 0;
    memcpy(&v, (const void *)(g_slide + (intptr_t)off), sizeof(v));
    return v;
}
static uint32_t rd32(uint64_t off) {
    uint32_t v = 0;
    memcpy(&v, (const void *)(g_slide + (intptr_t)off), sizeof(v));
    return v;
}
static void wr64(uint64_t off, uint64_t v) {
    memcpy((void *)(g_slide + (intptr_t)off), &v, sizeof(v));
}
static void wr32(uint64_t off, uint32_t v) {
    memcpy((void *)(g_slide + (intptr_t)off), &v, sizeof(v));
}

// ---------------- 弹窗方法接管 ----------------
static void aq_noop0(id self, SEL _cmd) {}
static void aq_noop1(id self, SEL _cmd, id a) {}
static void aq_noop2(id self, SEL _cmd, id a, id b) {}

static Class find_license_class(void) {
    Class c = objc_getClass("_0x2F9C7E14");
    if (c) return c;
    c = objc_getClass("0x2F9C7E14");
    if (c) return c;

    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return Nil;
    Class *list = (Class *)malloc(sizeof(Class) * count);
    if (!list) return Nil;
    count = objc_getClassList(list, count);
    Class hit = Nil;
    for (int i = 0; i < count; i++) {
        const char *n = class_getName(list[i]);
        if (n && strstr(n, "0x2F9C7E14")) { hit = list[i]; break; }
    }
    free(list);
    return hit;
}

static BOOL hook_once(void) {
    Class cls = find_license_class();
    if (!cls) return NO;

    int ok = 0;
    const char *sels[] = {
        "va2429730c25654",
        "v59341b48b7a63c:",
        "v470d683f8c0e8f:endTime:",
    };
    IMP imps[] = { (IMP)aq_noop0, (IMP)aq_noop1, (IMP)aq_noop2 };
    for (size_t i = 0; i < sizeof(sels) / sizeof(sels[0]); i++) {
        SEL sel = sel_registerName(sels[i]);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) continue;
        IMP old = method_setImplementation(m, imps[i]);
        plog(@"钩子: %s %@ (原实现 %p)", sels[i],
             old ? @"已接管" : @"设置完成", (void *)old);
        ok += 1;
    }
    if (ok > 0) {
        g_hooked = (ok == 3);
        plog(@"钩子: 共接管 %d/3 个弹窗方法（类 %s）", ok, class_getName(cls));
        flush_log();
        return YES;
    }
    return NO;
}

// ---------------- 密钥快照与恢复 ----------------
static void take_snapshot(const char *why) {
    g_k48 = rd64(OFF_K48);
    g_k50 = rd32(OFF_K50);
    g_k54 = rd32(OFF_K54);
    g_k58 = rd32(OFF_K58);
    g_snap = YES;
    plog(@"[密钥] 快照(%s) 4048=%016llX 4050=%08X 4054=%08X 4058=%08X",
         why, (unsigned long long)g_k48, g_k50, g_k54, g_k58);
    flush_log();
}

static void install_good_keys(const char *why) {
    AqawInstallFn fn = (AqawInstallFn)(g_slide + (intptr_t)OFF_INSTALL);
    if (fn) fn();
    take_snapshot(why);
}

// 只读看一眼当前弹窗（主线程调用，全部 @try 包住）
static void inspect_alert(void) {
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        if (!app) return;
        UIWindow *w = app.keyWindow;
        if (!w) return;
        UIViewController *vc = w.rootViewController;
        int depth = 0;
        while (vc.presentedViewController && depth < 8) {
            vc = vc.presentedViewController;
            depth += 1;
        }
        if (![vc isKindOfClass:[UIAlertController class]]) return;
        UIAlertController *a = (UIAlertController *)vc;
        NSMutableArray *acts = [NSMutableArray array];
        for (UIAlertAction *act in a.actions) {
            if (act.title.length) [acts addObject:act.title];
        }
        NSMutableArray *fields = [NSMutableArray array];
        for (UITextField *tf in a.textFields) {
            [fields addObject:tf.text.length ? tf.text : @"(空)"];
        }
        NSString *sig = [NSString stringWithFormat:@"%@|%@|%@|%@",
                         a.title ?: @"", a.message ?: @"",
                         [acts componentsJoinedByString:@","],
                         [fields componentsJoinedByString:@","]];
        if ([sig isEqualToString:g_lastAlert]) return;
        g_lastAlert = sig;
        plog(@"弹窗: 标题=%@ 正文=%@ 按钮=[%@] 输入框=[%@]",
             a.title ?: @"(无)", a.message ?: @"(无)",
             [acts componentsJoinedByString:@" / "],
             [fields componentsJoinedByString:@" / "]);
        flush_log();
    } @catch (NSException *e) {
        plog(@"查看弹窗异常: %@", e.reason ?: @"未知");
    }
}

// ---------------- 每 0.1 秒一次的巡检 ----------------
static void aq_tick(void) {
    g_tick += 1;

    if (!g_found && !locate_image()) return;

    if (!g_hooked) hook_once();

    // 1.5 秒后（或镜像晚加载后）装一次正确密钥并记下快照
    if (!g_snap) {
        if (g_tick >= 15) install_good_keys("原版安装函数");
        return;
    }

    // 密钥被改乱就立刻写回
    uint64_t c48 = rd64(OFF_K48);
    uint32_t c50 = rd32(OFF_K50);
    uint32_t c54 = rd32(OFF_K54);
    uint32_t c58 = rd32(OFF_K58);
    if (c48 != g_k48 || c50 != g_k50 || c54 != g_k54 || c58 != g_k58) {
        wr64(OFF_K48, g_k48);
        wr32(OFF_K50, g_k50);
        wr32(OFF_K54, g_k54);
        wr32(OFF_K58, g_k58);
        g_restores += 1;
        if (g_restores <= 10 || (g_restores % 50) == 0) {
            plog(@"[密钥] 被改乱，已恢复（第 %d 次）: %016llX/%08X/%08X/%08X -> %016llX/%08X/%08X/%08X",
                 g_restores,
                 (unsigned long long)c48, c50, c54, c58,
                 (unsigned long long)g_k48, g_k50, g_k54, g_k58);
            flush_log();
        }
    }

    // 前两分钟每 5 秒用原版安装函数重新校准一次快照
    if (g_tick % 50 == 0 && g_tick <= 1200) {
        uint64_t o48 = g_k48; uint32_t o50 = g_k50, o54 = g_k54, o58 = g_k58;
        install_good_keys("周期校准");
        if (o48 != g_k48 || o50 != g_k50 || o54 != g_k54 || o58 != g_k58) {
            plog(@"[密钥] 快照已按原版安装函数校正");
            flush_log();
        }
    }

    // 前两分钟每 0.5 秒读一次弹窗（只读，主线程）
    if (g_tick % 5 == 0 && g_tick <= 1200) {
        dispatch_async(dispatch_get_main_queue(), ^{ inspect_alert(); });
    }
}

__attribute__((constructor))
static void aqaw_hook_start(void) {
    g_q = dispatch_queue_create("aqaw.hook", DISPATCH_QUEUE_SERIAL);
    g_log = [NSMutableString string];
    [g_log appendString:@"========== aqaw 注入版补丁（不修改原文件） ==========\n"];

    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES);
    g_logPath = dirs.count
        ? [dirs[0] stringByAppendingPathComponent:@"aqaw_hook.log"]
        : [NSTemporaryDirectory() stringByAppendingPathComponent:@"aqaw_hook.log"];
    plog(@"日志文件: %@", g_logPath);
    flush_log();

    g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, g_q);
    if (!g_timer) return;
    uint64_t interval = 100ull * NSEC_PER_MSEC;
    dispatch_source_set_timer(g_timer,
                              dispatch_time(DISPATCH_TIME_NOW, interval),
                              interval,
                              20ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(g_timer, ^{ aq_tick(); });
    dispatch_resume(g_timer);
}
