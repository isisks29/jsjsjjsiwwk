// aqaw_runtime_patch.m —— aqaw 卡密弹窗接管 + 让解密密钥保持“已激活”（注入用）
//
// 这一版的原则是“能不调用就不调用、能不碰就不碰”：
//   * 不修改任何代码页（iOS 18 会因代码页签名失效直接闪退）；
//   * 不调用 aqaw 里的任何函数（上一版会调用它的密钥安装函数，可能导致
//     和 App 自身初始化竞争而闪退）；
//   * 只做两件事：
//       1. 用 Objective-C 运行时把卡密类里“只负责弹窗”的三个方法换成空函数；
//       2. 在 App 自己把解密密钥装好之后，记下这组值，之后每 50 毫秒比对
//          一次，一旦卡密失败流程把它改乱就写回（数据页，不涉及签名）。
//
// 使用前提：App 里的 aqaw.dylib 必须是【原版】。
//
// 编译（Theos）：
//       TARGET = iphone:clang:latest:14.0
//       ARCHS = arm64 arm64e
//       aqaw_runtime_patch_FILES = aqaw_runtime_patch.m
//       aqaw_runtime_patch_FRAMEWORKS = Foundation
//
// 日志：App 的 Documents 目录/aqaw_hook.log（第一行打印完整路径），同时 NSLog。
//
// 判读：
//   「钩子: … 已接管」= 弹窗入口已经失效；
//   「密钥: 已记录启动密钥」= 拿到了正确密钥；
//   「密钥: 被失败流程改乱，已恢复」= 失败流程动过密钥，被我们按 50ms 恢复。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

// ---------------- 关键地址（文件偏移 = 虚拟地址） ----------------
static const uint64_t OFF_K48 = 0x1644048;  // 8 字节密钥
static const uint64_t OFF_K50 = 0x1644050;  // 4 字节密钥（失败流程会把它清零）
static const uint64_t OFF_K54 = 0x1644054;  // 4 字节密钥
static const uint64_t OFF_K58 = 0x1644058;  // 4 字节密钥

typedef struct {
    uint64_t k48;
    uint32_t k50, k54, k58;
} KeyState;

static intptr_t g_slide = 0;
static BOOL g_found = NO;
static BOOL g_hooked = NO;
static BOOL g_snap = NO;
static BOOL g_haveFirst = NO;
static KeyState g_good;      // 已确认的正确密钥
static KeyState g_first;     // 最早读到的非零密钥（兜底）
static KeyState g_cand;      // 候选密钥
static int g_candCount = 0;
static int g_tick = 0;
static int g_restores = 0;

static NSMutableString *g_log = nil;
static NSString *g_logPath = nil;
static dispatch_queue_t g_q = nil;
static dispatch_source_t g_timer = nil;

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
static KeyState read_keys(void) {
    KeyState s = {0, 0, 0, 0};
    memcpy(&s.k48, (const void *)(g_slide + (intptr_t)OFF_K48), sizeof(uint64_t));
    memcpy(&s.k50, (const void *)(g_slide + (intptr_t)OFF_K50), sizeof(uint32_t));
    memcpy(&s.k54, (const void *)(g_slide + (intptr_t)OFF_K54), sizeof(uint32_t));
    memcpy(&s.k58, (const void *)(g_slide + (intptr_t)OFF_K58), sizeof(uint32_t));
    return s;
}

static void write_keys(KeyState s) {
    memcpy((void *)(g_slide + (intptr_t)OFF_K48), &s.k48, sizeof(uint64_t));
    memcpy((void *)(g_slide + (intptr_t)OFF_K50), &s.k50, sizeof(uint32_t));
    memcpy((void *)(g_slide + (intptr_t)OFF_K54), &s.k54, sizeof(uint32_t));
    memcpy((void *)(g_slide + (intptr_t)OFF_K58), &s.k58, sizeof(uint32_t));
}

static BOOL key_equal(KeyState a, KeyState b) {
    return a.k48 == b.k48 && a.k50 == b.k50 && a.k54 == b.k54 && a.k58 == b.k58;
}

static NSString *key_desc(KeyState s) {
    return [NSString stringWithFormat:@"%016llX/%08X/%08X/%08X",
            (unsigned long long)s.k48, s.k50, s.k54, s.k58];
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
    if (!cls) {
        if ((g_tick % 100) == 0) {
            plog(@"钩子: 还没找到卡密类，继续等待");
            flush_log();
        }
        return NO;
    }

    const char *sels[] = {
        "va2429730c25654",
        "v59341b48b7a63c:",
        "v470d683f8c0e8f:endTime:",
    };
    IMP imps[] = { (IMP)aq_noop0, (IMP)aq_noop1, (IMP)aq_noop2 };
    int ok = 0;
    for (size_t i = 0; i < sizeof(sels) / sizeof(sels[0]); i++) {
        SEL sel = sel_registerName(sels[i]);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) continue;
        method_setImplementation(m, imps[i]);
        ok += 1;
    }
    if (ok > 0) {
        g_hooked = YES;
        plog(@"钩子: 接管 %d/3 个弹窗方法（类 %s）", ok, class_getName(cls));
        flush_log();
        return YES;
    }
    return NO;
}

// ---------------- 每 50 毫秒巡检 ----------------
static void aq_tick(void) {
    g_tick += 1;

    if (!g_found && !locate_image()) return;
    if (!g_hooked && (g_tick <= 5 || (g_tick % 10) == 0)) hook_once();

    KeyState cur = read_keys();

    // 记录最早读到的非零密钥（正常安装一定是非零的）
    if (!g_haveFirst && cur.k50 != 0) {
        g_first = cur;
        g_haveFirst = YES;
        plog(@"[密钥] 首次读到启动密钥: %@", key_desc(cur));
        flush_log();
    }

    if (!g_snap) {
        if (cur.k50 != 0) {
            // 连续两次读到同一组非零值，认定启动安装已经完成
            if (g_candCount > 0 && key_equal(cur, g_cand)) {
                g_candCount += 1;
            } else {
                g_cand = cur;
                g_candCount = 1;
            }
            if (g_candCount >= 2) {
                g_good = cur;
                g_snap = YES;
                plog(@"[密钥] 已记录启动密钥: %@", key_desc(g_good));
                flush_log();
            }
            return;
        }
        g_candCount = 0;
        if (g_haveFirst && g_tick >= 20) {
            // 1 秒时仍是被改乱状态：用最早读到的正确值兜底
            g_good = g_first;
            g_snap = YES;
            plog(@"[密钥] 当前已被改乱，改用最早读到的正确值: %@", key_desc(g_good));
            write_keys(g_good);
            flush_log();
        } else if ((g_tick % 100) == 0) {
            plog(@"[密钥] 等待启动密钥就绪…");
            flush_log();
        }
        return;
    }

    if (key_equal(cur, g_good)) return;

    if (cur.k50 == 0) {
        // 失败流程的典型特征：4050 被清零，其它被随机化
        write_keys(g_good);
        g_restores += 1;
        if (g_restores <= 10 || (g_restores % 20) == 0) {
            plog(@"[密钥] 被失败流程改乱，已恢复（第 %d 次）: %@ -> %@",
                 g_restores, key_desc(cur), key_desc(g_good));
            flush_log();
        }
    } else {
        // 非清零的变化，视为 App 自己重新安装了密钥，跟随更新
        plog(@"[密钥] 跟随 App 的更新: %@ -> %@", key_desc(g_good), key_desc(cur));
        g_good = cur;
        flush_log();
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

    // 所有运行时操作都留到定时器里做，构造函数只负责建日志和定时器
    g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, g_q);
    if (!g_timer) return;
    uint64_t interval = 50ull * NSEC_PER_MSEC;
    dispatch_source_set_timer(g_timer,
                              dispatch_time(DISPATCH_TIME_NOW, interval),
                              interval,
                              10ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(g_timer, ^{ aq_tick(); });
    dispatch_resume(g_timer);
}
