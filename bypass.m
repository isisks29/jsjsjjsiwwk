// aqaw_runtime_patch.m —— aqaw 运行时内存补丁 + 弹窗记录（注入用）
//
// 为什么还要这个版本：
//   如果 App 里本来就自带一份 aqaw，或者注入工具是「新增一个 dylib」而不是
//   「替换原文件」，那么改文件的方式不会生效，旧的那份仍然会弹卡密框。
//   本文件作为独立 dylib 注入，在加载时直接改写内存里正在运行的 aqaw 代码，
//   无论它是从哪个路径加载的都能打上补丁。
//
// 它做两件事：
//   1. 在内存里把下面 5 处改成直接返回（与文件补丁完全相同的机器码）；
//   2. 之后 45 秒内每 0.35 秒看一次屏幕上的弹窗，把标题/正文/按钮/输入框
//      写进日志（只读，不改界面）。
//
// 编译（Theos）：
//       TARGET = iphone:clang:latest:14.0
//       ARCHS = arm64 arm64e
//       aqaw_runtime_patch_FILES = aqaw_runtime_patch.m
//       aqaw_runtime_patch_FRAMEWORKS = UIKit Foundation
//
// 日志：App 的 Documents 目录/aqaw_patch.log（第一行会打印完整路径），
//       同时 NSLog 输出。
//
// 判读：
//   「镜像命中 … slide=…」+「写入成功」= 补丁已在内存里生效；
//   「判定: 已打补丁」= 回读确认；
//   之后如果仍出现「弹窗:」行，说明还有别的弹窗来源，日志里的文字就是线索。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>
#import <stdint.h>
#import <string.h>

// ---------- 与文件补丁一致的 6 处改动 ----------
typedef struct {
    uint32_t off;
    uint32_t oldv;
    uint32_t newv;
    const char *desc;
} PatchSite;

static const PatchSite kSites[] = {
    {0x007F8988, 0xD100C3FF, 0xD65F03C0, "P1 禁用密钥流随机化"},
    {0x007EEC04, 0xA9BA6FFC, 0xD2800000, "P2 卡密输入弹窗 -> mov x0,#0"},
    {0x007EEC08, 0xA90167FA, 0xD65F03C0, "P2 紧随其后 ret"},
    {0x007F70E8, 0xA9BA6FFC, 0xD65F03C0, "P3 附属提示弹窗"},
    {0x007F4280, 0x6DB923E9, 0xD65F03C0, "P4 卡密提示信息方法"},
    {0x007F1804, 0xA9BA6FFC, 0xD65F03C0, "P5 卡密到期信息方法"},
};

static intptr_t g_slide = 0;
static BOOL g_found = NO;
static NSMutableString *g_log = nil;
static NSString *g_logPath = nil;
static dispatch_queue_t g_q;
static NSString *g_lastAlert = nil;

static void plog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[aqaw-patch] %@", s);
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

static uint32_t rd32(uint64_t off) {
    uint32_t v = 0;
    memcpy(&v, (const void *)(g_slide + (intptr_t)off), sizeof(v));
    return v;
}

static BOOL locate_image(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "aqaw") || strstr(name, "AQaw") ||
            strstr(name, "AQAR") || strstr(name, "Aqaw")) {
            g_slide = _dyld_get_image_vmaddr_slide(i);
            g_found = YES;
            plog(@"镜像命中: %s  slide=0x%llX", name, (unsigned long long)g_slide);
            return YES;
        }
    }
    return NO;
}

static BOOL patch_one(const PatchSite *s) {
    uint64_t addr = (uint64_t)(g_slide + (intptr_t)s->off);
    uint32_t cur = rd32(s->off);
    if (cur == s->newv) {
        plog(@"跳过（已是补丁后状态）0x%X %s", s->off, s->desc);
        return YES;
    }
    if (cur != s->oldv) {
        plog(@"跳过（原始字节不符）0x%X 实际=%08X 期望=%08X %s",
             s->off, cur, s->oldv, s->desc);
        return NO;
    }
    vm_address_t page = (vm_address_t)(addr & ~(uint64_t)(vm_page_size - 1));
    vm_size_t span = (vm_size_t)((addr + 4 - page + vm_page_size - 1) & ~(uint64_t)(vm_page_size - 1));
    kern_return_t kr = vm_protect(mach_task_self(), page, span, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        plog(@"写入失败 0x%X vm_protect=%d", s->off, (int)kr);
        return NO;
    }
    memcpy((void *)addr, &s->newv, sizeof(uint32_t));
    sys_icache_invalidate((void *)addr, sizeof(uint32_t));
    vm_protect(mach_task_self(), page, span, false,
               VM_PROT_READ | VM_PROT_EXECUTE);
    uint32_t after = rd32(s->off);
    BOOL ok = (after == s->newv);
    plog(@"写入%@ 0x%X %08X -> %08X %s",
         ok ? @"成功" : @"失败", s->off, s->oldv, after, s->desc);
    return ok;
}

static void apply_patches(void) {
    if (!g_found && !locate_image()) return;
    int ok = 0;
    for (size_t i = 0; i < sizeof(kSites) / sizeof(kSites[0]); i++) {
        if (patch_one(&kSites[i])) ok += 1;
    }
    plog(@"补丁结果: %d/%zu 处生效", ok, sizeof(kSites) / sizeof(kSites[0]));
    flush_log();
}

static void dump_state(NSString *tag) {
    if (!g_found) return;
    uint32_t p1 = rd32(0x7F8988), p2 = rd32(0x7EEC04), p3 = rd32(0x7F70E8);
    uint32_t p4 = rd32(0x7F4280), p5 = rd32(0x7F1804);
    uint64_t k48 = 0; memcpy(&k48, (const void *)(g_slide + 0x1644048), 8);
    uint32_t k50 = rd32(0x1644050), k54 = rd32(0x1644054), k58 = rd32(0x1644058);
    plog(@"[%@] P1=%08X P2=%08X P3=%08X P4=%08X P5=%08X", tag, p1, p2, p3, p4, p5);
    plog(@"[%@] 密钥流 4048=%016llX 4050=%08X 4054=%08X 4058=%08X",
         tag, (unsigned long long)k48, k50, k54, k58);
}

// 只读检查当前弹窗（主线程）
static void inspect_alerts(void) {
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        if (!app) return;
        NSArray *windows = [[app windows] copy];
        UIViewController *top = nil;
        for (UIWindow *w in windows) {
            if (![w isKindOfClass:[UIWindow class]]) continue;
            if (w.isKeyWindow) { top = w.rootViewController; break; }
        }
        if (!top) {
            for (UIWindow *w in windows) {
                if ([w isKindOfClass:[UIWindow class]] && w.rootViewController) {
                    top = w.rootViewController; break;
                }
            }
        }
        int depth = 0;
        while (top.presentedViewController && depth < 8) {
            top = top.presentedViewController; depth += 1;
        }
        if (![top isKindOfClass:[UIAlertController class]]) return;

        UIAlertController *a = (UIAlertController *)top;
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
        plog(@"检查弹窗异常: %@", e.reason ?: @"未知");
    }
}

__attribute__((constructor))
static void aqaw_patch_start(void) {
    g_q = dispatch_queue_create("aqaw.patch", DISPATCH_QUEUE_SERIAL);
    g_log = [NSMutableString string];
    [g_log appendString:@"========== aqaw 内存补丁 ==========\n"];

    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES);
    g_logPath = dirs.count
        ? [dirs[0] stringByAppendingPathComponent:@"aqaw_patch.log"]
        : [NSTemporaryDirectory() stringByAppendingPathComponent:@"aqaw_patch.log"];
    plog(@"日志文件: %@", g_logPath);

    // 找不到镜像就重试几次（覆盖 aqaw 比本 dylib 晚加载的情况）
    for (int i = 0; i < 10; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * i * NSEC_PER_SEC)),
                       g_q, ^{
            if (g_found) return;
            apply_patches();
            if (g_found) dump_state(@"写入后");
        });
    }

    // 密钥流采样：确认 P1 生效后不再被随机化
    int secs[] = {2, 5, 10, 20, 35};
    for (int i = 0; i < 5; i++) {
        int s = secs[i];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(s * NSEC_PER_SEC)),
                       g_q, ^{
            NSString *tag = [NSString stringWithFormat:@"%ds", s];
            dump_state(tag);
            flush_log();
        });
    }

    // 弹窗观察：0.35 秒一次，约 45 秒，只读
    for (int i = 0; i < 130; i++) {
        double delay = 0.35 * i;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ inspect_alerts(); });
    }

    flush_log();
}
