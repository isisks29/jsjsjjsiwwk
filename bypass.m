// aqaw_probe.m —— aqaw 运行时处理版（注入用）
//
// 为什么走运行时：
//   实测原样副本能进、等价改写（行为完全一致，只换一种机器码写法）也闪退，
//   说明这个库会校验自己的机器码，任何静态改字节的版本都不可能跑起来。
//   因此这里一个字节都不改 aqaw 的机器码，只在运行时观察它、并替换它
//   调用系统函数时用的指针槽。
//
// 这一版做什么（沿用同类靶场验证过的思路：零 .text 修改）：
//   1. 只把目标库调用 dispatch_async / dispatch_after 用的两个指针槽
//      换成观察函数，记录它丢出去的每个 block 的位置、来源和携带的数据，
//      并在 block 真正执行时再记一笔 —— 只记录、不改任何结果；
//   2. 把未激活时用于跳过面板的那个状态字改回 0（只改数据，不动代码），
//      并监视这一组四个字的变化，原版每次改写都留痕；
//   3. 持续观察面板组件（_0x8C2F4D71 / _0x1E6B7A93 / _0xD4E9A3C7）和
//      界面上新出现的混淆类名；1.2 秒时确认这三个类有没有被注册，并把目标库
//      里所有混淆类名列出来；面板一旦出现就取消隐藏；
//   4. 只读地记录密钥、许可证对象、结构校验结果和窗口构成变化；
//   5. 卡密弹窗出现时只关一次（同一个弹窗不重复关），并记录按钮和输入框，
//      让原版按「未激活」的正常分支继续；
//   6. 约 6 秒弹一次「aqaw 处理信息」窗口，内容同步复制到剪贴板，
//      用来告诉你走到了哪一步、面板有没有出现。
//
// 为什么不再伪造激活状态：
//   实测只要把状态改成「已激活」，原版就会带着这份状态进入自身的加密校验，
//   校验不通过就执行终止指令（闪退）。所以这里只改判定结果，状态保持原样。
//
// 仍然不做的事：
//   * 不修改磁盘文件；
//   * 不替换任何方法；
//   * 不主动调用面板初始化 / 挂载函数（它们依赖启动时的现场，空手调用会崩）；
//   * 不碰卡密以外的界面。
//
// 编译（Theos）：
//       TARGET = iphone:clang:latest:14.0
//       ARCHS = arm64 arm64e
//       aqaw_probe_FILES = aqaw_probe.m
//       aqaw_probe_FRAMEWORKS = UIKit Foundation
//
// 使用：保持原版 aqaw.dylib 不动，把本代码编译成 dylib 注入 App。
//   如果中途闪退，剪贴板里仍然保留闪退前最后的记录。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>
#import <dlfcn.h>
#import <stdint.h>
#import <string.h>
#import <stdlib.h>

typedef struct {
    uint64_t k48;
    uint32_t k50, k54, k58;
} KeyState;

static NSTimeInterval g_start = 0;
static NSMutableString *g_text = nil;
static NSString *g_lastClip = nil;
static intptr_t g_slide = 0;
static BOOL g_found = NO;
static BOOL g_impsLogged = NO;
static BOOL g_presenting = NO;
static BOOL g_shown = NO;
static UIWindow *g_win = nil;
static UIWindow *g_prevKey = nil;
static dispatch_queue_t g_q = nil;
static dispatch_source_t g_timer = nil;
static NSString *g_lastAlertSig = nil;
static NSMutableSet *g_seenVCs = nil;
static int g_tick = 0;
static BOOL g_uiDumped = NO;

static int g_dismissed = 0;
static BOOL g_gate25 = NO;
static BOOL g_gate9 = NO;
static BOOL g_haveKeys = NO;
static KeyState g_lastKeys = {0, 0, 0, 0};
static int g_keyLogCount = 0;
static BOOL g_panelFound = NO;
static int g_lastPanelCount = -1;
static int g_panelChecks = 0;
static BOOL g_hookInstalled = NO;
static int g_hookTries = 0;
static BOOL g_flagLogged = NO;
static NSMutableSet *g_blockSites = nil;
static int g_blockLogs = 0;
static NSMutableSet *g_seenViewClasses = nil;
static int g_flagWrites = 0;
static int g_flagChangeLogs = 0;
static uint32_t g_lastFlagArr[4] = {0xFFFFFFFFu, 0, 0, 0};
static void *g_lastLicenseObj = (void *)0x1;
static NSMutableDictionary *g_siteRuns = nil;
static int g_dispatchRunLogs = 0;
static NSString *g_lastWinSig = nil;
static BOOL g_baseLogged = NO;
static BOOL g_panelClassChecked = NO;

static NSString *aq_snapshot(void);
static void aq_copy(void);
static BOOL aq_install_hooks(void);
static void aq_clear_panel_flag(void);

static double aq_now(void) {
    return [NSProcessInfo processInfo].systemUptime - g_start;
}

static void aq_add(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[aqaw-fix] %@", s);
    @synchronized (g_text) {
        if (g_text) [g_text appendFormat:@"[%.2fs] %@\n", aq_now(), s];
    }
    // 同时落盘一份：万一闪退，记录还在，可以重新打开读取。
    @try {
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        if (dir.length) {
            NSString *path = [dir stringByAppendingPathComponent:@"aqaw_fix_log.txt"];
            [aq_snapshot() writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
    } @catch (NSException *e) {
    }
    // 每秒最多把最新记录自动放进剪贴板一次，闪退后也能直接粘贴出来。
    static double lastAuto = -100.0;
    double now = aq_now();
    if (now - lastAuto >= 1.0) {
        lastAuto = now;
        aq_copy();
    }
}

static NSString *aq_snapshot(void) {
    NSString *s;
    @synchronized (g_text) { s = g_text ? [g_text copy] : @""; }
    return s;
}

static void aq_copy(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *s = aq_snapshot();
        if (!s.length) return;
        if ([s isEqualToString:g_lastClip]) return;
        g_lastClip = [s copy];
        @try {
            [UIPasteboard generalPasteboard].string = s;
        } @catch (NSException *e) {
        }
    });
}

static BOOL aq_locate(void) {
    uint32_t n = _dyld_image_count();
    int best = -1;
    int fallback = -1;
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (!strstr(name, "aqaw") && !strstr(name, "AQaw") &&
            !strstr(name, "Aqaw") && !strstr(name, "AQAR")) continue;
        const char *base = strrchr(name, '/');
        base = base ? base + 1 : name;
        aq_add(@"镜像候选: %s", name);
        if (fallback < 0) fallback = (int)i;
        if (strcmp(base, "aqaw.dylib") == 0) best = (int)i;
    }
    int pick = best >= 0 ? best : fallback;
    if (pick < 0) return NO;
    g_slide = _dyld_get_image_vmaddr_slide(pick);
    uint32_t magic = 0;
    memcpy(&magic, (const void *)g_slide, 4);
    if (magic != 0xFEEDFACF && magic != 0xCFFAEDFE &&
        magic != 0xCAFEBABE && magic != 0xBEBAFECA) {
        aq_add(@"镜像头校验失败: 0x%08X，暂不动手", magic);
        g_slide = 0;
        return NO;
    }
    aq_add(@"找到 aqaw 镜像（第 %d 个，头 0x%08X）", pick, magic);
    g_slide = (intptr_t)_dyld_get_image_vmaddr_slide(pick);
    g_found = YES;
    return YES;
}

// 只读地取当前这组解密密钥（只碰数据，不动代码）
static KeyState aq_read_keys(void) {
    KeyState s = {0, 0, 0, 0};
    if (!g_found) return s;
    memcpy(&s.k48, (const void *)(g_slide + 0x1644048), 8);
    memcpy(&s.k50, (const void *)(g_slide + 0x1644050), 4);
    memcpy(&s.k54, (const void *)(g_slide + 0x1644054), 4);
    memcpy(&s.k58, (const void *)(g_slide + 0x1644058), 4);
    return s;
}

static BOOL aq_key_equal(KeyState a, KeyState b) {
    return a.k48 == b.k48 && a.k50 == b.k50 && a.k54 == b.k54 && a.k58 == b.k58;
}

static NSString *aq_key_desc(KeyState s) {
    return [NSString stringWithFormat:@"%016llX/%08X/%08X/%08X",
            (unsigned long long)s.k48, s.k50, s.k54, s.k58];
}

// 只读记录三个弹窗方法当前实现（用于确认有没有被别的东西改过）
static void aq_log_imps(void) {
    Class cls = objc_getClass("_0x2F9C7E14");
    if (!cls) {
        aq_add(@"卡密类还没有注册");
        return;
    }
    const char *sels[3] = {
        "va2429730c25654",
        "v59341b48b7a63c:",
        "v470d683f8c0e8f:endTime:",
    };
    uint64_t exps[3] = { 0x7F6A20, 0x7F4280, 0x7F1804 };
    BOOL all = YES;
    for (int i = 0; i < 3; i++) {
        Method m = class_getInstanceMethod(cls, sel_registerName(sels[i]));
        if (!m) { all = NO; continue; }
        unsigned long off = (unsigned long)((uintptr_t)method_getImplementation(m) -
                                            (uintptr_t)g_slide);
        if (off != exps[i]) all = NO;
    }
    aq_add(@"弹窗方法实现%@", all ? @"未被改动" : @"与预期不一致");
    g_impsLogged = YES;
}

// 自动关闭带输入框的卡密弹窗（只处理带输入框的）
static void aq_handle_license_alert(void) {
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        if (!app) return;
        NSMutableArray<UIWindow *> *wins = [NSMutableArray array];
        for (UIScene *s in app.connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) {
                [wins addObjectsFromArray:((UIWindowScene *)s).windows];
            }
        }
        if (wins.count == 0) {
            NSArray *legacy = [app windows];
            if (legacy.count) [wins addObjectsFromArray:legacy];
        }
        for (UIWindow *w in wins) {
            if (![w isKindOfClass:[UIWindow class]]) continue;
            if (g_win && w == g_win) continue;
            UIViewController *vc = w.rootViewController;
            int depth = 0;
            while (vc.presentedViewController && depth < 6) {
                vc = vc.presentedViewController;
                depth += 1;
            }
            if (![vc isKindOfClass:[UIAlertController class]]) {
                // 只记录类型，不处理，方便判断卡密弹窗是不是另一种控件
                if (!g_seenVCs) g_seenVCs = [NSMutableSet set];
                NSString *cn = NSStringFromClass([vc class]);
                if (cn && ![g_seenVCs containsObject:cn]) {
                    [g_seenVCs addObject:cn];
                    aq_add(@"发现其他弹窗类型: %@（未处理）", cn);
                }
                continue;
            }
            UIAlertController *a = (UIAlertController *)vc;
            if (a.textFields.count == 0) continue;   // 只处理卡密输入框

            NSString *sig = [NSString stringWithFormat:@"%@|%@|%lu",
                             a.title ?: @"", a.message ?: @"",
                             (unsigned long)a.textFields.count];
            if (![sig isEqualToString:g_lastAlertSig]) {
                g_lastAlertSig = [sig copy];
                aq_add(@"发现卡密弹窗，自动关闭：标题=%@ 正文=%@",
                       a.title ?: @"(无)", a.message ?: @"(无)");
                NSMutableString *acts = [NSMutableString string];
                for (UIAlertAction *ac in a.actions) {
                    [acts appendFormat:@"%@|", ac.title ?: @"(无标题)"];
                }
                NSString *ph = @"(无)";
                if (a.textFields.count > 0) {
                    ph = a.textFields[0].placeholder ?: @"(无占位文本)";
                }
                aq_add(@"弹窗详情: 按钮=%@ 输入框=%lu 占位=%@",
                       acts, (unsigned long)a.textFields.count, ph);
                aq_copy();
            }
            // 只关第一次出现的弹窗：反复关同一类弹窗容易把界面弄崩。
            if (g_dismissed >= 1) return;
            // 只关闭弹窗，不写任何状态：让原版按「未激活」的正常分支继续。
            [a dismissViewControllerAnimated:NO completion:nil];
            g_dismissed += 1;
            if (g_dismissed <= 5 || (g_dismissed % 20) == 0) {
                aq_add(@"已自动关闭卡密弹窗 %d 次", g_dismissed);
                aq_copy();
            }
            return;
        }
    } @catch (NSException *e) {
    }
}

// 取所有窗口：场景里的窗口 + 应用自己的窗口列表，两路合并去重。
// 有些独立创建的窗口不进场景列表，只看场景会漏掉。
static NSArray<UIWindow *> *aq_all_windows(void) {
    UIApplication *app = [UIApplication sharedApplication];
    if (!app) return @[];
    NSMutableArray<UIWindow *> *wins = [NSMutableArray array];
    for (UIScene *s in app.connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]]) {
            for (UIWindow *w in ((UIWindowScene *)s).windows) {
                if (![wins containsObject:w]) [wins addObject:w];
            }
        }
    }
    @try {
        for (UIWindow *w in [app windows]) {
            if (![wins containsObject:w]) [wins addObject:w];
        }
    } @catch (NSException *e) {
    }
    return wins;
}

// ---- 校验链探测 ----------------------------------------------------------
// 全部只读 + 调用原版自带函数，不改任何代码。
// 依次确认：密钥自检 → 许可证对象是否存在/是否稳定 → 结构是否"已封存"
//           → 面板相关标志当前取值。
// 每一步之后都刷新剪贴板：如果中途闪退，剪贴板里留下最后一步，便于定位。

static uint64_t aq_rd64(void *p, size_t off) {
    uint64_t v = 0;
    memcpy(&v, (const char *)p + off, 8);
    return v;
}

static uint32_t aq_rd32(void *p, size_t off) {
    uint32_t v = 0;
    memcpy(&v, (const char *)p + off, 4);
    return v;
}


// ---- 调度入口观察（不改目标代码，只换两个系统函数指针槽）------------------
// 目标库自己也会把「验卡结果」丢到主线程去处理。这里只把它调用
// dispatch_async / dispatch_after 时用的指针槽换成观察函数，
// 记下它丢出去的每个 block 在库里的位置和捕获的数据——只记录，不改值。
typedef void (*aq_async_fn)(dispatch_queue_t, dispatch_block_t);
typedef void (*aq_after_fn)(dispatch_time_t, dispatch_queue_t, dispatch_block_t);

static aq_async_fn aq_real_async = NULL;
static aq_after_fn aq_real_after = NULL;

// 返回 YES 表示这是目标库里的 block；*invOut / *raOut 给出位置偏移。
// 首次遇到某个(位置,来源)组合时，把块里携带的数据整段打出来。
static BOOL aq_note_block(const char *kind, dispatch_block_t b, uintptr_t ra,
                          long *invOut, long *raOut) {
    if (!b || !g_found) return NO;
    // ARC 下不能把 block 指针直接当 char* 用，先转成整数地址再读。
    uintptr_t bb = (uintptr_t)(__bridge void *)b;
    uintptr_t inv = 0;
    memcpy(&inv, (const void *)(bb + 0x10), 8);
    long off = (long)(inv - (uintptr_t)g_slide);
    long raOff = (long)(ra - (uintptr_t)g_slide);
    if (off <= 0 || off >= 0x1400000) return NO;   // 不是目标库里的 block
    *invOut = off;
    *raOut = raOff;
    BOOL first = NO;
    @synchronized (g_blockSites) {
        if (!g_blockSites) g_blockSites = [NSMutableSet set];
        NSString *key = [NSString stringWithFormat:@"%s:%ld:%ld", kind, off, raOff];
        if (![g_blockSites containsObject:key]) {
            [g_blockSites addObject:key];
            g_blockLogs += 1;
            first = YES;
        }
    }
    if (!first || g_blockLogs > 30) return YES;
    // 按 block 自身登记的大小决定最多读几个字，避免越界。
    uintptr_t desc = 0;
    uint64_t bsize = 0;
    memcpy(&desc, (const void *)(bb + 0x18), sizeof(desc));
    if (desc) memcpy(&bsize, (const void *)(desc + 8), sizeof(bsize));
    int words = 16;
    if (bsize >= 0x20 && bsize < 0x1000) {
        words = (int)((bsize - 0x20) / 4);
        if (words > 16) words = 16;
    }
    uint32_t arr[16] = {0};
    NSMutableString *dump = [NSMutableString string];
    for (int i = 0; i < words; i++) {      // 覆盖 block+0x20 起的捕获数据
        memcpy(&arr[i], (const void *)(bb + 0x20 + i * 4), 4);
        [dump appendFormat:@"%08X ", arr[i]];
    }
    // 把成对的字拼回 64 位，若是本库内地址就标出偏移，便于直接定位。
    NSMutableString *ptrs = [NSMutableString string];
    uintptr_t base = (uintptr_t)g_slide;
    for (int i = 0; i + 1 < words; i += 2) {
        uint64_t q = ((uint64_t)arr[i + 1] << 32) | arr[i];
        if (q > base && q < base + 0x13E0000)
            [ptrs appendFormat:@"[+0x%llX] ", (unsigned long long)(q - base)];
    }
    aq_add(@"调度块 %s 位置 +0x%lX 来自 +0x%lX 大小 0x%llX 内容 %@%@",
           kind, off, raOff, (unsigned long long)bsize, dump, ptrs);
    aq_copy();
    return YES;
}

// 真正执行时也记一笔（每个位置最多记 3 次），确认这个块有没有跑到、什么时候跑。
static void aq_run_block(const char *kind, long invOff, long raOff, dispatch_block_t b) {
    NSString *key = [NSString stringWithFormat:@"%s:%ld", kind, invOff];
    int n = 0;
    @synchronized (g_siteRuns) {
        if (!g_siteRuns) g_siteRuns = [NSMutableDictionary dictionary];
        n = [[g_siteRuns objectForKey:key] intValue];
        if (n < 3) [g_siteRuns setObject:@(n + 1) forKey:key];
        g_dispatchRunLogs += 1;
    }
    if (n < 3 && g_dispatchRunLogs <= 80) {
        aq_add(@"执行处理块 %s 位置 +0x%lX 来自 +0x%lX", kind, invOff, raOff);
        aq_copy();
    }
    if (b) b();
}

static void aq_my_async(dispatch_queue_t q, dispatch_block_t b) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    long io = 0, ro = 0;
    BOOL mine = aq_note_block("async", b, ra, &io, &ro);
    if (!aq_real_async) return;
    if (mine) {
        long si = io, sr = ro;
        aq_real_async(q, ^{ aq_run_block("async", si, sr, b); });
    } else {
        aq_real_async(q, b);
    }
}

static void aq_my_after(dispatch_time_t t, dispatch_queue_t q, dispatch_block_t b) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    long io = 0, ro = 0;
    BOOL mine = aq_note_block("after", b, ra, &io, &ro);
    if (!aq_real_after) return;
    if (mine) {
        long si = io, sr = ro;
        aq_real_after(t, q, ^{ aq_run_block("after", si, sr, b); });
    } else {
        aq_real_after(t, q, b);
    }
}

static BOOL aq_install_hooks(void) {
    if (!g_found) return NO;
    g_hookTries += 1;
    aq_real_async = (aq_async_fn)dlsym(RTLD_DEFAULT, "dispatch_async");
    aq_real_after = (aq_after_fn)dlsym(RTLD_DEFAULT, "dispatch_after");
    if (!aq_real_async || !aq_real_after) {
        aq_add(@"调度观察未安装: 系统函数地址缺失");
        aq_copy();
        return NO;
    }
    struct { uintptr_t slot; void *fn; } hook[2] = {
        { 0x13E0628, (void *)&aq_my_async },
        { 0x13E0620, (void *)&aq_my_after },
    };
    for (int i = 0; i < 2; i++) {
        uintptr_t slot = (uintptr_t)(g_slide + hook[i].slot);
        uintptr_t page = slot & ~(uintptr_t)0x3FFF;
        kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS)
            kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                            VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            aq_add(@"调度观察未安装: 指针槽不可写 (%d)", (int)kr);
            aq_copy();
            return NO;
        }
        memcpy((void *)slot, &hook[i].fn, sizeof(void *));
        vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE);
    }
    g_hookInstalled = YES;
    aq_add(@"调度观察已安装（只记录，不改任何结果）");
    aq_copy();
    return YES;
}

// 只改一个数据字：未激活时原版把它置为 1，并据此跳过面板。
// 这里把它改回 0；若之后又被写回 1，就再改一次（最多记 6 次日志）。
// 同时盯着这一组四个字，凡是它们变化就记一笔，能看出原版什么时候改了状态。
static void aq_clear_panel_flag(void) {
    if (!g_found) return;
    uint32_t a[4] = {0, 0, 0, 0};
    memcpy(a, (const void *)(g_slide + 0x1639298), sizeof(a));
    if (memcmp(a, g_lastFlagArr, sizeof(a)) != 0) {
        uint32_t prevA0 = g_lastFlagArr[0];
        memcpy(g_lastFlagArr, a, sizeof(a));
        if (g_flagChangeLogs < 20) {
            g_flagChangeLogs += 1;
            if (prevA0 == 0xFFFFFFFFu)
                aq_add(@"面板标志组 %08X %08X %08X %08X", a[0], a[1], a[2], a[3]);
            else
                aq_add(@"面板标志组变化 %08X %08X %08X %08X（原首字 %08X）",
                       a[0], a[1], a[2], a[3], prevA0);
            aq_copy();
        }
    }
    if (a[2] == 0) return;
    uint32_t z = 0;
    memcpy((void *)(g_slide + 0x16392A0), &z, 4);
    if (g_flagWrites < 6) {
        aq_add(@"面板状态字 %08X → 00000000（只改数据，第 %d 次）", a[2], g_flagWrites + 1);
        aq_copy();
    }
    g_flagWrites += 1;
    g_lastFlagArr[2] = 0;
}

static void aq_probe_gate(NSString *tag) {
    if (!g_found) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        aq_add(@"%@ 状态检查开始", tag);
        aq_copy();

        // 只观察 App 自己已经创建好的许可证对象；没有就不强行创建，
        // 避免在它初始化之前打乱现场。
        void *o1 = NULL;
        memcpy(&o1, (const void *)(g_slide + 0x1644040), sizeof(o1));
        aq_add(@"%@ 许可证对象=%p", tag, o1);
        aq_copy();
        if (!o1) return;

        int (*f_key)(void) = (int (*)(void))(g_slide + 0xA19EE0);
        int keyRc = -100;
        @try { keyRc = f_key(); } @catch (NSException *e) { }
        aq_add(@"%@ 密钥自检=%d", tag, keyRc);
        aq_copy();

        void *o2 = NULL;
        void *(*f_obj)(void) = (void *(*)(void))(g_slide + 0xA1A064);
        @try { o2 = f_obj(); } @catch (NSException *e) { }
        aq_add(@"%@ 许可证对象复查=%p（%@）", tag, o2,
               (o1 == o2) ? @"同一对象" : @"不同对象");
        aq_copy();

        aq_add(@"%@ 字段 00=%08X 78=%016llX 8E=%08X 92=%08X", tag,
               aq_rd32(o1, 0x00), (unsigned long long)aq_rd64(o1, 0x78),
               aq_rd32(o1, 0x8E), aq_rd32(o1, 0x92));
        aq_copy();
        aq_add(@"%@ 结构 %016llX %016llX %016llX %016llX %08X %08X", tag,
               (unsigned long long)aq_rd64(o1, 0x219A),
               (unsigned long long)aq_rd64(o1, 0x21A2),
               (unsigned long long)aq_rd64(o1, 0x21AA),
               (unsigned long long)aq_rd64(o1, 0x21B2),
               aq_rd32(o1, 0x21BA), aq_rd32(o1, 0x21C2));
        aq_copy();

        int (*f_val)(void *) = (int (*)(void *))(g_slide + 0xA1A2D0);
        int v0 = -100;
        @try { v0 = f_val(o1); } @catch (NSException *e) { }
        aq_add(@"%@ 结构校验=%d（只读，不主动改写）", tag, v0);
        aq_copy();

        // 只读记录与面板出现直接相关的那组标志，方便对照「面板为什么没出来」。
        uint32_t f0 = 0, f4 = 0, f8 = 0, fc = 0;
        memcpy(&f0, (const void *)(g_slide + 0x1639298), 4);
        memcpy(&f4, (const void *)(g_slide + 0x163929C), 4);
        memcpy(&f8, (const void *)(g_slide + 0x16392A0), 4);
        memcpy(&fc, (const void *)(g_slide + 0x16392A4), 4);
        aq_add(@"%@ 面板标志 %08X %08X %08X %08X", tag, f0, f4, f8, fc);
        aq_copy();
    });
}

static int g_viewCount = 0;

// 走一遍视图树：记录每一层（只记前几层，避免内容过长），
// 同时专门找出面板相关组件；找到时把隐藏状态改回显示。
static BOOL aq_walk_view(UIView *v, int depth) {
    if (!v || depth > 8 || g_viewCount >= 40) return NO;
    BOOL hit = NO;
    NSString *cn = NSStringFromClass([v class]);
    BOOL panel = cn && ([cn isEqualToString:@"_0x8C2F4D71"] ||
                        [cn isEqualToString:@"_0x1E6B7A93"] ||
                        [cn isEqualToString:@"_0xD4E9A3C7"]);
    if (panel) {
        hit = YES;
        aq_add(@"发现面板组件 %@ 隐藏=%d 透明度=%.2f 尺寸=%.0fx%.0f 位置=%.0f,%.0f",
               cn, (int)v.hidden, v.alpha, v.frame.size.width, v.frame.size.height,
               v.frame.origin.x, v.frame.origin.y);
        if (v.hidden) {
            v.hidden = NO;
            aq_add(@"已取消隐藏 %@", cn);
        }
    }
    if (depth <= 4) {
        g_viewCount += 1;
        NSMutableString *pad = [NSMutableString string];
        for (int i = 0; i < depth; i++) [pad appendString:@"  "];
        aq_add(@"%@%@ 隐藏=%d 透明=%.2f 尺寸=%.0fx%.0f 子视图=%lu",
               pad, cn, (int)v.hidden, v.alpha,
               v.frame.size.width, v.frame.size.height,
               (unsigned long)v.subviews.count);
    }
    for (UIView *s in v.subviews) {
        if (aq_walk_view(s, depth + 1)) hit = YES;
    }
    return hit;
}

static void aq_dump_ui(void) {
    @try {
        NSArray<UIWindow *> *wins = aq_all_windows();
        aq_add(@"界面快照: 共 %lu 个窗口", (unsigned long)wins.count);
        int panelHits = 0;
        for (UIWindow *w in wins) {
            if (g_win && w == g_win) continue;
            NSString *wcn = NSStringFromClass([w class]);
            aq_add(@"窗口 %@ 隐藏=%d 透明度=%.2f 层级=%.0f 根=%@",
                   wcn, (int)w.hidden, w.alpha, w.windowLevel,
                   NSStringFromClass([w.rootViewController class]));
            if ([wcn isEqualToString:@"_0x8C2F4D71"] && w.hidden) {
                w.hidden = NO;
                aq_add(@"已取消隐藏面板窗口 %@", wcn);
            }
            g_viewCount = 0;
            if (aq_walk_view(w, 0)) panelHits += 1;
        }
        if (panelHits > 0) g_panelFound = YES;
        aq_add(@"面板检测结论: %@",
               panelHits > 0 ? @"面板组件已存在" : @"面板组件完全不存在");
    } @catch (NSException *e) {
        aq_add(@"界面快照失败: %@", e.reason ?: @"未知");
    }
}

// 轻量复查：只数面板组件数量，不打印整棵视图树
static int aq_find_panel(UIView *v, int depth) {
    if (!v || depth > 10) return 0;
    int n = 0;
    NSString *cn = NSStringFromClass([v class]);
    if (cn && ([cn isEqualToString:@"_0x8C2F4D71"] ||
               [cn isEqualToString:@"_0x1E6B7A93"] ||
               [cn isEqualToString:@"_0xD4E9A3C7"])) {
        n += 1;
    }
    for (UIView *s in v.subviews) {
        n += aq_find_panel(s, depth + 1);
    }
    return n;
}

// 收集界面里带混淆前缀的组件类名，看看原版这次到底建了哪些界面。
static void aq_note_classes(UIView *v, int depth, NSMutableSet *found) {
    if (!v || depth > 10) return;
    NSString *cn = NSStringFromClass([v class]);
    if (cn && [cn hasPrefix:@"_0x"] && ![found containsObject:cn]) [found addObject:cn];
    for (UIView *s in v.subviews) aq_note_classes(s, depth + 1, found);
}

// 面板类有没有被注册：类不存在，说明原版根本没执行到「建面板」那一步。
// 顺便列出目标库里所有混淆类名，万一面板类名记错了也能当场看到真名。
static void aq_check_panel_classes(void) {
    const char *names[3] = { "_0x8C2F4D71", "_0x1E6B7A93", "_0xD4E9A3C7" };
    for (int i = 0; i < 3; i++) {
        Class c = objc_getClass(names[i]);
        aq_add(@"面板类 %s %@", names[i], c ? @"已注册" : @"不存在");
    }
    const char *img = NULL;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        if ((intptr_t)_dyld_get_image_header(i) == g_slide) {
            img = _dyld_get_image_name(i);
            break;
        }
    }
    if (img) {
        unsigned int cnt = 0;
        const char **cs = objc_copyClassNamesForImage(img, &cnt);
        NSMutableString *ml = [NSMutableString string];
        int shown = 0;
        for (unsigned int i = 0; cs && i < cnt && shown < 40; i++) {
            if (cs[i] && strncmp(cs[i], "_0x", 3) == 0) {
                [ml appendFormat:@"%s ", cs[i]];
                shown += 1;
            }
        }
        if (cs) free(cs);
        aq_add(@"目标库混淆类共 %u 个，列前 %d: %@", cnt, shown,
               ml.length ? ml : @"(无)");
    }
    aq_copy();
}

static void aq_check_panel(NSString *tag) {
    int n = 0;
    NSMutableSet *found = [NSMutableSet set];
    NSArray<UIWindow *> *wins = aq_all_windows();
    // 窗口构成一旦变化就记一笔：能看出原版什么时候新建/拆掉了窗口。
    NSMutableString *wsig = [NSMutableString string];
    for (UIWindow *w in wins) {
        if (g_win && w == g_win) continue;
        [wsig appendFormat:@"%@/%@,", NSStringFromClass([w class]),
                           NSStringFromClass([w.rootViewController class])];
    }
    if (![wsig isEqualToString:g_lastWinSig]) {
        g_lastWinSig = [wsig copy];
        aq_add(@"%@窗口构成: %@", tag, wsig);
    }
    for (UIWindow *w in wins) {
        if (g_win && w == g_win) continue;
        n += aq_find_panel(w, 0);
        aq_note_classes(w, 0, found);
    }
    @synchronized (g_seenViewClasses) {
        if (!g_seenViewClasses) g_seenViewClasses = [NSMutableSet set];
        for (NSString *cn in found) {
            if ([g_seenViewClasses containsObject:cn]) continue;
            [g_seenViewClasses addObject:cn];
            aq_add(@"%@新出现的界面组件: %@", tag, cn);
        }
    }
    if (n > 0 && !g_panelFound) {
        g_panelFound = YES;
        aq_add(@"%@面板已出现: %d 个组件", tag, n);
        // 面板出现了就把信息窗收起来，别挡住面板
        @try {
            if (g_win && !g_win.hidden) {
                if (g_prevKey) [g_prevKey makeKeyWindow];
                g_win.hidden = YES;
                aq_add(@"信息窗已收起，避免遮挡面板");
            }
        } @catch (NSException *e) {
        }
    } else if (n != g_lastPanelCount) {
        aq_add(@"%@面板复查: %d 个组件", tag, n);
    }
    g_lastPanelCount = n;
    aq_copy();
}

// 展示处理信息（独立置顶窗口）
static void aq_show(void) {
    if (g_shown || g_presenting) return;
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        if (!app) return;
        UIViewController *host = nil;

        UIWindowScene *scene = nil;
        for (UIScene *s in app.connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            if (s.activationState == UISceneActivationStateForegroundActive) {
                scene = (UIWindowScene *)s;
                break;
            }
        }
        if (!scene) {
            for (UIScene *s in app.connectedScenes) {
                if ([s isKindOfClass:[UIWindowScene class]]) {
                    scene = (UIWindowScene *)s;
                    break;
                }
            }
        }

        if (scene) {
            if (!g_win) {
                g_prevKey = app.keyWindow;
                g_win = [[UIWindow alloc] initWithWindowScene:scene];
                g_win.windowLevel = UIWindowLevelAlert + 100;
                UIViewController *root = [[UIViewController alloc] init];
                root.view.backgroundColor = [UIColor clearColor];
                g_win.rootViewController = root;
                [g_win makeKeyAndVisible];
            }
            host = g_win.rootViewController;
            aq_add(@"信息窗承载: 独立置顶窗口");
        } else {
            UIWindow *w = app.keyWindow;
            if (!w || !w.rootViewController) {
                aq_add(@"信息窗展示失败: 没有可用窗口");
                return;
            }
            aq_add(@"信息窗承载: %@", NSStringFromClass([w class]));
            host = w.rootViewController;
            int depth = 0;
            while (host.presentedViewController && depth < 6) {
                host = host.presentedViewController;
                depth += 1;
            }
        }
        if (!host) {
            aq_add(@"信息窗展示失败: 没有承载界面");
            return;
        }

        NSString *msg = aq_snapshot();
        if (msg.length > 1200) {
            // 头和尾都保留：开头是安装/状态，结尾是最后发生的事，中间省略。
            msg = [NSString stringWithFormat:@"%@\n…（中间省略，完整版已复制到剪贴板）…\n%@",
                   [msg substringToIndex:520],
                   [msg substringFromIndex:msg.length - 620]];
        }

        UIAlertController *a =
            [UIAlertController alertControllerWithTitle:@"aqaw 处理信息"
                                                message:msg
                                         preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"复制并关闭"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *act) {
            g_lastClip = nil;
            aq_copy();
            @try {
                if (g_prevKey) [g_prevKey makeKeyWindow];
                g_win.hidden = YES;
            } @catch (NSException *e) {
            }
        }]];
        [a addAction:[UIAlertAction actionWithTitle:@"关闭"
                                              style:UIAlertActionStyleCancel
                                            handler:^(UIAlertAction *act) {
            @try {
                if (g_prevKey) [g_prevKey makeKeyWindow];
                g_win.hidden = YES;
            } @catch (NSException *e) {
            }
        }]];

        g_presenting = YES;
        aq_add(@"信息窗即将弹出（%lu 字）", (unsigned long)msg.length);
        [host presentViewController:a animated:YES completion:^{
            g_presenting = NO;
            g_shown = YES;
            aq_add(@"信息窗已弹出");
            g_lastClip = nil;
            aq_copy();
        }];
    } @catch (NSException *e) {
        g_presenting = NO;
        aq_add(@"信息窗展示失败: %@", e.reason ?: @"未知");
    }
}

static void aq_tick(void) {
    g_tick += 1;
    if (!g_found) aq_locate();
    if (g_found && !g_impsLogged) aq_log_imps();
    // 尽快装上调度观察（只换两个系统函数指针槽，不改目标库一条指令）。
    if (g_found && !g_hookInstalled && g_hookTries < 3 && aq_now() >= 0.5) {
        aq_install_hooks();
    }
    // 1.5 秒起，把未激活时用于跳过面板的那个状态字改回 0（只改数据）。
    if (g_found && aq_now() >= 1.5) {
        aq_clear_panel_flag();
    }
    // 定位成功后先记下基址和版本，方便把记录和具体安装包对上。
    if (g_found && !g_baseLogged) {
        g_baseLogged = YES;
        NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
        aq_add(@"镜像基址 %p 版本 %@ (build %@)", (void *)g_slide,
               info[@"CFBundleShortVersionString"] ?: @"?",
               info[@"CFBundleVersion"] ?: @"?");
        aq_copy();
    }
    // 1.2 秒时确认三个面板类到底有没有被注册（只读）。
    if (g_found && !g_panelClassChecked && aq_now() >= 1.2) {
        g_panelClassChecked = YES;
        aq_check_panel_classes();
    }
    // 许可证对象一旦变化就记一笔（只读）。
    if (g_found) {
        void *lo = NULL;
        memcpy(&lo, (const void *)(g_slide + 0x1644040), sizeof(lo));
        if (lo != g_lastLicenseObj) {
            aq_add(@"许可证对象变化 %p → %p", g_lastLicenseObj, lo);
            g_lastLicenseObj = lo;
            aq_copy();
        }
    }
    // 1 秒时先把面板相关标志记一笔（只读），用来判断面板该不该出现。
    if (g_found && !g_flagLogged && aq_now() >= 1.0) {
        g_flagLogged = YES;
        uint32_t a = 0, b = 0, c = 0, d = 0;
        memcpy(&a, (const void *)(g_slide + 0x1639298), 4);
        memcpy(&b, (const void *)(g_slide + 0x163929C), 4);
        memcpy(&c, (const void *)(g_slide + 0x16392A0), 4);
        memcpy(&d, (const void *)(g_slide + 0x16392A4), 4);
        aq_add(@"面板标志(1秒) %08X %08X %08X %08X", a, b, c, d);
        aq_copy();
    }
    // 校验链探测：2.6 秒一次（卡密流程刚走完），9 秒一次（弹窗关掉之后）。
    if (g_found && !g_gate25 && aq_now() >= 2.6) {
        g_gate25 = YES;
        aq_probe_gate(@"2.6秒");
    }
    if (g_found && !g_gate9 && aq_now() >= 9.0) {
        g_gate9 = YES;
        aq_probe_gate(@"9秒");
    }
    // 面板定时复查：4 秒起每 2 秒一次，直到面板出现或超过 180 秒。
    if (g_found && !g_panelFound && aq_now() >= 4.0 && aq_now() < 180.0) {
        int n = (int)(aq_now() / 2.0);
        if (n != g_panelChecks) {
            g_panelChecks = n;
            dispatch_async(dispatch_get_main_queue(), ^{ aq_check_panel(@"定时"); });
        }
    }

    if (g_found) {
        KeyState cur = aq_read_keys();
        if (!g_haveKeys || !aq_key_equal(cur, g_lastKeys)) {
            g_keyLogCount += 1;
            if (g_keyLogCount <= 15 || (g_keyLogCount % 50) == 0) {
                aq_add(@"解密密钥 %@", aq_key_desc(cur));
                aq_copy();
            }
            g_lastKeys = cur;
            g_haveKeys = YES;
        }
    }

    if ((g_tick % 10) == 0) {
        dispatch_async(dispatch_get_main_queue(), ^{ aq_handle_license_alert(); });
    }
    if ((g_tick % 10) == 0 && !g_shown && !g_presenting && aq_now() >= 6.0) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!g_uiDumped) {
                g_uiDumped = YES;
                aq_dump_ui();
                aq_copy();
            }
            aq_show();
        });
    }
    if ((g_tick % 20) == 0) aq_copy();
}

__attribute__((constructor))
static void aqaw_fix_start(void) {
    g_start = [NSProcessInfo processInfo].systemUptime;
    g_text = [NSMutableString string];
    [g_text appendString:@"===== aqaw 处理记录 =====\n"];
    aq_add(@"处理代码已加载");

    g_q = dispatch_queue_create("aqaw.fix", DISPATCH_QUEUE_SERIAL);
    g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, g_q);
    if (!g_timer) return;
    dispatch_source_set_timer(g_timer,
                              dispatch_time(DISPATCH_TIME_NOW, 100ull * NSEC_PER_MSEC),
                              100ull * NSEC_PER_MSEC,
                              20ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(g_timer, ^{ aq_tick(); });
    dispatch_resume(g_timer);
}
