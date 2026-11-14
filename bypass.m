// aqaw_probe.m —— aqaw 运行时处理版（注入用）
//
// 为什么走运行时：
//   实测原样副本能进、等价改写（行为完全一致，只换一种机器码写法）也闪退，
//   说明这个库会校验自己的机器码，任何静态改字节的版本都不可能跑起来。
//   因此这里一个字节都不改 aqaw，只在运行时替它把「设备密钥」装好。
//
// 这一版做什么：
//   1. 只在内存里改「要不要显示面板」那两个判断点，固定选择「显示」，
//      不修改磁盘文件，也不改任何激活状态；
//   2. 持续观察面板组件（_0x8C2F4D71 / _0x1E6B7A93 / _0xD4E9A3C7），
//      一旦出现就取消隐藏、并把信息窗收起，确保能看见；
//   3. 只读地记录密钥、许可证对象和结构校验结果；
//   4. 卡密弹窗出现时自动关闭，让原版按「未激活」的正常分支继续；
//   5. 约 6 秒弹一次「aqaw 处理信息」窗口，内容同步复制到剪贴板，
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
#import <stdint.h>
#import <string.h>

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
static BOOL g_gatePatched = NO;
static int g_gatePatchTries = 0;
static BOOL g_flagLogged = NO;

static NSString *aq_snapshot(void);
static void aq_copy(void);
static BOOL aq_patch_gate(void);

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
            }
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


// 只改「要不要把面板显示出来」这两个判断点，别的一概不动：
//   点一：选了「显示面板」之后，原版还会再问一次状态，这里固定选「继续构建」；
//   点二：原版会看一个状态字（未激活时是 1）决定跳过面板，这里固定选「构建面板」。
// 改动只发生在内存里的这两条指令，激活状态、许可证数据、密钥全部保持原样。
static BOOL aq_patch_gate(void) {
    if (!g_found) return NO;
    g_gatePatchTries += 1;
    struct { uintptr_t off; uint32_t from; uint32_t to; } fix[2] = {
        { 0xA107D4, 0x1A97014Au, 0xD503201Fu },   // 固定选择「准备显示面板」
        { 0xA10BD8, 0x1A89011Cu, 0x2A0903FCu },   // 固定选择「构建面板」
    };
    uintptr_t page = (uintptr_t)(g_slide + fix[0].off) & ~(uintptr_t)0x3FFF;
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        aq_add(@"面板判定改写失败: 内存不可写 (%d)", (int)kr);
        aq_copy();
        return NO;
    }
    BOOL ok = YES;
    for (int i = 0; i < 2; i++) {
        uintptr_t a = (uintptr_t)(g_slide + fix[i].off);
        uint32_t cur = 0;
        memcpy(&cur, (const void *)a, 4);
        if (cur != fix[i].from) {
            aq_add(@"面板判定改写跳过: 位置%c 原指令不匹配 (%08X)", 'A' + i, cur);
            ok = NO;
            continue;
        }
        memcpy((void *)a, &fix[i].to, 4);
        sys_icache_invalidate((void *)a, 4);
    }
    vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);
    if (ok) {
        g_gatePatched = YES;
        aq_add(@"面板判定已在内存中改为「显示面板」");
    }
    aq_copy();
    return ok;
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

static void aq_check_panel(NSString *tag) {
    int n = 0;
    for (UIWindow *w in aq_all_windows()) {
        if (g_win && w == g_win) continue;
        n += aq_find_panel(w, 0);
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
        if (msg.length > 1100) {
            msg = [[msg substringToIndex:1100] stringByAppendingString:
                   @"\n…（内容太长已截断，完整版已复制到剪贴板）"];
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
    // 在 App 自己做面板判定之前，把「要不要显示面板」的两个判断点固定成「显示」。
    // 激活状态、密钥、许可证数据都不动。
    if (g_found && !g_gatePatched && g_gatePatchTries < 3 && aq_now() >= 0.15) {
        aq_patch_gate();
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
    // 面板定时复查：4 秒起每 2 秒一次，直到面板出现或超过 40 秒。
    if (g_found && !g_panelFound && aq_now() >= 4.0 && aq_now() < 40.0) {
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

    if ((g_tick % 3) == 0) {
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
