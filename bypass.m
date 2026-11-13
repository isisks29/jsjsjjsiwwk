// aqaw_probe.m —— aqaw 免改代码处理版（注入用）
//
// 与上一版（纯诊断）的区别：
//   1. 不替换任何方法实现（上一版替换后 App 会闪退，说明这套卡密会检测自己的
//      方法有没有被改过）；
//   2. 改为“界面层自动处理”：发现带输入框的卡密弹窗就自动关闭它；
//   3. 看住解密密钥：等 App 自己把密钥装好后记下来，一旦被卡密失败流程清零/
//      改乱，就按记下的原值写回（只写数据，不改代码、不改方法）。
//
// 仍然不做的事：
//   * 不修改任何代码页；
//   * 不调用原文件里的任何函数；
//   * 不碰卡密以外的界面（只处理带输入框的弹窗）。
//
// 编译（Theos）：
//       TARGET = iphone:clang:latest:14.0
//       ARCHS = arm64 arm64e
//       aqaw_probe_FILES = aqaw_probe.m
//       aqaw_probe_FRAMEWORKS = UIKit Foundation
//
// 使用：保持原版 aqaw.dylib 不动，注入后打开 App。
//   约 6 秒后会弹一次「aqaw 处理信息」窗口，内容同时复制到剪贴板；
//   关掉它以后，后台仍会继续自动关闭卡密弹窗、维护密钥。
//   如果中途闪退，剪贴板里仍然保留闪退前最后的记录。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
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

static KeyState g_good = {0, 0, 0, 0};
static KeyState g_cand = {0, 0, 0, 0};
static int g_candCount = 0;
static BOOL g_armed = NO;
static int g_restores = 0;
static int g_dismissed = 0;
static BOOL g_haveKeys = NO;
static KeyState g_lastKeys = {0, 0, 0, 0};

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
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "aqaw") || strstr(name, "AQaw") ||
            strstr(name, "Aqaw") || strstr(name, "AQAR")) {
            g_slide = _dyld_get_image_vmaddr_slide(i);
            g_found = YES;
            aq_add(@"找到 aqaw 镜像");
            return YES;
        }
    }
    return NO;
}

static KeyState aq_read_keys(void) {
    KeyState s = {0, 0, 0, 0};
    if (!g_found) return s;
    memcpy(&s.k48, (const void *)(g_slide + 0x1644048), 8);
    memcpy(&s.k50, (const void *)(g_slide + 0x1644050), 4);
    memcpy(&s.k54, (const void *)(g_slide + 0x1644054), 4);
    memcpy(&s.k58, (const void *)(g_slide + 0x1644058), 4);
    return s;
}

static void aq_write_keys(KeyState s) {
    if (!g_found) return;
    memcpy((void *)(g_slide + 0x1644048), &s.k48, 8);
    memcpy((void *)(g_slide + 0x1644050), &s.k50, 4);
    memcpy((void *)(g_slide + 0x1644054), &s.k54, 4);
    memcpy((void *)(g_slide + 0x1644058), &s.k58, 4);
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
                g_win.windowLevel = UIWindowLevelAlert + 10;
                UIViewController *root = [[UIViewController alloc] init];
                root.view.backgroundColor = [UIColor clearColor];
                g_win.rootViewController = root;
                [g_win makeKeyAndVisible];
            }
            host = g_win.rootViewController;
        } else {
            UIWindow *w = app.keyWindow;
            if (!w || !w.rootViewController) return;
            host = w.rootViewController;
            int depth = 0;
            while (host.presentedViewController && depth < 6) {
                host = host.presentedViewController;
                depth += 1;
            }
        }
        if (!host) return;

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
        [host presentViewController:a animated:YES completion:^{
            g_presenting = NO;
            g_shown = YES;
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

    if (g_found) {
        KeyState cur = aq_read_keys();
        if (!g_haveKeys || !aq_key_equal(cur, g_lastKeys)) {
            aq_add(@"解密密钥 %@", aq_key_desc(cur));
            g_lastKeys = cur;
            g_haveKeys = YES;
            aq_copy();
        }

        if (!g_armed) {
            if (cur.k50 != 0) {
                // 连续 6 次读到完全相同的一组非零值，才认为安装完成
                if (g_candCount > 0 && aq_key_equal(cur, g_cand)) {
                    g_candCount += 1;
                } else {
                    g_cand = cur;
                    g_candCount = 1;
                }
                if (g_candCount >= 6) {
                    g_good = cur;
                    g_armed = YES;
                    aq_add(@"已锁定正确密钥: %@", aq_key_desc(g_good));
                    aq_copy();
                }
            } else {
                g_candCount = 0;
                if ((g_tick % 50) == 0) {
                    aq_add(@"密钥仍为 0，等待 App 自己安装");
                    aq_copy();
                }
            }
        } else if (!aq_key_equal(cur, g_good)) {
            if (cur.k50 == 0) {
                aq_write_keys(g_good);
                g_restores += 1;
                if (g_restores <= 10 || (g_restores % 20) == 0) {
                    aq_add(@"密钥被清零，已恢复（第 %d 次）", g_restores);
                    aq_copy();
                }
            } else {
                g_good = cur;
                aq_add(@"App 重新安装了密钥，已跟随: %@", aq_key_desc(g_good));
                aq_copy();
            }
        }
    }

    if ((g_tick % 3) == 0) {
        dispatch_async(dispatch_get_main_queue(), ^{ aq_handle_license_alert(); });
    }
    if ((g_tick % 10) == 0 && !g_shown && !g_presenting && aq_now() >= 6.0) {
        dispatch_async(dispatch_get_main_queue(), ^{ aq_show(); });
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
