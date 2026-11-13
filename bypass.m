// aqaw_probe.m —— aqaw 只读诊断弹窗（注入用）
//
// 目标：进 App 后自动弹出一个窗口显示诊断信息，并自动复制到剪贴板，
//       不需要再去 App 的文稿目录里找日志。
//
// 这一版是完全只读的：
//   * 不修改任何代码页；
//   * 不调用原文件里的任何函数；
//   * 不修改解密密钥；
//   * 只读取镜像地址、三个弹窗方法的当前实现、密钥值、以及屏幕上的弹窗文字。
//
// 编译（Theos）：
//       TARGET = iphone:clang:latest:14.0
//       ARCHS = arm64 arm64e
//       aqaw_probe_FILES = aqaw_probe.m
//       aqaw_probe_FRAMEWORKS = UIKit Foundation
//
// 使用：注入后正常打开 App。约 1.5 秒后会弹出一个「aqaw 诊断信息」窗口，
//       内容同时已经复制到剪贴板，直接粘贴到聊天窗口发给我即可。
//       如果 App 中途闪退，剪贴板里仍然是闪退前最后的诊断信息。
//
// 说明：诊断窗口是独立的一个置顶窗口，不会被 App 自己的弹窗盖住。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <stdint.h>
#import <string.h>

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
static NSString *g_lastAlert = nil;
static int g_tick = 0;
static uint64_t g_k48 = 0;
static uint32_t g_k50 = 0, g_k54 = 0, g_k58 = 0;
static BOOL g_haveKeys = NO;

static double aq_now(void) {
    return [NSProcessInfo processInfo].systemUptime - g_start;
}

static void aq_add(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[aqaw-diag] %@", s);
    @synchronized (g_text) {
        if (g_text) [g_text appendFormat:@"[%.2fs] %@\n", aq_now(), s];
    }
}

static NSString *aq_snapshot(void) {
    NSString *s;
    @synchronized (g_text) { s = g_text ? [g_text copy] : @""; }
    return s;
}

// 把完整诊断文本写进剪贴板（主线程操作）
static void aq_copy(void) {
    NSString *s = aq_snapshot();
    if (!s.length) return;
    if ([s isEqualToString:g_lastClip]) return;
    g_lastClip = [s copy];
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            [UIPasteboard generalPasteboard].string = aq_snapshot();
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
            aq_add(@"找到镜像 %s", name);
            aq_add(@"镜像基址偏移 slide=0x%llX", (unsigned long long)g_slide);
            return YES;
        }
    }
    return NO;
}

// 读取三个弹窗方法当前的实现地址（只读）
static void aq_log_imps(void) {
    Class cls = objc_getClass("_0x2F9C7E14");
    if (!cls) {
        aq_add(@"卡密类还没有注册");
        return;
    }
    aq_add(@"卡密类已注册: %s", class_getName(cls));
    const char *sels[3] = {
        "va2429730c25654",
        "v59341b48b7a63c:",
        "v470d683f8c0e8f:endTime:",
    };
    uint64_t exps[3] = { 0x7F6A20, 0x7F4280, 0x7F1804 };
    for (int i = 0; i < 3; i++) {
        SEL sel = sel_registerName(sels[i]);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) {
            aq_add(@"方法 %s 不存在", sels[i]);
            continue;
        }
        uintptr_t imp = (uintptr_t)method_getImplementation(m);
        unsigned long off = (unsigned long)(imp - (uintptr_t)g_slide);
        aq_add(@"方法 %s 当前实现=0x%lX 期望=0x%llX %@",
               sels[i], off, (unsigned long long)exps[i],
               (off == exps[i]) ? @"一致" : @"不一致");
    }
    g_impsLogged = YES;
    aq_copy();
}

static void aq_log_keys(void) {
    if (!g_found) return;
    uint64_t a = 0;
    uint32_t b = 0, c = 0, d = 0;
    memcpy(&a, (const void *)(g_slide + 0x1644048), 8);
    memcpy(&b, (const void *)(g_slide + 0x1644050), 4);
    memcpy(&c, (const void *)(g_slide + 0x1644054), 4);
    memcpy(&d, (const void *)(g_slide + 0x1644058), 4);
    if (g_haveKeys && a == g_k48 && b == g_k50 && c == g_k54 && d == g_k58) return;
    aq_add(@"解密密钥 4048=%016llX 4050=%08X 4054=%08X 4058=%08X",
           (unsigned long long)a, b, c, d);
    g_k48 = a; g_k50 = b; g_k54 = c; g_k58 = d;
    g_haveKeys = YES;
    aq_copy();
}

// 只读看一眼 App 自己弹出来的窗口（跳过我们自己的诊断窗口）
static void aq_check_app_alert(void) {
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        if (!app) return;
        NSArray *wins = [[app windows] copy];
        for (UIWindow *w in wins) {
            if (![w isKindOfClass:[UIWindow class]]) continue;
            if (g_win && w == g_win) continue;
            UIViewController *vc = w.rootViewController;
            int depth = 0;
            while (vc.presentedViewController && depth < 6) {
                vc = vc.presentedViewController;
                depth += 1;
            }
            if (![vc isKindOfClass:[UIAlertController class]]) continue;
            UIAlertController *a = (UIAlertController *)vc;
            NSString *sig = [NSString stringWithFormat:@"%@|%@|%lu",
                             a.title ?: @"", a.message ?: @"",
                             (unsigned long)a.textFields.count];
            if ([sig isEqualToString:g_lastAlert]) return;
            g_lastAlert = [sig copy];
            NSMutableString *fields = [NSMutableString string];
            for (UITextField *tf in a.textFields) {
                [fields appendFormat:@"[%@] ", tf.text ?: @""];
            }
            aq_add(@"App 弹窗 标题=%@ 正文=%@ 输入框数=%lu %@",
                   a.title ?: @"(无)", a.message ?: @"(无)",
                   (unsigned long)a.textFields.count, fields);
            aq_copy();
            return;
        }
    } @catch (NSException *e) {
    }
}

// 创建置顶窗口并展示诊断信息（主线程）
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
            [UIAlertController alertControllerWithTitle:@"aqaw 诊断信息"
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
            aq_copy();   // 自动复制完整内容
        }];
    } @catch (NSException *e) {
        g_presenting = NO;
        aq_add(@"诊断窗展示失败: %@", e.reason ?: @"未知");
    }
}

static void aq_tick(void) {
    g_tick += 1;
    if (!g_found) aq_locate();
    if (g_found && !g_impsLogged) aq_log_imps();
    if (g_found) aq_log_keys();

    if ((g_tick % 5) == 0) {
        dispatch_async(dispatch_get_main_queue(), ^{ aq_check_app_alert(); });
    }
    if ((g_tick % 3) == 0 && !g_shown && !g_presenting && aq_now() >= 0.3) {
        dispatch_async(dispatch_get_main_queue(), ^{ aq_show(); });
    }
    if (g_tick <= 5 || (g_tick % 20) == 0) aq_copy();
}

__attribute__((constructor))
static void aqaw_probe_start(void) {
    g_start = [NSProcessInfo processInfo].systemUptime;
    g_text = [NSMutableString string];
    [g_text appendString:@"===== aqaw 诊断 =====\n"];
    aq_add(@"诊断代码已加载");

    g_q = dispatch_queue_create("aqaw.probe", DISPATCH_QUEUE_SERIAL);
    g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, g_q);
    if (!g_timer) return;
    dispatch_source_set_timer(g_timer,
                              dispatch_time(DISPATCH_TIME_NOW, 100ull * NSEC_PER_MSEC),
                              100ull * NSEC_PER_MSEC,
                              20ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(g_timer, ^{ aq_tick(); });
    dispatch_resume(g_timer);
}
