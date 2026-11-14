// aqaw_probe.m —— aqaw 运行时处理版（注入用）
//
// 为什么走运行时：
//   实测原样副本能进、等价改写（行为完全一致，只换一种机器码写法）也闪退，
//   说明这个库会校验自己的机器码，任何静态改字节的版本都不可能跑起来。
//   因此这里一个字节都不改 aqaw 的机器码，只在运行时观察它、并替换它
//   调用系统函数时用的指针槽。
//
// 这一版做什么（零 .text 修改，也不替换原版任何方法）：
//   1. 把目标库调用系统函数时用的几个指针槽换成观察函数：dispatch_async /
//      dispatch_after 只记录它的调度块；exit / _exit / kill / pthread_kill /
//      terminate / syscall 则记录并拦下，避免进程被无声结束；
//   2. 只读监视数据段里那组四个字（原版自带的常量表）。实测强行改写会让原版
//      走到不存在的分支、主线程卡死并被系统杀掉，所以这里只看不写；
//   3. 持续观察面板组件（_0x8C2F4D71 / _0x1E6B7A93 / _0xD4E9A3C7）和界面上
//      新出现的混淆类名；面板一旦出现就取消隐藏；
//   4. 只读地记录密钥、许可证状态指针（并打出它前 32 字节的内容）、窗口构成变化；
//   5. 卡密弹窗出现后约 1.5 秒，自动往输入框填一个测试卡密并触发「验证」按钮，
//      让原版走完它自己的流程；本地存储会在开局和 30 秒各看一次，用来判断
//      原版把激活结果存在哪里；
//   6. 记录原版卡密通道的连接地址和收发内容（原版用自带套接字，不走系统网络
//      组件；只记录，不改请求也不改返回），用来判断校验连的是谁、返回的格式；
//   7. 看到校验结果后约 2.5 秒，用原版自己的激活状态写入方法写入一份测试状态，
//      看面板会不会因此放行；结果弹窗 4 秒后自动收起，避免挡住面板；
//   8. 卡密弹窗保留 60 秒供自动验证使用，之后才自动关闭，避免界面卡死；
//   9. 大约 30 秒弹一次「aqaw 处理信息」窗口，内容同步复制到剪贴板；
//  10. 异常现场自救：捕获崩溃信号和未捕获异常，把出错指令、来源地址和访问
//      地址写进沙盒文件；再检测主线程是否被卡死（被系统看门狗杀掉时不会
//      有任何信号，只能靠这条路记下来）。每次启动还会把上一次运行的日志
//      尾巴读回来 —— 万一进程是被原版悄悄结束的，也能看到最后一步。
//
// 为什么不再替换原版方法：
//   上一版替换了原版的卡密处理方法和钥匙串方法，结果弹窗刚出现进程就无声
//   结束、还没留下崩溃信号 —— 原版很可能在校验自己的方法实现。所以这一版
//   只换系统函数的指针槽，原版自己的方法一条都不碰。
//
// 仍然不做的事：
//   * 不修改磁盘上的任何文件；
//   * 不修改目标库的任何机器码；
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
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>
#import <dlfcn.h>
#import <stdint.h>
#import <string.h>
#import <stdlib.h>
#import <stdarg.h>
#import <signal.h>
#import <unistd.h>
#import <fcntl.h>
#import <sys/ucontext.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>

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
static int g_flagChangeLogs = 0;
static uint32_t g_lastFlagArr[4] = {0xFFFFFFFFu, 0, 0, 0};
static void *g_lastLicenseObj = (void *)0x1;
static NSString *g_lastWinSig = nil;
static BOOL g_baseLogged = NO;
static BOOL g_panelClassChecked = NO;
static int g_alertDismissed = 0;
static double g_alertFirstSeen = 0;
static BOOL g_alertSeen = NO;
static BOOL g_autoTried = NO;
static NSMutableSet *g_seenAlertMsgs = nil;
static BOOL g_defsLogged1 = NO;
static BOOL g_defsLogged2 = NO;
static BOOL g_netInstalled = NO;
static int g_netTries = 0;
static UIAlertController *g_resultAlert = nil;
static double g_resultFirstSeen = 0;
static BOOL g_resultClosed = NO;
static BOOL g_fakeTried = NO;
static BOOL g_fakeScheduled = NO;
static int g_sockSendLogs = 0;
static int g_sockRecvLogs = 0;
static int g_mainBeats = 0;
static int g_mainSeen = 0;
static double g_lastMainMove = 0;
static BOOL g_hangLogged = NO;

static NSString *aq_snapshot(void);
static void aq_copy(void);
static BOOL aq_install_hooks(void);
static void aq_watch_flag(void);
static void aq_add(NSString *fmt, ...);

// ---- 闪退现场记录 --------------------------------------------------------
// 闪退时系统不给报告，那就自己记：把信号、出错指令地址和出错时访问的地址
// 直接写进 App 沙盒里的一个文件。下次启动时把它读出来放进记录，随剪贴板一起给你。
static char g_crash_path[512] = {0};

// 不依赖任何运行库的十六进制输出，信号处理函数里只能用这种最朴素的写法。
static int aq_hex_into(char *p, unsigned long long v) {
    char tmp[16];
    int n = 0, i;
    if (v == 0) { p[0] = '0'; return 1; }
    while (v && n < 16) { tmp[n++] = "0123456789ABCDEF"[v & 0xF]; v >>= 4; }
    for (i = 0; i < n; i++) p[i] = tmp[n - 1 - i];
    return n;
}

static char *aq_put(char *p, const char *s) {
    size_t n = strlen(s);
    memcpy(p, s, n);
    return p + n;
}

static void aq_crash_handler(int sig, siginfo_t *info, void *uctx) {
    char buf[384];
    char *p = buf;
    unsigned long long pc = 0, lr = 0, fault = (unsigned long long)(uintptr_t)info->si_addr;
#if defined(__arm64__)
    if (uctx) {
        ucontext_t *u = (ucontext_t *)uctx;
        pc = (unsigned long long)u->uc_mcontext->__ss.__pc;
        lr = (unsigned long long)u->uc_mcontext->__ss.__lr;
    }
#endif
    p = aq_put(p, "\n=== 上次闪退 ===\nsignal=");
    p += aq_hex_into(p, (unsigned long long)sig);
    p = aq_put(p, " pc=0x");
    p += aq_hex_into(p, pc);
    p = aq_put(p, " lr=0x");
    p += aq_hex_into(p, lr);
    p = aq_put(p, " fault=0x");
    p += aq_hex_into(p, fault);
    if (g_slide && pc >= (unsigned long long)g_slide &&
        pc < (unsigned long long)g_slide + 0x13E0000ULL) {
        p = aq_put(p, " 目标库内偏移=0x");
        p += aq_hex_into(p, pc - (unsigned long long)g_slide);
    } else {
        p = aq_put(p, " 不在目标库内");
    }
    *p++ = '\n';
    if (g_crash_path[0]) {
        int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            ssize_t ignored = write(fd, buf, (size_t)(p - buf));
            (void)ignored;
            close(fd);
        }
    }
    // 记完恢复系统默认处理，再把这个信号重新抛出去，保持原有崩溃行为。
    signal(sig, SIG_DFL);
    kill(getpid(), sig);
    _exit(1);
}

static void aq_uncaught(NSException *e) {
    NSString *s = [NSString stringWithFormat:
                   @"\n=== 上次未捕获异常 ===\n%@: %@\n%@\n",
                   e.name ?: @"?", e.reason ?: @"?",
                   e.callStackSymbols ?: @[]];
    @try {
        if (!g_crash_path[0]) return;
        NSString *path = [NSString stringWithUTF8String:g_crash_path];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) {
            [[NSData data] writeToFile:path atomically:NO];
            fh = [NSFileHandle fileHandleForWritingAtPath:path];
        }
        [fh seekToEndOfFile];
        [fh writeData:[s dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } @catch (NSException *x) {
    }
}

// 启动时调用一次：算出记录文件位置、读上次的闪退记录、挂上信号与异常捕获。
static void aq_install_crash_capture(void) {
    @try {
        NSString *dir = [NSSearchPathForDirectoriesInDomains(
                             NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        if (dir.length) {
            NSString *p = [dir stringByAppendingPathComponent:@"aqaw_crash.txt"];
            if ([p lengthOfBytesUsingEncoding:NSUTF8StringEncoding] < sizeof(g_crash_path)) {
                strncpy(g_crash_path, [p UTF8String], sizeof(g_crash_path) - 1);
            }
            NSString *prev = [NSString stringWithContentsOfFile:p
                                                       encoding:NSUTF8StringEncoding
                                                          error:nil];
            if (prev.length) {
                aq_add(@"上次运行留下的异常记录:%@", prev);
                [[NSFileManager defaultManager] removeItemAtPath:p error:nil];
            }
        }
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = aq_crash_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        int sigs[5] = { SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGABRT };
        for (int i = 0; i < 5; i++) sigaction(sigs[i], &sa, NULL);
        NSSetUncaughtExceptionHandler(&aq_uncaught);
        aq_add(@"异常捕获已开启（闪退后重新打开会显示上次现场）");
    } @catch (NSException *e) {
    }
}

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
            if (a.textFields.count == 0) {
                // 没有输入框的弹窗通常是验证结果提示，只记录，不动它。
                if (!g_seenAlertMsgs) g_seenAlertMsgs = [NSMutableSet set];
                NSString *msig = [NSString stringWithFormat:@"%@|%@",
                                  a.title ?: @"", a.message ?: @""];
                if (![g_seenAlertMsgs containsObject:msig]) {
                    [g_seenAlertMsgs addObject:msig];
                    NSMutableString *acts2 = [NSMutableString string];
                    for (UIAlertAction *ac in a.actions) {
                        [acts2 appendFormat:@"%@|", ac.title ?: @"(无标题)"];
                    }
                    aq_add(@"结果弹窗: 标题=%@ 正文=%@ 按钮=%@",
                           a.title ?: @"(无)", a.message ?: @"(无)", acts2);
                    aq_copy();
                }
                // 新的结果弹窗：记下出现时间，稍后自动收起，免得挡住面板。
                if (a != g_resultAlert) {
                    g_resultAlert = a;
                    g_resultFirstSeen = aq_now();
                    g_resultClosed = NO;
                }
                if (!g_resultClosed && aq_now() - g_resultFirstSeen >= 4.0) {
                    g_resultClosed = YES;
                    [a dismissViewControllerAnimated:NO completion:nil];
                    aq_add(@"结果弹窗已自动收起，继续观察面板");
                    aq_copy();
                }
                continue;
            }

            NSString *sig = [NSString stringWithFormat:@"%@|%@|%lu",
                             a.title ?: @"", a.message ?: @"",
                             (unsigned long)a.textFields.count];
            if (![sig isEqualToString:g_lastAlertSig]) {
                g_lastAlertSig = [sig copy];
                g_alertFirstSeen = aq_now();
                g_alertSeen = YES;
                aq_add(@"发现卡密弹窗：标题=%@ 正文=%@",
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

            // 弹窗出现约 1.5 秒后，自动填入一个测试卡密并触发「验证」按钮。
            // 目的只是让原版自己发出网络请求，好把请求和返回格式记下来。
            if (!g_autoTried && g_alertSeen && aq_now() - g_alertFirstSeen >= 1.5) {
                g_autoTried = YES;
                UITextField *tf = a.textFields.count ? a.textFields[0] : nil;
                if (tf) {
                    tf.text = @"AQ88888888";
                    aq_add(@"已自动填入测试卡密（仅用于观察）");
                }
                UIAlertAction *target = nil;
                for (UIAlertAction *ac in a.actions) {
                    NSString *t = ac.title ?: @"";
                    if ([t containsString:@"取消"] || [t containsString:@"关闭"]) continue;
                    target = ac;
                    break;
                }
                if (target) {
                    id handler = nil;
                    @try { handler = [target valueForKey:@"handler"]; } @catch (NSException *e) {}
                    if (handler) {
                        aq_add(@"已自动触发按钮「%@」", target.title ?: @"?");
                        ((void (^)(UIAlertAction *))handler)(target);
                    } else {
                        aq_add(@"按钮「%@」没有可触发的处理块", target.title ?: @"?");
                    }
                } else {
                    aq_add(@"没有找到验证按钮");
                }
                aq_copy();
            }

            // 停留超过 60 秒仍没人处理才关闭，避免界面卡死。
            if (g_alertDismissed < 1 && g_alertSeen && aq_now() - g_alertFirstSeen >= 60.0) {
                [a dismissViewControllerAnimated:NO completion:nil];
                g_alertDismissed += 1;
                aq_add(@"卡密弹窗停留超过 60 秒，已自动关闭");
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

// 只观察，不包裹、不改写原 block：原样交给系统调度。
static void aq_my_async(dispatch_queue_t q, dispatch_block_t b) {
    long io = 0, ro = 0;
    aq_note_block("async", b, (uintptr_t)__builtin_return_address(0), &io, &ro);
    if (aq_real_async) aq_real_async(q, b);
}

static void aq_my_after(dispatch_time_t t, dispatch_queue_t q, dispatch_block_t b) {
    long io = 0, ro = 0;
    aq_note_block("after", b, (uintptr_t)__builtin_return_address(0), &io, &ro);
    if (aq_real_after) aq_real_after(t, q, b);
}

// 原版若自己调用退出 / 终止函数，这里先记一笔再拦下，避免进程无声消失。
typedef int (*aq_kill_fn)(int, int);
typedef int (*aq_pthread_kill_fn)(void *, int);
static aq_kill_fn aq_real_kill = NULL;
static aq_pthread_kill_fn aq_real_pthread_kill = NULL;

static BOOL aq_fatal_sig(int sig) {
    return sig == SIGKILL || sig == SIGABRT || sig == SIGSEGV ||
           sig == SIGBUS || sig == SIGILL || sig == SIGTRAP;
}

static void aq_my__exit(int code) {
    aq_add(@"原版调用了退出函数(%d)，已拦下", code);
}
static void aq_my_terminate(void) {
    aq_add(@"原版调用了终止函数，已拦下");
}
static int aq_my_kill(int pid, int sig) {
    if (pid == getpid() || pid == 0 || pid == -1) {
        aq_add(@"原版向自己发送信号 sig=%d，已拦下", sig);
        return 0;
    }
    return aq_real_kill ? aq_real_kill(pid, sig) : 0;
}
static int aq_my_pthread_kill(void *th, int sig) {
    if (aq_fatal_sig(sig)) {
        aq_add(@"原版向线程发送致命信号 sig=%d，已拦下", sig);
        return 0;
    }
    return aq_real_pthread_kill ? aq_real_pthread_kill(th, sig) : 0;
}

// 有些保护会绕过 exit/_exit，直接用 syscall(1, ...) 结束进程，这里一并拦。
typedef long (*aq_syscall_fn)(long, long, long, long, long, long, long);
static aq_syscall_fn aq_real_syscall = NULL;
static long aq_my_syscall(long n, ...) {
    va_list ap;
    va_start(ap, n);
    long a = va_arg(ap, long), b = va_arg(ap, long), c = va_arg(ap, long);
    long d = va_arg(ap, long), e = va_arg(ap, long), f = va_arg(ap, long);
    va_end(ap);
    if (n == 1) {   // 1 = exit
        aq_add(@"原版调用了间接退出调用(exit, 参数=%ld)，已拦下", a);
        return -1;
    }
    if (n == 37 && (a == getpid() || a == 0 || a == -1)) {   // 37 = kill
        aq_add(@"原版通过间接调用向自己发信号 sig=%ld，已拦下", b);
        return -1;
    }
    return aq_real_syscall ? aq_real_syscall(n, a, b, c, d, e, f) : -1;
}

// ---- 卡密通道观察：目标库自带的网络部分用原始套接字，直接看收发内容 ----------
// 这些函数只在目标库自己的调用入口上生效，游戏本体的网络不会经过这里。
static NSString *aq_bytes_desc(const void *buf, size_t n) {
    if (!buf || n == 0) return @"(空)";
    size_t cap = n > 700 ? 700 : n;
    NSString *s = [[NSString alloc] initWithBytes:buf length:cap encoding:NSUTF8StringEncoding];
    if (s) {
        s = [s stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
        s = [s stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
        return aq_trunc(s, 700);
    }
    NSMutableString *h = [NSMutableString string];
    const unsigned char *p = (const unsigned char *)buf;
    for (size_t i = 0; i < cap && i < 160; i++) [h appendFormat:@"%02X", p[i]];
    return [NSString stringWithFormat:@"(二进制 %lu 字节) %@", (unsigned long)n, h];
}

typedef ssize_t (*aq_send_fn)(int, const void *, size_t, int);
typedef ssize_t (*aq_sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*aq_recv_fn)(int, void *, size_t, int);
typedef ssize_t (*aq_recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef int (*aq_connect_fn)(int, const struct sockaddr *, socklen_t);
static aq_send_fn aq_real_send = NULL;
static aq_sendto_fn aq_real_sendto = NULL;
static aq_recv_fn aq_real_recv = NULL;
static aq_recvfrom_fn aq_real_recvfrom = NULL;
static aq_connect_fn aq_real_connect = NULL;

static NSString *aq_sock_addr(const struct sockaddr *addr) {
    if (!addr) return @"(无地址)";
    char ip[64] = {0};
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        return [NSString stringWithFormat:@"%s:%d", ip, (int)ntohs(in->sin_port)];
    }
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
        return [NSString stringWithFormat:@"[%s]:%d", ip, (int)ntohs(in6->sin6_port)];
    }
    return [NSString stringWithFormat:@"(类型%d)", (int)addr->sa_family];
}

static ssize_t aq_my_send(int fd, const void *buf, size_t n, int flags) {
    if (buf && n > 0 && g_sockSendLogs < 30) {
        g_sockSendLogs += 1;
        aq_add(@"卡密通道发出 %lu 字节: %@", (unsigned long)n, aq_bytes_desc(buf, n));
        aq_copy();
    }
    return aq_real_send ? aq_real_send(fd, buf, n, flags) : -1;
}

static ssize_t aq_my_sendto(int fd, const void *buf, size_t n, int flags,
                            const struct sockaddr *addr, socklen_t len) {
    if (buf && n > 0 && g_sockSendLogs < 30) {
        g_sockSendLogs += 1;
        aq_add(@"卡密通道发出 %lu 字节 → %@: %@", (unsigned long)n,
               aq_sock_addr(addr), aq_bytes_desc(buf, n));
        aq_copy();
    }
    return aq_real_sendto ? aq_real_sendto(fd, buf, n, flags, addr, len) : -1;
}

static ssize_t aq_my_recv(int fd, void *buf, size_t n, int flags) {
    ssize_t r = aq_real_recv ? aq_real_recv(fd, buf, n, flags) : -1;
    if (r > 0 && g_sockRecvLogs < 30) {
        g_sockRecvLogs += 1;
        aq_add(@"卡密通道收到 %ld 字节: %@", (long)r, aq_bytes_desc(buf, (size_t)r));
        aq_copy();
    }
    return r;
}

static ssize_t aq_my_recvfrom(int fd, void *buf, size_t n, int flags,
                              struct sockaddr *addr, socklen_t *len) {
    ssize_t r = aq_real_recvfrom ? aq_real_recvfrom(fd, buf, n, flags, addr, len) : -1;
    if (r > 0 && g_sockRecvLogs < 30) {
        g_sockRecvLogs += 1;
        aq_add(@"卡密通道收到 %ld 字节: %@", (long)r, aq_bytes_desc(buf, (size_t)r));
        aq_copy();
    }
    return r;
}

static int aq_my_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (g_sockSendLogs < 30) {
        aq_add(@"卡密通道连接 %@", aq_sock_addr(addr));
    }
    return aq_real_connect ? aq_real_connect(fd, addr, len) : -1;
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
    aq_real_syscall = (aq_syscall_fn)dlsym(RTLD_DEFAULT, "syscall");
    aq_real_kill = (aq_kill_fn)dlsym(RTLD_DEFAULT, "kill");
    aq_real_pthread_kill = (aq_pthread_kill_fn)dlsym(RTLD_DEFAULT, "pthread_kill");
    aq_real_send = (aq_send_fn)dlsym(RTLD_DEFAULT, "send");
    aq_real_sendto = (aq_sendto_fn)dlsym(RTLD_DEFAULT, "sendto");
    aq_real_recv = (aq_recv_fn)dlsym(RTLD_DEFAULT, "recv");
    aq_real_recvfrom = (aq_recvfrom_fn)dlsym(RTLD_DEFAULT, "recvfrom");
    aq_real_connect = (aq_connect_fn)dlsym(RTLD_DEFAULT, "connect");
    struct { uintptr_t slot; void *fn; } hook[12] = {
        { 0x13E0628, (void *)&aq_my_async },
        { 0x13E0620, (void *)&aq_my_after },
        { 0x13E0570, (void *)&aq_my__exit },
        { 0x13E07C0, (void *)&aq_my_kill },
        { 0x13E09C0, (void *)&aq_my_pthread_kill },
        { 0x13E04C8, (void *)&aq_my_terminate },
        { 0x13E0B00, (void *)&aq_my_syscall },
        { 0x13E0A48, (void *)&aq_my_send },
        { 0x13E0A50, (void *)&aq_my_sendto },
        { 0x13E0A10, (void *)&aq_my_recv },
        { 0x13E0A18, (void *)&aq_my_recvfrom },
        { 0x13E05F0, (void *)&aq_my_connect },
    };
    for (int i = 0; i < 12; i++) {
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
    aq_add(@"调度、退出与卡密通道观察已安装（只记录，退出类调用会被拦下）");
    aq_copy();
    return YES;
}

// ---- 只读观察：网络请求 / 钥匙串 / 卡密处理 -------------------------------
// 全部用运行时替换方法实现，只记录参数和结果，绝不改文件的任何字节。
static NSString *aq_trunc(NSString *s, NSUInteger cap) {
    if (!s) return @"(空)";
    if (s.length <= cap) return s;
    return [[s substringToIndex:cap] stringByAppendingString:@"…"];
}

// ---- 网络观察（只记录请求与返回，不改动请求内容和返回内容） -----------------
// 卡密校验要联网，这里把 App 发出的每个请求和收到的每个返回都记下来，
// 用来判断校验走的是哪个地址、服务器返回的格式是什么。
static void aq_log_request(NSURLRequest *req, NSString *tag) {
    @try {
        if (!req) {
            aq_add(@"%@ 请求: (无内容)", tag);
            return;
        }
        NSString *u = req.URL.absoluteString ?: @"(无地址)";
        NSString *m = req.HTTPMethod ?: @"GET";
        NSData *b = req.HTTPBody;
        NSString *bs = @"无";
        if (b.length) {
            NSString *s = [[NSString alloc] initWithData:b encoding:NSUTF8StringEncoding];
            bs = s ? aq_trunc(s, 400)
                   : [NSString stringWithFormat:@"%lu 字节二进制", (unsigned long)b.length];
        }
        NSDictionary *h = req.allHTTPHeaderFields;
        aq_add(@"%@ 请求: %@ %@ 头=%lu项 体=%@",
               tag, m, aq_trunc(u, 300), (unsigned long)h.count, bs);
    } @catch (NSException *e) {
    }
}

typedef NSURLSessionDataTask *(*aq_task_fn)(id, SEL, NSURLRequest *);
static aq_task_fn aq_orig_dataTask = NULL;
typedef NSURLSessionDataTask *(*aq_task_cb_fn)(id, SEL, NSURLRequest *,
                                               void (^)(NSData *, NSURLResponse *, NSError *));
static aq_task_cb_fn aq_orig_dataTaskCB = NULL;

static NSURLSessionDataTask *aq_my_dataTask(id self, SEL _cmd, NSURLRequest *req) {
    aq_log_request(req, @"发出");
    return aq_orig_dataTask ? aq_orig_dataTask(self, _cmd, req) : nil;
}

static NSURLSessionDataTask *aq_my_dataTaskCB(id self, SEL _cmd, NSURLRequest *req,
                                              void (^cb)(NSData *, NSURLResponse *, NSError *)) {
    aq_log_request(req, @"发出");
    if (!cb || !aq_orig_dataTaskCB) {
        return aq_orig_dataTaskCB ? aq_orig_dataTaskCB(self, _cmd, req, cb) : nil;
    }
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
        ^(NSData *data, NSURLResponse *resp, NSError *err) {
            @try {
                NSString *u = resp.URL.absoluteString ?: req.URL.absoluteString ?: @"(未知)";
                long code = -1;
                NSString *hs = @"";
                if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                    NSHTTPURLResponse *hr = (NSHTTPURLResponse *)resp;
                    code = (long)hr.statusCode;
                    hs = [NSString stringWithFormat:@" 头=%lu项", (unsigned long)hr.allHeaderFields.count];
                }
                NSString *body = @"(空)";
                if (data.length) {
                    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                    body = s ? aq_trunc(s, 800)
                             : [NSString stringWithFormat:@"%lu 字节二进制", (unsigned long)data.length];
                }
                aq_add(@"网络返回: 状态=%ld%@ 地址=%@ 出错=%@ 体=%@",
                       code, hs, aq_trunc(u, 240),
                       err ? (err.localizedDescription ?: @"未知") : @"无", body);
                aq_copy();
            } @catch (NSException *e) {
            }
            cb(data, resp, err);
        };
    return aq_orig_dataTaskCB(self, _cmd, req, wrapped);
}

static BOOL aq_install_net(void) {
    g_netTries += 1;
    Class s = NSClassFromString(@"NSURLSession");
    if (!s) {
        aq_add(@"网络观察未安装: 系统类缺失");
        return NO;
    }
    int n = 0;
    Method m1 = class_getInstanceMethod(s, @selector(dataTaskWithRequest:));
    if (m1) {
        aq_orig_dataTask = (aq_task_fn)method_getImplementation(m1);
        method_setImplementation(m1, (IMP)&aq_my_dataTask);
        n += 1;
    }
    Method m2 = class_getInstanceMethod(s, @selector(dataTaskWithRequest:completionHandler:));
    if (m2) {
        aq_orig_dataTaskCB = (aq_task_cb_fn)method_getImplementation(m2);
        method_setImplementation(m2, (IMP)&aq_my_dataTaskCB);
        n += 1;
    }
    if (n == 0) {
        aq_add(@"网络观察未安装: 找不到请求方法");
        return NO;
    }
    g_netInstalled = YES;
    aq_add(@"网络观察已安装（%d 个入口，只记录不修改）", n);
    aq_copy();
    return YES;
}

// 只读检查：卡密类有没有现成的单例入口（方便后面复用原版对象）。
static void aq_probe_license_class(void) {
    Class cls = NSClassFromString(@"_0x2F9C7E14");
    if (!cls) {
        aq_add(@"伪造激活: 卡密类不存在");
        return;
    }
    const char *names[6] = { "sharedInstance", "shared", "defaultManager",
                             "manager", "instance", "defaultInstance" };
    NSMutableString *hit = [NSMutableString string];
    for (int i = 0; i < 6; i++) {
        SEL sel = NSSelectorFromString([NSString stringWithUTF8String:names[i]]);
        if ([cls respondsToSelector:sel]) [hit appendFormat:@"%s ", names[i]];
    }
    aq_add(@"伪造激活: 卡密类的现成入口=%@", hit.length ? hit : @"没有");
}

// 尝试写入一份「已激活」状态（只在本地内存里调用原版写入方法，不改任何文件）。
// 目的：让原版以为自己已经被激活，从而放行面板。失败会被捕获并记录。
static void aq_try_fake_activation(NSString *reason) {
    if (g_fakeTried) return;
    g_fakeTried = YES;
    Class cls = NSClassFromString(@"_0x2F9C7E14");
    if (!cls) {
        aq_add(@"伪造激活: 卡密类不存在");
        aq_copy();
        return;
    }
    @try {
        id inst = [[cls alloc] init];
        SEL sel = NSSelectorFromString(@"v470d683f8c0e8f:endTime:");
        if (!inst || ![inst respondsToSelector:sel]) {
            aq_add(@"伪造激活: 写入方法不存在");
            aq_copy();
            return;
        }
        // 上一轮发现这个方法的第二个参数会被取 length，说明它要的是数据而不是日期；
        // 这一轮改传一段空数据，先看它下一步做什么。
        id end = [NSData data];
        // ARC 下不能直接调 objc_msgSend，先落到同类型函数指针再调用。
        void (*fn)(id, SEL, id, id) = (void (*)(id, SEL, id, id))objc_msgSend;
        fn(inst, sel, @"AQ88888888", end);
        aq_add(@"伪造激活: 已尝试写入测试状态（%@）", reason ?: @"阶段");
        aq_copy();
    } @catch (NSException *e) {
        aq_add(@"伪造激活失败: %@", e.reason ?: @"未知异常");
        aq_copy();
    }
}

static void aq_dump_defaults(NSString *tag) {
    @try {
        NSDictionary *d = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        NSMutableString *s = [NSMutableString string];
        int n = 0;
        for (NSString *k in d) {
            if (n++ >= 40) break;
            id v = d[k];
            NSString *vs = [v isKindOfClass:[NSString class]] ? (NSString *)v
                          : [NSString stringWithFormat:@"(%@)%@", NSStringFromClass([v class]), v];
            [s appendFormat:@"%@=%@; ", k, aq_trunc(vs, 60)];
        }
        if (s.length == 0) s = [NSMutableString stringWithString:@"(空)"];
        aq_add(@"%@ 本地存储: %@", tag, aq_trunc(s, 700));
        aq_copy();
    } @catch (NSException *e) {
    }
}

// 只读观察这一组四个字：它们位于数据段，实测是原版自带的常量表，
// 强行改写会让原版走到不存在的分支、主线程卡死。这里只记录变化，绝不写。
static void aq_watch_flag(void) {
    if (!g_found) return;
    uint32_t a[4] = {0, 0, 0, 0};
    memcpy(a, (const void *)(g_slide + 0x1639298), sizeof(a));
    if (memcmp(a, g_lastFlagArr, sizeof(a)) != 0) {
        uint32_t prevA0 = g_lastFlagArr[0];
        memcpy(g_lastFlagArr, a, sizeof(a));
        if (g_flagChangeLogs < 20) {
            g_flagChangeLogs += 1;
            if (prevA0 == 0xFFFFFFFFu)
                aq_add(@"数据段常量组 %08X %08X %08X %08X", a[0], a[1], a[2], a[3]);
            else
                aq_add(@"数据段常量组变化 %08X %08X %08X %08X（原首字 %08X）",
                       a[0], a[1], a[2], a[3], prevA0);
            aq_copy();
        }
    }
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

// 每秒一行心跳：闪退时能据此判断最后停在什么状态。
static void aq_heartbeat(void) {
    @try {
        int wins = 0, panel = 0;
        BOOL alert = NO;
        for (UIWindow *w in aq_all_windows()) {
            if (g_win && w == g_win) continue;
            wins += 1;
            panel += aq_find_panel(w, 0);
            UIViewController *vc = w.rootViewController;
            int d = 0;
            while (vc.presentedViewController && d < 6) {
                vc = vc.presentedViewController;
                d += 1;
            }
            if ([vc isKindOfClass:[UIAlertController class]]) alert = YES;
        }
        uint32_t f = 0;
        memcpy(&f, (const void *)(g_slide + 0x16392A0), 4);
        aq_add(@"心跳: 状态字=%08X 窗口=%d 面板组件=%d 卡密弹窗=%@",
               f, wins, panel, alert ? @"在" : @"无");
        aq_copy();
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
    // 0.6 秒起装上网络观察：校验请求一发出就能把地址和返回内容记下来。
    if (!g_netInstalled && g_netTries < 2 && aq_now() >= 0.6) {
        aq_install_net();
    }
    // 这一版不替换原版任何方法（上一版替换后弹窗刚出现就无声退出）。
    // 只读盯着数据段那组常量：原版若自己改了它，这里会留痕。
    if (g_found && aq_now() >= 1.5) {
        aq_watch_flag();
    }
    // 主线程心跳：给主队列派一个小任务，看它多久没被处理。
    // 主线程被卡死时，剪贴板也刷不进去，只能把现场写进沙盒文件等下次启动读出来。
    if (g_found) {
        dispatch_async(dispatch_get_main_queue(), ^{ g_mainBeats += 1; });
        if (g_mainBeats != g_mainSeen) {
            g_mainSeen = g_mainBeats;
            g_lastMainMove = aq_now();
        } else if (!g_hangLogged && aq_now() > 6.0 && aq_now() - g_lastMainMove > 3.0) {
            g_hangLogged = YES;
            @try {
                NSString *path = g_crash_path[0] ? [NSString stringWithUTF8String:g_crash_path] : nil;
                if (path) {
                    NSString *s = [NSString stringWithFormat:
                                   @"\n=== 上次运行主线程卡死 ===\n最后一步时间 %.1fs，卡住超过 3 秒\n",
                                   g_lastMainMove];
                    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
                    if (!fh) {
                        [[NSData data] writeToFile:path atomically:NO];
                        fh = [NSFileHandle fileHandleForWritingAtPath:path];
                    }
                    if (fh) {
                        [fh seekToEndOfFile];
                        [fh writeData:[s dataUsingEncoding:NSUTF8StringEncoding]];
                        [fh closeFile];
                    }
                }
            } @catch (NSException *e) {
            }
        }
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
            aq_add(@"许可证状态指针变化 %p → %p", g_lastLicenseObj, lo);
            if (lo) {
                uint32_t w[8] = {0};
                memcpy(w, lo, sizeof(w));
                aq_add(@"许可证状态前 32 字节: %08X %08X %08X %08X %08X %08X %08X %08X",
                       w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
            }
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
        aq_add(@"数据段常量组(1秒) %08X %08X %08X %08X", a, b, c, d);
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
    // 面板定时复查：2 秒起每 0.5 秒一次，直到面板出现或超过 180 秒。
    if (g_found && !g_panelFound && aq_now() >= 2.0 && aq_now() < 180.0) {
        int n = (int)(aq_now() * 2.0);
        if (n != g_panelChecks) {
            g_panelChecks = n;
            dispatch_async(dispatch_get_main_queue(), ^{ aq_check_panel(@"定时"); });
        }
    }
    // 2.5~25 秒每秒一行心跳，记录状态字、窗口数、面板组件数和弹窗是否还在。
    if (g_found && aq_now() >= 2.5 && aq_now() <= 25.0 && (g_tick % 10) == 0) {
        dispatch_async(dispatch_get_main_queue(), ^{ aq_heartbeat(); });
    }
    // 本地存储只在开头和验证之后各看一次，用来判断原版把激活状态存在哪里。
    if (g_found && !g_defsLogged1 && aq_now() >= 2.0) {
        g_defsLogged1 = YES;
        aq_dump_defaults(@"开局");
    }
    if (g_found && !g_defsLogged2 && aq_now() >= 30.0) {
        g_defsLogged2 = YES;
        aq_dump_defaults(@"30秒");
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
    if ((g_tick % 10) == 0 && !g_shown && !g_presenting && aq_now() >= 30.0) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!g_uiDumped) {
                g_uiDumped = YES;
                aq_dump_ui();
                aq_copy();
            }
            aq_show();
        });
    }
    // 校验结果出现 2.5 秒后，尝试写一份「已激活」状态，看原版会不会因此放行面板。
    // 放到主线程执行；即使这一下出错，前面看到的记录也已经落盘。
    BOOL fakeDue = (g_resultAlert && aq_now() - g_resultFirstSeen >= 2.5);
    if (!fakeDue && !g_resultAlert && aq_now() >= 18.0) fakeDue = YES;   // 兜底
    if (fakeDue && !g_fakeScheduled) {
        g_fakeScheduled = YES;
        dispatch_async(dispatch_get_main_queue(), ^{
            aq_probe_license_class();
            aq_try_fake_activation(g_resultAlert ? @"校验结果之后" : @"18秒兜底");
        });
    }
    if ((g_tick % 20) == 0) aq_copy();
}

__attribute__((constructor))
static void aqaw_fix_start(void) {
    g_start = [NSProcessInfo processInfo].systemUptime;
    g_text = [NSMutableString string];
    [g_text appendString:@"===== aqaw 处理记录 =====\n"];
    // 先把上一次运行留下的日志读进来。如果上次是被原版无声结束的，
    // 这就是唯一能看到"最后走到哪一步"的现场。
    @try {
        NSString *dir = [NSSearchPathForDirectoriesInDomains(
                             NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        if (dir.length) {
            NSString *lp = [dir stringByAppendingPathComponent:@"aqaw_fix_log.txt"];
            NSString *prev = [NSString stringWithContentsOfFile:lp
                                                       encoding:NSUTF8StringEncoding
                                                          error:nil];
            if (prev.length > 40) {
                NSString *tail = prev.length > 2000
                               ? [prev substringFromIndex:prev.length - 2000] : prev;
                [g_text appendFormat:@"=== 上次运行最后记录 ===\n%@\n", tail];
            }
        }
    } @catch (NSException *e) {
    }
    aq_add(@"处理代码已加载");
    aq_install_crash_capture();

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
