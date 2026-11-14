// aqaw_probe.m —— aqaw 运行时处理版（注入用）
//
// 为什么走运行时：
//   实测原样副本能进、等价改写（行为完全一致，只换一种机器码写法）也闪退，
//   说明这个库会校验自己的机器码，任何静态改字节的版本都不可能跑起来。
//   因此这里一个字节都不改 aqaw 的机器码，只在运行时观察它、并替换它
//   调用系统函数时用的指针槽。
//
// 这一版做什么（磁盘文件零修改；只在旁边观察，不改任何一条机器码）：
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
//   7. 面板放行「只改数据，不碰代码」，并保留只读确认。原版在创建面板前会拿
//      数据段里的卡密缓存（0x1639298 起 0x90 字节）和只读常量段里的预期值
//      （0x130433C 起 32 个字）逐字比对。上一版去改那条分支指令，写完恢复执行
//      权限时系统两次都拒绝（日志里的 2/2），那一页失去执行权限、进程当场闪退。
//      这一版一个代码字节都不碰；日志已证明这 36 个字全程与预期值完全一致
//      （「共写入 0 次」），所以它不再是面板不出现的原因 —— 但仍保留观察，
//      万一原版中途清掉就立刻补回。
//   8. 看到校验结果后约 2.5 秒，用原版自己的激活状态写入方法写入一份测试状态，
//      看面板会不会因此放行；出现成功提示时自动点「确定」并把卡密输入框收起，
//      失败提示 4 秒后自动收起，避免挡住面板；
//   9. 记录原版校验算法实际参与计算的字节和结果（摘要与校验码），用来判断它
//      到底在比对什么；
//  10. 卡密弹窗保留 60 秒供自动验证使用，之后才自动关闭，避免界面卡死；
//  11. 大约 30 秒弹一次「aqaw 处理信息」窗口，内容同步复制到剪贴板；
//  12. 异常现场自救：捕获崩溃信号和未捕获异常，把出错指令、来源地址和访问
//      地址写进沙盒文件；再检测主线程是否被卡死（被系统看门狗杀掉时不会
//      有任何信号，只能靠这条路记下来）。每次启动还会把上一次运行的日志
//      尾巴读回来 —— 万一进程是被原版悄悄结束的，也能看到最后一步。
//  13. 面板构件运行时挂接 + 自建面板。只在三个纯界面类的初始化方法上做
//      「调用原实现 + 记录参数 + 原样返回」的观察（不替换卡密相关方法、不改机器码）。
//        · 覆盖窗口 _0x8C2F4D71（能接收点击的置顶窗口）
//        · 菜单视图 _0x1E6B7A93（Metal 绘制，自带 ImGui 菜单界面）
//        · 悬浮球   _0xD4E9A3C7（自带图片和拖动，点击后开菜单）
//      实测原版开局这一趟根本没创建任何面板构件（窗口列表里从头到尾只有游戏窗口
//      和键盘窗口），20 秒再让原版引擎跑一次也还是没建。所以从 22 秒起改用原版
//      自己的类自己搭：
//        · 22 秒：用 _0xD4E9A3C7 在右上角造悬浮球，放进 _0x8C2F4D71 覆盖窗口；
//          窗口和球都用静态变量长期持有（上一版只放在局部变量里，8 秒后就被
//          系统回收了，30 秒快照里已经找不到）。容器用自带的穿透命中判定，
//          只有点中悬浮球才算命中，其余位置交还游戏；
//        · 26 秒：用 _0x1E6B7A93 造菜单视图（Metal + ImGui），并给它两份配套
//          视图 _0xB1D7F3A9 / _0xC8E2A541，直接显示出来。菜单和悬浮球共用同一份
//          配置结构（原版设计就是球改配置、菜单读配置）；
//        · 点悬浮球可以开/关菜单。全部构建必须在主线程（上一版在后台队列里
//          建窗口，系统直接拒绝）。
//
// 为什么不再替换卡密相关方法：
//   上一版替换了原版的卡密处理方法和钥匙串方法，结果弹窗刚出现进程就无声
//   结束、还没留下崩溃信号 —— 原版很可能在校验自己的方法实现。所以卡密相关
//   方法一条都不碰；第 13 条只挂三个纯界面类的初始化方法。
//
// 仍然不做的事：
//   * 不修改磁盘上的任何文件；
//   * 不改任何一条机器码（第 7 条只写可写数据段里的缓存内容）；
//   * 不替换任何卡密 / 钥匙串 / 校验相关的方法；
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
#import <QuartzCore/QuartzCore.h>
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
#import <CommonCrypto/CommonDigest.h>

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
static BOOL g_gate12 = NO;
static BOOL g_successTapped = NO;
static double g_successSeen = 0;
static int g_shaUpdateLogs = 0;
static int g_shaFinalLogs = 0;
static int g_crcLogs = 0;
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
static NSString *aq_trunc(NSString *s, NSUInteger cap);
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
                // 新的结果弹窗：记下出现时间。
                if (a != g_resultAlert) {
                    g_resultAlert = a;
                    g_resultFirstSeen = aq_now();
                    g_resultClosed = NO;
                    g_successSeen = 0;
                }
                BOOL successLike = ((a.title && [a.title containsString:@"成功"]) ||
                                    (a.message && [a.message containsString:@"成功"]));
                if (successLike) {
                    if (g_successSeen == 0) g_successSeen = aq_now();
                    // 成功提示上的「确定」才会让原版继续往下走，这里替用户点一下，
                    // 而不是直接关掉弹窗（直接关会把后面的流程一起丢掉）。
                    if (!g_successTapped && aq_now() - g_successSeen >= 1.2) {
                        g_successTapped = YES;
                        UIAlertAction *target = nil;
                        for (UIAlertAction *ac in a.actions) {
                            NSString *t = ac.title ?: @"";
                            if ([t isEqualToString:@"确定"] || [t isEqualToString:@"好"] ||
                                [t isEqualToString:@"知道了"]) {
                                target = ac;
                                break;
                            }
                        }
                        if (!target && a.actions.count > 0) target = a.actions.firstObject;
                        id handler = nil;
                        @try { handler = [target valueForKey:@"handler"]; } @catch (NSException *e) {}
                        if (handler) {
                            aq_add(@"已自动点击成功提示的「%@」", target.title ?: @"?");
                            ((void (^)(UIAlertAction *))handler)(target);
                        } else {
                            [a dismissViewControllerAnimated:NO completion:nil];
                            aq_add(@"成功提示没有可触发的处理块，已关闭");
                        }
                        aq_copy();
                    }
                    continue;
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

            // 成功提示已经确认过，卡密输入框就没用了，收起来别挡面板。
            if (g_successTapped && g_alertDismissed < 1) {
                [a dismissViewControllerAnimated:NO completion:nil];
                g_alertDismissed += 1;
                aq_add(@"激活成功已确认，关闭卡密输入框");
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

// ---- 校验算法观察：摘要与校验码（只记录参与计算的数据和结果） -----------------
// 卡密校验是本地完成的，这里看它到底把哪些字节拿去算了摘要、算出的结果是多少，
// 从而判断它是在比对什么。
typedef int (*aq_sha_fn)(const void *, uint32_t, unsigned char *);
typedef int (*aq_sha_update_fn)(void *, const void *, uint32_t);
typedef int (*aq_sha_final_fn)(unsigned char *, void *);
typedef unsigned long (*aq_crc32_fn)(unsigned long, const void *, unsigned int);
static aq_sha_fn aq_real_sha = NULL;
static aq_sha_update_fn aq_real_sha_update = NULL;
static aq_sha_final_fn aq_real_sha_final = NULL;
static aq_crc32_fn aq_real_crc32 = NULL;

static int aq_my_sha(const void *data, uint32_t len, unsigned char *md) {
    int r = aq_real_sha ? aq_real_sha(data, len, md) : 0;
    if (data && len > 0 && md && g_shaFinalLogs < 25) {
        g_shaFinalLogs += 1;
        NSMutableString *h = [NSMutableString string];
        for (int i = 0; i < 32; i++) [h appendFormat:@"%02X", md[i]];
        aq_add(@"一次性摘要 %u 字节: %@ → %@", (unsigned)len,
               aq_bytes_desc(data, (size_t)len), h);
        aq_copy();
    }
    return r;
}

static int aq_my_sha_update(void *ctx, const void *data, uint32_t len) {
    if (data && len > 0 && g_shaUpdateLogs < 25) {
        g_shaUpdateLogs += 1;
        aq_add(@"摘要输入 %u 字节: %@", (unsigned)len, aq_bytes_desc(data, (size_t)len));
        aq_copy();
    }
    return aq_real_sha_update ? aq_real_sha_update(ctx, data, len) : 0;
}

static int aq_my_sha_final(unsigned char *md, void *ctx) {
    int r = aq_real_sha_final ? aq_real_sha_final(md, ctx) : 0;
    if (md && g_shaFinalLogs < 25) {
        g_shaFinalLogs += 1;
        NSMutableString *h = [NSMutableString string];
        for (int i = 0; i < 32; i++) [h appendFormat:@"%02X", md[i]];
        aq_add(@"摘要结果 %@", h);
        aq_copy();
    }
    return r;
}

static unsigned long aq_my_crc32(unsigned long crc, const void *buf, unsigned int len) {
    unsigned long r = aq_real_crc32 ? aq_real_crc32(crc, buf, len) : 0;
    if (buf && len > 0 && g_crcLogs < 20) {
        g_crcLogs += 1;
        aq_add(@"校验码计算 %u 字节: %@ → %08lX", len,
               aq_bytes_desc(buf, (size_t)len), r);
        aq_copy();
    }
    return r;
}

// ---- 钥匙串读写观察（原样转发，只记录读到的服务/账号/内容） ----------------
// 激活状态在系统钥匙串里。这里只换目标库调用系统钥匙串函数时的指针槽，
// 调用参数和返回值原样转发，不改任何内容，也不碰原版自己的方法。
typedef int (*aq_sec2_fn)(id, id *);
typedef int (*aq_sec1_fn)(id);
typedef int (*aq_sec11_fn)(id, id);
static aq_sec2_fn aq_real_sec_add = NULL;
static aq_sec2_fn aq_real_sec_copy = NULL;
static aq_sec11_fn aq_real_sec_upd = NULL;
static aq_sec1_fn aq_real_sec_del = NULL;
static int g_secLogs = 0;

static NSString *aq_trunc(NSString *s, NSUInteger cap);

static NSString *aq_obj_desc(id o, NSUInteger cap) {
    if (!o) return @"(空)";
    id d = ((id (*)(id, SEL))objc_msgSend)(o, sel_registerName("description"));
    if (!d) return @"(无描述)";
    return aq_trunc((NSString *)d, cap);
}

static int aq_my_sec_add(id attrs, id *result) {
    int st = aq_real_sec_add ? aq_real_sec_add(attrs, result) : -1;
    if (g_secLogs < 20) {
        g_secLogs += 1;
        aq_add(@"钥匙串存入 状态=%d 内容=%@", st, aq_obj_desc(attrs, 320));
        aq_copy();
    }
    return st;
}

static int aq_my_sec_copy(id query, id *result) {
    int st = aq_real_sec_copy ? aq_real_sec_copy(query, result) : -1;
    if (g_secLogs < 20) {
        g_secLogs += 1;
        aq_add(@"钥匙串读取 状态=%d 查询=%@ 结果=%@", st,
               aq_obj_desc(query, 320),
               (st == 0 && result) ? aq_obj_desc(*result, 320) : @"(无)");
        aq_copy();
    }
    return st;
}

static int aq_my_sec_upd(id query, id attrs) {
    int st = aq_real_sec_upd ? aq_real_sec_upd(query, attrs) : -1;
    if (g_secLogs < 20) {
        g_secLogs += 1;
        aq_add(@"钥匙串更新 状态=%d 查询=%@ 新内容=%@", st,
               aq_obj_desc(query, 220), aq_obj_desc(attrs, 220));
        aq_copy();
    }
    return st;
}

static int aq_my_sec_del(id query) {
    int st = aq_real_sec_del ? aq_real_sec_del(query) : -1;
    if (g_secLogs < 20) {
        g_secLogs += 1;
        aq_add(@"钥匙串删除 状态=%d 查询=%@", st, aq_obj_desc(query, 320));
        aq_copy();
    }
    return st;
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
    aq_real_sha = (aq_sha_fn)dlsym(RTLD_DEFAULT, "CC_SHA256");
    aq_real_sha_update = (aq_sha_update_fn)dlsym(RTLD_DEFAULT, "CC_SHA256_Update");
    aq_real_sha_final = (aq_sha_final_fn)dlsym(RTLD_DEFAULT, "CC_SHA256_Final");
    aq_real_crc32 = (aq_crc32_fn)dlsym(RTLD_DEFAULT, "crc32");
    aq_real_sec_add = (aq_sec2_fn)dlsym(RTLD_DEFAULT, "SecItemAdd");
    aq_real_sec_copy = (aq_sec2_fn)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    aq_real_sec_upd = (aq_sec11_fn)dlsym(RTLD_DEFAULT, "SecItemUpdate");
    aq_real_sec_del = (aq_sec1_fn)dlsym(RTLD_DEFAULT, "SecItemDelete");
    struct { uintptr_t slot; void *fn; } hook[16] = {
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
        { 0x13E0600, (void *)&aq_my_crc32 },
        { 0x13E0230, (void *)&aq_my_sha_update },
        { 0x13E0220, (void *)&aq_my_sha_final },
        { 0x13E0218, (void *)&aq_my_sha },
    };
    for (int i = 0; i < 16; i++) {
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
    struct { uintptr_t slot; void *fn; BOOL ready; } sechook[4] = {
        { 0x13E02E0, (void *)&aq_my_sec_add, aq_real_sec_add != NULL },
        { 0x13E02E8, (void *)&aq_my_sec_copy, aq_real_sec_copy != NULL },
        { 0x13E02F0, (void *)&aq_my_sec_del, aq_real_sec_del != NULL },
        { 0x13E02F8, (void *)&aq_my_sec_upd, aq_real_sec_upd != NULL },
    };
    for (int i = 0; i < 4; i++) {
        if (!sechook[i].ready) continue;
        uintptr_t slot = (uintptr_t)(g_slide + sechook[i].slot);
        uintptr_t page = slot & ~(uintptr_t)0x3FFF;
        kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS)
            kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                            VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) continue;
        memcpy((void *)slot, &sechook[i].fn, sizeof(void *));
        vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE);
    }
    g_hookInstalled = YES;
    aq_add(@"调度、退出、卡密通道、校验算法与钥匙串读取观察已安装（只记录，退出类调用会被拦下）");
    aq_copy();
    return YES;
}

// ---- 面板构件的运行时挂接：只在这三个视图类上挂/换方法，不改任何一条机器码 ------
// 证据（实际指令）：面板由「覆盖窗口 _0x8C2F4D71 → 菜单视图 _0x1E6B7A93（Metal 绘制）
// → 悬浮球 _0xD4E9A3C7」三件套组成。原版在创建它们之前先比对数据段缓存与常量段预期值，
// 这一版实测两边 36 个字完全一致（日志「共写入 0 次」），也就是说比对是过的，
// 面板却没出现。为了分清「根本没走到创建」还是「创建了又被藏起来/拆掉」，
// 这里只在运行时给这三个类挂上观察方法：调用原实现、记录参数与结果，再原样返回。
static BOOL aq_panelWatchInstalled = NO;
static BOOL aq_overlaySeen = NO;
static BOOL aq_ballSeen = NO;
static BOOL aq_viewSeen = NO;
static BOOL aq_overlayForced = NO;
static BOOL aq_ballBuilt = NO;
static BOOL aq_ballTried = NO;
static BOOL aq_panelMissingLogged = NO;
static BOOL aq_engineRetried = NO;
static CGRect aq_overlayFrame;
static CGRect aq_ballFrame;
static CGRect aq_viewFrame;
static double aq_overlaySeenAt = 0;

typedef id (*AqInitFrameFn)(id, SEL, CGRect);
typedef void (*AqSetHiddenFn)(id, SEL, BOOL);
typedef id (*AqInitFrame2Fn)(id, SEL, CGRect, void *);
typedef id (*AqInitFrame4Fn)(id, SEL, CGRect, void *, id, id);
typedef id (*AqInitSceneFn)(id, SEL, id);

static AqInitFrameFn aq_origWinInit = NULL;
static AqSetHiddenFn aq_origWinHidden = NULL;
static AqInitFrame2Fn aq_origBallInit = NULL;
static AqInitFrame4Fn aq_origViewInit = NULL;
static AqInitSceneFn aq_origWinSceneInit = NULL;

// 自建面板用到的状态。窗口和视图都放静态变量里持有，
// 上一版只把它们放在局部变量里，窗口几秒后就被系统回收了（30 秒快照里已经找不到）。
static BOOL aq_selfBuilding = NO;
static UIWindow *aq_ballWindow = nil;
static id aq_ballView = nil;
static UIWindow *aq_menuWindow = nil;
static id aq_menuView = nil;
static BOOL aq_menuBuilt = NO;
static BOOL aq_menuTried = NO;
static BOOL aq_menuVisible = NO;
static BOOL aq_ballDiag2 = NO;
static uint8_t aq_panelCfg[0x200];   // 悬浮球和菜单视图共用同一份配置

// 穿透容器：只有点中里面的悬浮球才算命中，其余位置一律交还给游戏。
// 这里手写矩形判断，不用系统的 CGRectContainsPoint —— 那个符号在 CoreGraphics 里，
// 不额外链接框架时会报未定义符号。
static BOOL aq_rect_contains(CGRect r, CGPoint p) {
    return p.x >= r.origin.x && p.x <= r.origin.x + r.size.width &&
           p.y >= r.origin.y && p.y <= r.origin.y + r.size.height;
}

static id aq_pass_hit(id self, SEL _cmd, CGPoint p, id event) {
    @try {
        for (UIView *sub in [(UIView *)self subviews]) {
            if (sub.isHidden || sub.alpha < 0.01) continue;
            CGPoint q = [sub convertPoint:p fromView:(UIView *)self];
            if (aq_rect_contains(sub.bounds, q)) return sub;
        }
    } @catch (NSException *e) {
    }
    return nil;
}

static Class aq_passthrough_view_class(void) {
    static Class C = Nil;
    if (!C) {
        C = NSClassFromString(@"AqPassthroughView");
        if (!C) {
            C = objc_allocateClassPair([UIView class], "AqPassthroughView", 0);
            if (C) {
                class_addMethod(C, @selector(hitTest:withEvent:), (IMP)aq_pass_hit, "@40@0:8{CGPoint=dd}16@32");
                objc_registerClassPair(C);
            }
        }
    }
    return C;
}

static UIWindowScene *aq_front_scene(void) {
    UIApplication *app = [UIApplication sharedApplication];
    UIWindowScene *any = nil;
    @try {
        for (UIScene *s in app.connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            if (!any) any = (UIWindowScene *)s;
            if (s.activationState == UISceneActivationStateForegroundActive) return (UIWindowScene *)s;
        }
    } @catch (NSException *e) {
    }
    return any;
}

// 把一个视图树按 类名/位置/可见性 逐层记下来，用来判断「看不到」到底是没建、
// 建了但没图、还是尺寸/透明度被清成了 0。
static void aq_dump_view_tree(id obj, NSString *indent, int depth) {
    UIView *v = (UIView *)obj;
    if (!v || depth > 4) return;
    @try {
        CGRect f = v.frame;
        NSMutableString *extra = [NSMutableString string];
        if ([v isKindOfClass:[UIImageView class]]) {
            UIImage *img = ((UIImageView *)v).image;
            [extra appendFormat:@" 图片=%@ 图尺寸=%.0fx%.0f", img ? @"有" : @"无",
                               img ? img.size.width : 0, img ? img.size.height : 0];
        }
        aq_add(@"%@%@ frame=(%.0f,%.0f,%.0f,%.0f) 隐藏=%d 透明度=%.2f 子视图=%lu%@",
               indent, NSStringFromClass([v class]),
               f.origin.x, f.origin.y, f.size.width, f.size.height,
               (int)v.isHidden, v.alpha, (unsigned long)v.subviews.count, extra);
        for (UIView *s in v.subviews) {
            aq_dump_view_tree(s, [indent stringByAppendingString:@"  "], depth + 1);
        }
    } @catch (NSException *e) {
    }
}

static id aq_hook_win_init(id self, SEL _cmd, CGRect f) {
    id r = aq_origWinInit ? aq_origWinInit(self, _cmd, f) : nil;
    aq_overlaySeen = YES;
    aq_overlayFrame = f;
    aq_overlaySeenAt = aq_now();
    aq_add(@"[面板] 覆盖窗口被创建 frame=(%.0f,%.0f,%.0f,%.0f) 结果=%p",
           f.origin.x, f.origin.y, f.size.width, f.size.height, r);
    return r;
}

static void aq_hook_win_hidden(id self, SEL _cmd, BOOL hidden) {
    if (aq_origWinHidden) aq_origWinHidden(self, _cmd, hidden);
    if (aq_selfBuilding || self == aq_ballWindow || self == aq_menuWindow) return;
    aq_add(@"[面板] 覆盖窗口 hidden=%d（原版自己改的可见性）", (int)hidden);
}

// 上一版只盯了 initWithFrame:，但新系统上建窗口走的是 initWithWindowScene:。
// 我们自己建的那个窗口就没触发 initWithFrame: —— 原版若走同一条路，之前也是看不到的。
static id aq_hook_win_scene_init(id self, SEL _cmd, id scene) {
    id r = aq_origWinSceneInit ? aq_origWinSceneInit(self, _cmd, scene) : nil;
    if (aq_selfBuilding) return r;
    aq_overlaySeen = YES;
    aq_overlaySeenAt = aq_now();
    aq_add(@"[面板] 覆盖窗口被创建（按场景）结果=%p", r);
    return r;
}

static id aq_hook_ball_init(id self, SEL _cmd, CGRect f, void *cfg) {
    aq_add(@"[面板] 悬浮球正在创建 frame=(%.0f,%.0f,%.0f,%.0f) 配置=%p",
           f.origin.x, f.origin.y, f.size.width, f.size.height, cfg);
    id r = aq_origBallInit ? aq_origBallInit(self, _cmd, f, cfg) : nil;
    aq_ballSeen = YES;
    aq_ballFrame = f;
    aq_add(@"[面板] 悬浮球创建完成 结果=%p", r);
    return r;
}

static id aq_hook_view_init(id self, SEL _cmd, CGRect f, void *cfg, id a, id b) {
    aq_add(@"[面板] 菜单视图正在创建 frame=(%.0f,%.0f,%.0f,%.0f) 配置=%p",
           f.origin.x, f.origin.y, f.size.width, f.size.height, cfg);
    id r = aq_origViewInit ? aq_origViewInit(self, _cmd, f, cfg, a, b) : nil;
    aq_viewSeen = YES;
    aq_viewFrame = f;
    aq_add(@"[面板] 菜单视图创建完成 结果=%p", r);
    return r;
}

// 覆盖窗口是否真的存在（按类名在应用窗口列表里找）。
static UIWindow *aq_overlay_window(void) {
    @try {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if ([NSStringFromClass([w class]) isEqualToString:@"_0x8C2F4D71"]) return w;
        }
    } @catch (NSException *e) {
    }
    return nil;
}

// 把每个窗口的真实状态写进记录：类名、可见性、层级、尺寸、子视图数量。
static void aq_dump_windows(NSString *tag) {
    @try {
        NSArray<UIWindow *> *ws = [UIApplication sharedApplication].windows;
        aq_add(@"%@窗口共 %lu 个", tag, (unsigned long)ws.count);
        for (UIWindow *w in ws) {
            NSString *vc = w.rootViewController ? NSStringFromClass([w.rootViewController class]) : @"无";
            aq_add(@"  %@ 可见=%d 层级=%.0f 尺寸=%.0fx%.0f 子视图=%lu 根控制器=%@",
                   NSStringFromClass([w class]), (int)!w.hidden, w.windowLevel,
                   w.bounds.size.width, w.bounds.size.height,
                   (unsigned long)w.subviews.count, vc);
        }
    } @catch (NSException *e) {
        aq_add(@"%@窗口状态读取失败: %@", tag, e.reason ?: @"未知");
    }
}

// 如果原版创建了覆盖窗口却把它藏起来（或者还没挂到屏幕上），这里把它请回最前面。
static void aq_reveal_overlay(void) {
    UIWindow *w = aq_overlay_window();
    if (!w) {
        aq_add(@"[面板] 没有找到覆盖窗口（原版没有创建，或在创建后被释放）");
        return;
    }
    @try {
        BOOL wasHidden = w.hidden;
        CGFloat wasLevel = w.windowLevel;
        NSUInteger subs = w.subviews.count;
        w.hidden = NO;
        w.windowLevel = UIWindowLevelAlert + 40;
        [w makeKeyAndVisible];
        aq_add(@"[面板] 覆盖窗口已请到前台：原来可见=%d 层级=%.0f 子视图=%lu，现在可见=%d 层级=%.0f",
               (int)!wasHidden, wasLevel, (unsigned long)subs, (int)!w.hidden, w.windowLevel);
    } @catch (NSException *e) {
        aq_add(@"[面板] 覆盖窗口请到前台失败: %@", e.reason ?: @"未知");
    }
}

// 原版一直没创建悬浮球时，用原版自己的悬浮球类自己搭一个，放在右上角。
// 只调用它自己的初始化方法，并关掉自带点击手势（它的点击处理器依赖启动现场，
// 空手触发会崩；拖动用的触摸方法不依赖现场，仍然可用）。
static void aq_toggle_menu(void);

static void aq_ball_tapped(id self, SEL _cmd) {
    aq_toggle_menu();
}

static void aq_build_ball_main(void) {
    @try {
        Class B = NSClassFromString(@"_0xD4E9A3C7");
        if (!B) {
            aq_add(@"[悬浮球] 类未注册，无法自建");
            return;
        }
        UIWindowScene *scene = aq_front_scene();
        if (!scene) {
            aq_add(@"[悬浮球] 没有可用的界面场景，暂不自建");
            return;
        }
        CGRect scr = [UIScreen mainScreen].bounds;
        CGFloat side = 56.0, margin = 12.0, top = 60.0;
        CGRect f = CGRectMake(scr.size.width - side - margin, top, side, side);
        // 悬浮球和菜单视图共用同一份配置（原版也是这么设计的：球只改这份配置里的开关）。
        memset(aq_panelCfg, 0, sizeof(aq_panelCfg));
        id ball = ((id (*)(id, SEL, CGRect, void *))objc_msgSend)(
            [B alloc], NSSelectorFromString(@"initWithFrame::"), f, aq_panelCfg);
        if (!ball) {
            aq_add(@"[悬浮球] 自建返回空");
            return;
        }
        // 原版自带的点击处理器依赖启动现场，先关掉；换成我们自己的开/关菜单。
        for (UIGestureRecognizer *g in [ball gestureRecognizers]) g.enabled = NO;
        class_addMethod([ball class], NSSelectorFromString(@"aqBallTapped"), (IMP)aq_ball_tapped, "v@:");
        UITapGestureRecognizer *tap =
            [[UITapGestureRecognizer alloc] initWithTarget:ball action:NSSelectorFromString(@"aqBallTapped")];
        [ball addGestureRecognizer:tap];

        // 图标是初始化时从内置图片还原出来的。如果它是空的，就补一层能看见的圆底，
        // 免得出现「视图确实在窗口里、屏幕上却什么都没有」的情况。
        UIImage *icon = nil;
        @try {
            SEL si = NSSelectorFromString(@"iconImageView");
            if ([ball respondsToSelector:si]) {
                id iv = ((id (*)(id, SEL))objc_msgSend)(ball, si);
                if ([iv isKindOfClass:[UIImageView class]]) icon = [(UIImageView *)iv image];
            }
        } @catch (NSException *e) {
        }
        if (!icon) {
            UIView *ballView = (UIView *)ball;
            ballView.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.85];
            ballView.layer.cornerRadius = side / 2.0;
            ballView.layer.borderWidth = 2.0;
            ballView.layer.borderColor = [UIColor colorWithRed:0.35 green:0.9 blue:0.62 alpha:1.0].CGColor;
            aq_add(@"[悬浮球] 内置图标为空，已补可见圆底");
        }

        Class W = NSClassFromString(@"_0x8C2F4D71");
        aq_selfBuilding = YES;
        UIWindow *w = W ? [[W alloc] initWithWindowScene:scene]
                        : [[UIWindow alloc] initWithWindowScene:scene];
        w.windowLevel = UIWindowLevelAlert + 32;
        UIViewController *vc = [[UIViewController alloc] init];
        // 容器只放行「点中悬浮球」的位置，其余点击交还游戏。
        Class PC = aq_passthrough_view_class();
        vc.view = PC ? [[PC alloc] initWithFrame:scr] : [[UIView alloc] initWithFrame:scr];
        vc.view.backgroundColor = [UIColor clearColor];
        w.rootViewController = vc;
        [vc.view addSubview:ball];
        // 静态变量持有，窗口和球不会再被系统提前回收（上一版就是这么消失的）。
        aq_ballWindow = w;
        aq_ballView = ball;
        aq_ballBuilt = YES;
        aq_ballFrame = f;
        w.hidden = NO;
        aq_selfBuilding = NO;
        aq_add(@"[悬浮球] 已用原版类自建并放到右上角 frame=(%.0f,%.0f,%.0f,%.0f)，自带点击已关闭、拖动保留",
               f.origin.x, f.origin.y, f.size.width, f.size.height);
        aq_dump_view_tree(ball, @"[悬浮球]", 0);
        CGRect wf = w.frame, vf = vc.view.frame;
        aq_add(@"[悬浮球] 承载窗口 尺寸=%.0fx%.0f 位置=(%.0f,%.0f) 层级=%.0f 隐藏=%d 容器=(%.0f,%.0f,%.0f,%.0f)",
               w.bounds.size.width, w.bounds.size.height, wf.origin.x, wf.origin.y,
               w.windowLevel, (int)w.hidden, vf.origin.x, vf.origin.y, vf.size.width, vf.size.height);
        aq_dump_windows(@"自建悬浮球后");
    } @catch (NSException *e) {
        aq_add(@"[悬浮球] 自建失败: %@", e.reason ?: @"未知");
    }
}

// 界面必须在主线程上创建（上一版在后台队列里建窗口，系统直接拒绝）。
static void aq_build_ball(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        aq_build_ball_main();
    });
}

// 菜单视图就是原版那套 Metal + ImGui 面板，它自己会读这份配置里的开关。
static void aq_toggle_menu(void) {
    if (!aq_menuBuilt || !aq_menuWindow) {
        aq_add(@"[菜单] 还没建好，暂不能开/关");
        return;
    }
    aq_menuVisible = !aq_menuVisible;
    aq_menuWindow.hidden = !aq_menuVisible;
    aq_add(@"[菜单] %@", aq_menuVisible ? @"已打开" : @"已收起");
    aq_copy();
}

static void aq_build_menu_main(void) {
    @try {
        Class V = NSClassFromString(@"_0x1E6B7A93");
        if (!V) {
            aq_add(@"[菜单] 视图类未注册");
            return;
        }
        UIWindowScene *scene = aq_front_scene();
        if (!scene) {
            aq_add(@"[菜单] 没有可用的界面场景");
            return;
        }
        CGRect scr = [UIScreen mainScreen].bounds;
        // 原版初始化时还要两个配套视图（面板里两个分组的内容/回调）。
        Class A = NSClassFromString(@"_0xB1D7F3A9");
        Class C = NSClassFromString(@"_0xC8E2A541");
        id av = nil, cv = nil;
        SEL setCfg = NSSelectorFromString(@"set_0xE4C8719B:");
        if (A) {
            av = [[A alloc] initWithFrame:scr];
            if (av && [av respondsToSelector:setCfg]) {
                ((void (*)(id, SEL, void *))objc_msgSend)(av, setCfg, aq_panelCfg);
            }
        }
        if (C) {
            cv = [[C alloc] initWithFrame:scr];
            if (cv && [cv respondsToSelector:setCfg]) {
                ((void (*)(id, SEL, void *))objc_msgSend)(cv, setCfg, aq_panelCfg);
            }
        }
        aq_add(@"[菜单] 配套视图 甲=%@ 乙=%@",
               av ? NSStringFromClass([av class]) : @"无",
               cv ? NSStringFromClass([cv class]) : @"无");
        id menu = ((id (*)(id, SEL, CGRect, void *, id, id))objc_msgSend)(
            [V alloc], NSSelectorFromString(@"initWithFrame::::"), scr, aq_panelCfg, av, cv);
        if (!menu) {
            aq_add(@"[菜单] 创建返回空");
            aq_copy();
            return;
        }
        aq_menuView = menu;
        Class W = NSClassFromString(@"_0x8C2F4D71");
        aq_selfBuilding = YES;
        UIWindow *w = W ? [[W alloc] initWithWindowScene:scene]
                        : [[UIWindow alloc] initWithWindowScene:scene];
        aq_selfBuilding = NO;
        w.windowLevel = UIWindowLevelAlert + 31;
        UIViewController *vc = [[UIViewController alloc] init];
        vc.view = [[UIView alloc] initWithFrame:scr];
        vc.view.backgroundColor = [UIColor clearColor];
        w.rootViewController = vc;
        [vc.view addSubview:menu];
        aq_menuWindow = w;
        aq_menuBuilt = YES;
        aq_add(@"[菜单] 已创建 结果=%p 尺寸=%.0fx%.0f，直接显示", menu, scr.size.width, scr.size.height);
        w.hidden = NO;
        aq_menuVisible = YES;
        aq_dump_view_tree(menu, @"[菜单]", 0);
        aq_dump_windows(@"自建菜单后");
        aq_copy();
    } @catch (NSException *e) {
        aq_add(@"[菜单] 创建失败: %@", e.reason ?: @"未知");
        aq_copy();
    }
}

static void aq_build_menu(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        aq_build_menu_main();
    });
}

static void aq_install_panel_watch(void) {
    if (aq_panelWatchInstalled) return;
    aq_panelWatchInstalled = YES;
    Class W = NSClassFromString(@"_0x8C2F4D71");
    Class B = NSClassFromString(@"_0xD4E9A3C7");
    Class V = NSClassFromString(@"_0x1E6B7A93");
    int added = 0, replaced = 0;
    if (W) {
        Class sup = class_getSuperclass(W);
        SEL sf = @selector(initWithFrame:);
        Method mf = sup ? class_getInstanceMethod(sup, sf) : NULL;
        if (mf) {
            aq_origWinInit = (AqInitFrameFn)method_getImplementation(mf);
            if (class_addMethod(W, sf, (IMP)aq_hook_win_init, method_getTypeEncoding(mf))) added++;
        }
        SEL sh = @selector(setHidden:);
        Method mh = sup ? class_getInstanceMethod(sup, sh) : NULL;
        if (mh) {
            aq_origWinHidden = (AqSetHiddenFn)method_getImplementation(mh);
            if (class_addMethod(W, sh, (IMP)aq_hook_win_hidden, method_getTypeEncoding(mh))) added++;
        }
        SEL sw = @selector(initWithWindowScene:);
        Method mw = sup ? class_getInstanceMethod(sup, sw) : NULL;
        if (mw) {
            aq_origWinSceneInit = (AqInitSceneFn)method_getImplementation(mw);
            if (class_addMethod(W, sw, (IMP)aq_hook_win_scene_init, method_getTypeEncoding(mw))) added++;
        }
    }
    if (B) {
        SEL sb = NSSelectorFromString(@"initWithFrame::");
        Method mb = class_getInstanceMethod(B, sb);
        if (mb) {
            aq_origBallInit = (AqInitFrame2Fn)method_getImplementation(mb);
            method_setImplementation(mb, (IMP)aq_hook_ball_init);
            replaced++;
        }
    }
    if (V) {
        SEL sv = NSSelectorFromString(@"initWithFrame::::");
        Method mv = class_getInstanceMethod(V, sv);
        if (mv) {
            aq_origViewInit = (AqInitFrame4Fn)method_getImplementation(mv);
            method_setImplementation(mv, (IMP)aq_hook_view_init);
            replaced++;
        }
    }
    aq_add(@"面板构件观察已安装（窗口类%@ 悬浮球类%@ 菜单视图类%@；新增 %d 个、替换 %d 个方法）",
           W ? @"在" : @"缺", B ? @"在" : @"缺", V ? @"在" : @"缺", added, replaced);
    aq_copy();
}

// ---- 面板放行：把卡密缓存按出厂内容写回（纯数据，不碰任何代码） --------------
// 反汇编结论（均为实际指令）：
//   * 0xA110F8：把内部标记从 x26 复制到栈上的位置，供最后的判断读取；
//   * 0xA10D80：ldr w8,[x8]; subs wzr,w8,#0 → 标记为 0 就走「创建面板」；
//   * 0xA105DC：标记被置 1 的唯一点，由 0xA11164 的比对失败分支跳过来；
//   * 0xA11164：把缓存里的一个字（0x1639298+0x10+i*4）与预期值
//                （0x130433C+i*4）比较，相等走成功，不等走上面的置 1。
// 上一版据此认为「面板不出现 = 这段比对没通过」，实测日志推翻了它：
// 36 个字从头到尾与预期值完全一致（「卡密缓存与预期值一致（36 个字全部相同）」、
// 「共写入 0 次」），比对是过的，面板仍然没出现。所以这里不再是放行手段，
// 只保留只读监视 + 万一被清掉就补回。缓存区在 __DATA（可写），预期值在
// __TEXT/__ckimm（只读）；全过程一行机器码都不动。
static const uint32_t kAqCkBlob[36] = {
    0x434A4B43u, 0x00000001u, 0x00000001u, 0x00000020u,  // 头：标识、版本、字数 32
    0x82DEFD09u, 0x8BE5C0ADu, 0x457E9383u, 0xDE9C8092u,
    0xA32FA94Bu, 0x2DEB9FC9u, 0x6EB58511u, 0x64558161u,
    0x19B44876u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0xEFD60FD0u, 0x53FCF9A4u,
    0xA57D7FBAu, 0xB5136A38u, 0x21D75ED5u, 0x571449F1u,
    0x9242E5D9u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x1C203114u, 0x01032208u
};

static BOOL g_ckFirstCheck = NO;
static BOOL g_ckRestored = NO;
static BOOL g_ckHaveSeen = NO;
static BOOL g_ckWindowClosed = NO;
static int  g_ckWriteCount = 0;
static uint32_t g_ckLastSeen[36] = {0};

static void aq_repair_keycache(void) {
    if (!g_found) return;
    uintptr_t blobAddr = (uintptr_t)(g_slide + 0x1639298);
    uint32_t cur[36];
    memcpy(cur, (const void *)blobAddr, sizeof(cur));

    int diff = 0;
    int firstDiff = 0;
    for (int i = 0; i < 36; i++) {
        if (cur[i] != kAqCkBlob[i]) {
            if (diff == 0) firstDiff = i;
            diff++;
        }
    }

    if (!g_ckFirstCheck) {
        g_ckFirstCheck = YES;
        if (diff == 0) {
            aq_add(@"卡密缓存与预期值一致（36 个字全部相同）");
        } else {
            aq_add(@"卡密缓存与预期值不同：%d/36 个字不一致，首个不同在第 %d 个字（当前 %08X，预期 %08X）",
                   diff, firstDiff, cur[firstDiff], kAqCkBlob[firstDiff]);
        }
    }

    if (diff == 0) {
        memcpy(g_ckLastSeen, cur, sizeof(cur));
        g_ckHaveSeen = YES;
        return;
    }

    if (!g_ckHaveSeen || memcmp(g_ckLastSeen, cur, sizeof(cur)) != 0) {
        g_ckHaveSeen = YES;
        memcpy(g_ckLastSeen, cur, sizeof(cur));
        aq_add(@"卡密缓存内容有变化（%d/36 处不同），前四字 %08X %08X %08X %08X",
               diff, cur[0], cur[1], cur[2], cur[3]);
    }

    // 只写可写数据段；不经过 vm_protect，也不碰代码页。
    memcpy((void *)blobAddr, kAqCkBlob, sizeof(kAqCkBlob));
    g_ckWriteCount++;
    if (!g_ckRestored) {
        g_ckRestored = YES;
        aq_add(@"已按出厂内容写回卡密缓存（纯数据写入，代码一个字节没动）");
        aq_copy();
    }
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
    // 原版开局检查（实测 1.3~3.5 秒之间）会读这块缓存。检查开始前先写回出厂内容，
    // 之后每 0.1 秒确认一次：原版中途把它清掉就立刻补回去。全程只写数据段。
    if (g_found && aq_now() >= 0.30 && aq_now() <= 8.0) {
        aq_repair_keycache();
    }
    if (g_found && !g_ckWindowClosed && aq_now() > 8.0) {
        g_ckWindowClosed = YES;
        aq_add(@"卡密缓存写回结束，共写入 %d 次", g_ckWriteCount);
        aq_copy();
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
    // 0.9 秒起装上面板构件观察：原版一创建覆盖窗口 / 悬浮球 / 菜单视图就留痕。
    if (g_found && !aq_panelWatchInstalled && aq_now() >= 0.9) {
        aq_install_panel_watch();
    }
    // 覆盖窗口一出现，等 0.5 秒看它的真实状态；若被藏着就请到前台。
    if (g_found && aq_overlaySeen && !aq_overlayForced && aq_now() >= aq_overlaySeenAt + 0.5) {
        aq_overlayForced = YES;
        aq_dump_windows(@"覆盖窗口出现后");
        aq_reveal_overlay();
    }
    // 4.5 秒还没见过覆盖窗口：把窗口构成记清楚，说明原版根本没走到创建。
    if (g_found && !aq_overlaySeen && !aq_panelMissingLogged && aq_now() >= 4.5) {
        aq_panelMissingLogged = YES;
        aq_add(@"[面板] 4.5 秒了仍未见覆盖窗口创建（原版没走到这一步）");
        aq_dump_windows(@"未见覆盖窗口时");
        aq_copy();
    }
    // 20 秒：激活流程已经走完，再让原版引擎跑一次，看它这次会不会创建面板。
    if (g_found && !aq_engineRetried && aq_now() >= 20.0) {
        aq_engineRetried = YES;
        dispatch_async(dispatch_get_main_queue(), ^{
            aq_add(@"[引擎] 20 秒再跑一次原版引擎块（激活流程之后）");
            aq_copy();
            void (*invoke)(void *) = (void (*)(void *))(g_slide + 0xA0FF80);
            invoke((void *)(g_slide + 0xA0FCD8));
            aq_add(@"[引擎] 引擎块第二次运行结束");
            aq_dump_windows(@"二次引擎后");
            aq_copy();
        });
    }
    // 22 秒原版还没建过悬浮球：用原版自己的类在右上角自建一个（只试一次）。
    if (g_found && !aq_ballSeen && !aq_ballTried && aq_now() >= 22.0) {
        aq_ballTried = YES;
        aq_build_ball();
    }
    // 28 秒复查悬浮球窗口还在不在（上一版就是几秒后窗口被系统回收了）。
    if (g_found && aq_ballBuilt && !aq_ballDiag2 && aq_now() >= 28.0) {
        aq_ballDiag2 = YES;
        aq_dump_windows(@"28秒悬浮球复查");
        if (aq_ballView) {
            UIView *bv = (UIView *)aq_ballView;
            aq_add(@"[悬浮球] 28 秒复查 隐藏=%d 透明度=%.2f 父视图=%@",
                   (int)bv.isHidden, bv.alpha,
                   bv.superview ? NSStringFromClass([bv.superview class]) : @"无");
        }
        aq_copy();
    }
    // 26 秒：用原版自己的菜单视图类把面板建出来（原版引擎不建，我们就自己建）。
    if (g_found && aq_ballBuilt && !aq_menuTried && aq_now() >= 26.0) {
        aq_menuTried = YES;
        aq_add(@"[菜单] 26 秒：在原版菜单视图类上自建面板");
        aq_build_menu();
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
    // 伪造激活之后再看一次状态，确认原版到底把什么写进了状态结构。
    if (g_found && !g_gate12 && aq_now() >= 12.0) {
        g_gate12 = YES;
        aq_probe_gate(@"12秒");
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
