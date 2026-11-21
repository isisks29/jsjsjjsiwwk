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
//      和键盘窗口），20 秒再让原版引擎跑一次也还是没建。所以改用原版自己的类自己搭：
//        · 22 秒：用 _0xD4E9A3C7 在右上角造悬浮球，放进 _0x8C2F4D71 覆盖窗口；
//          窗口和球都用静态变量长期持有（上一版只放在局部变量里，8 秒后就被
//          系统回收了，30 秒快照里已经找不到）。容器用自带的穿透命中判定，
//          只有点中悬浮球才算命中，其余位置交还游戏；
//        · 等游戏加载安静后（35 秒起连续 4 秒没有网络动作，最晚 70 秒）用
//          _0x1E6B7A93 造菜单视图（Metal + ImGui），并给它两份配套视图
//          _0xB1D7F3A9 / _0xC8E2A541，直接显示出来。菜单和悬浮球共用同一份
//          配置结构（原版设计就是球改配置、菜单读配置）；
//        · 点悬浮球可以开/关菜单。全部构建必须在主线程（上一版在后台队列里
//          建窗口，系统直接拒绝）。
//        · 实测原版每画一帧都会把菜单画面重新藏起来（调用点固定在库内
//          0x913768），并把配置第 0 字节写回 0。这一版只拦下针对画面自身
//          的隐藏请求（窗口和游戏一律不碰），并在绘制前后原样打印配置
//          前 32 字节，据此判断哪些字节是原版自己在维护的状态；
//        · 同时直接调用原版悬浮球的点击处理 iconOnClick（反汇编确认它只读
//          这份共享配置、不碰其他界面），等于让原版自己「点一下球」；
//        · 还在菜单所在窗口里放了一个红色小方块，用来确认这个窗口到底
//          能不能显示（能看到方块 = 窗口正常，面板看不见就是绘制内容的问题）。
//
// 为什么不再替换卡密相关方法：
//   上一版替换了原版的卡密处理方法和钥匙串方法，结果弹窗刚出现进程就无声
//   结束、还没留下崩溃信号 —— 原版很可能在校验自己的方法实现。所以卡密相关
//   方法一条都不碰；第 13 条只挂三个纯界面类的初始化方法。
//   这条经验又验证了一次：最近一版在卡密类的两个方法上装「只记录、不改行为」
//   的观察，进程在加载界面一秒多就被无声结束，而这两个方法一次都没被调用过
//   —— 说明原版是静态比对方法实现地址（本文件开头的检查表里正好就有这两个
//   方法）。所以连「只记录」也不做，卡密类完全不碰。
//   现在唯一被换掉的新方法是绘制后端的方法（只读每帧顶点数），属于纯界面类，
//   和卡密校验无关。
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
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/vm_region.h>
#import <mach/thread_act.h>
#import <pthread.h>
#import <stdio.h>
#if defined(__arm64__)
#import <mach/arm/thread_status.h>
#endif
#import <libkern/OSCacheControl.h>
#import <dlfcn.h>
#import <stdint.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <malloc/malloc.h>
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
static void aq_dump_windows(NSString *tag);   // 前置声明：点完确定后要看窗口有没有变化
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
static double g_lastNetAt = 0;   // 最后一次看到网络动作的时间（用来判断游戏是否还在加载）
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

// iOS 的 pthread 接口里没有「直接取主线程 pthread」的现成函数，
// 所以主线程的 mach 端口要在主线程上取一次存下来，供后台取样时使用。
static mach_port_t g_mainMachThread = MACH_PORT_NULL;

// 主线程被卡住时，从旁边抓一下它到底停在哪条指令上；写进现场文件，下次启动能看到。
static void aq_snap_main_pc(char *out, size_t cap) {
    if (!out || cap == 0) return;
    out[0] = '\0';
#if defined(__arm64__)
    thread_t mt = g_mainMachThread;
    if (!mt || mt == MACH_PORT_NULL) return;
    if (thread_suspend(mt) != KERN_SUCCESS) return;
    arm_thread_state64_t st;
    mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(mt, ARM_THREAD_STATE64, (thread_state_t)&st, &cnt);
    if (kr == KERN_SUCCESS) {
        snprintf(out, cap, " 主线程停点 pc=0x%llX lr=0x%llX",
                 (unsigned long long)st.__pc, (unsigned long long)st.__lr);
    }
    thread_resume(mt);
#endif
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

// 日志门控：逐帧、心跳、网络、窗口枚举这类高频噪声一律不再写日志，
// 每次运行只保留「取证大块」（深挖/哈希搜索/菜单映射汇总/关键状态）。
static BOOL aq_log_drop(NSString *s) {
    static const char *drop[] = {
        "发出 请求:", "网络返回:", "心跳:", "一次性摘要", "摘要输入",
        "摘要结果", "校验码计算", "定时窗口构成", "界面快照", "窗口构成",
        "发现面板", "触控统计", "[存活", "[绘制", "[三步", "[回调",
        "[启动子]", "[补齐]", "[原版帧", "[帧", "[画面", "[窗口",
        "[对象", "[方法", "[深诊", "[标志", "[菜单窗", "[界面",
        "[直画", "[数据段常量组", "[调度块", "[定时", "[配置",
        "[差分", "[状态", "[代码页", "[扫描", "[内存", "[分段",
        "[常量组", "[明文", "[暗桩", "[入口", "[描述符", "[整体",
        "[互换", "[触摸", "[重置", "[直写", "[通道", "[门户",
        "[按钮", "[表格", "[弹窗", "[剪贴板", "[扩散", "[签名",
        "[section", "[段]", "[菜单] 显示后", "[菜单] 隐藏调用累",
        "[菜单] 拦下原版隐藏动作", "[菜单] 复查",
        NULL
    };
    const char *c = [s UTF8String];
    if (!c) return NO;
    for (int i = 0; drop[i]; i++) {
        size_t n = strlen(drop[i]);
        if (strncmp(c, drop[i], n) == 0) return YES;
    }
    return NO;
}

static void aq_add(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (aq_log_drop(s)) return;   // 噪声直接丢弃：不进 NSLog、不进内存、不进剪贴板
    NSLog(@"[aqaw-fix] %@", s);
    double now = aq_now();
    @synchronized (g_text) {
        if (g_text) {
            [g_text appendFormat:@"[%.2fs] %@\n", now, s];
            // 只保留最近一段：日志越积越大越拖主线程（曾经整串写盘把主线程卡死）。
            if (g_text.length > 120000)
                [g_text deleteCharactersInRange:NSMakeRange(0, g_text.length - 80000)];
        }
    }
    // 落盘限速：以前每条都整串写盘，日志一大就会把主线程卡住（曾因此被系统结束）。
    static double lastDisk = -100.0;
    if (now - lastDisk >= 0.25) {
        lastDisk = now;
        @try {
            NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
            if (dir.length) {
                NSString *path = [dir stringByAppendingPathComponent:@"aqaw_fix_log.txt"];
                [aq_snapshot() writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
            }
        } @catch (NSException *e) {
        }
    }
    // 每两秒最多把最新记录自动放进剪贴板一次，闪退后也能直接粘贴出来。
    static double lastAuto = -100.0;
    if (now - lastAuto >= 2.0) {
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
    // 剪贴板写入是同步 IPC，整串日志又有几十万字符，太频繁会拖住主线程。
    static double lastCopy = -100.0;
    double now = aq_now();
    if (now - lastCopy < 1.5) return;
    lastCopy = now;
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

// ---- 代码页取证：签名库的代码页一旦被动过，系统会把整页收走 ------------------
// 两次闪退的出错地址都落在 0x908204，也就是 0x908000-0x90BFFF 这一页里。这里只用
// 系统接口查这一页的当前权限和目标指令，一个字节都不写，用来分辨究竟是「我们的改写
// 把它弄坏了」还是「别的东西先把它弄坏了」。
static void aq_prot_str(int prot, char *out, size_t cap) {
    if (!out || cap < 4) return;
    out[0] = (prot & VM_PROT_READ) ? 'r' : '-';
    out[1] = (prot & VM_PROT_WRITE) ? 'w' : '-';
    out[2] = (prot & VM_PROT_EXECUTE) ? 'x' : '-';
    out[3] = 0;
}

static BOOL aq_page_info(uintptr_t liboff, int *curProt, int *maxProt) {
    if (!g_slide) return NO;
    vm_address_t a = (vm_address_t)((uintptr_t)g_slide + liboff);
    a &= ~(vm_address_t)0x3FFF;
    vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &cnt, &obj);
    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
    if (kr != KERN_SUCCESS) return NO;
    if (curProt) *curProt = (int)info.protection;
    if (maxProt) *maxProt = (int)info.max_protection;
    return YES;
}

// 返回这一页是否可执行：1=可执行 0=不可执行 -1=查不到。
static int aq_code_page_exec_state(void) {
    int cur = -1, mx = -1;
    if (!aq_page_info(0x908000, &cur, &mx)) return -1;
    return (cur & VM_PROT_EXECUTE) ? 1 : 0;
}

static void aq_probe_code_page(const char *tag) {
    if (!g_found || !g_slide) return;
    int cur = -1, mx = -1;
    if (!aq_page_info(0x908000, &cur, &mx)) {
        aq_add(@"[代码页] %s 0x908000 查不到页信息", tag);
        return;
    }
    char c[4] = "---", m[4] = "---";
    aq_prot_str(cur, c, sizeof(c));
    aq_prot_str(mx, m, sizeof(m));
    if (cur & VM_PROT_READ) {
        const uint32_t *ins = (const uint32_t *)(uintptr_t)(g_slide + 0x909608);
        uint32_t w0 = ins[0], w1 = ins[1];
        NSString *state =
            (w0 == 0x529B98F4u && w1 == 0x72AB1774u) ? @"原版" :
            (w0 == 0x5285BEF4u && w1 == 0x72A251B4u) ? @"改写后" : @"其它";
        aq_add(@"[代码页] %s 0x908000 当前权限=%s 上限=%s 目标指令=%08X %08X（%@）",
               tag, c, m, w0, w1, state);
    } else {
        aq_add(@"[代码页] %s 0x908000 当前权限=%s 上限=%s（不可读，跳过指令核对）", tag, c, m);
    }
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
// 真正点一下结果提示上的按钮：系统弹窗的按钮就是普通控件，给它发一条「按下」
// 事件，效果和手指点一下一样。取不到按钮处理块时用这个，别直接关掉弹窗。
static BOOL aq_tap_alert_control(UIView *v, NSString *want) {
    if (!v || !want.length) return NO;
    if ([v isKindOfClass:[UIControl class]]) {
        NSString *t = nil;
        @try { t = [v valueForKey:@"currentTitle"]; } @catch (NSException *e) {}
        if (!t.length) t = v.accessibilityLabel;
        if ([t isKindOfClass:[NSString class]] && [t isEqualToString:want]) {
            [(UIControl *)v sendActionsForControlEvents:UIControlEventTouchUpInside];
            return YES;
        }
    }
    for (UIView *s in v.subviews) {
        if (aq_tap_alert_control(s, want)) return YES;
    }
    return NO;
}

// 系统把结果提示按钮的处理块放在私有字段里，「handler」这个名字取不到。
// 这里直接遍历按钮对象的字段，找到那个处理块并按原样执行一次。
// 这一步很关键：原版「授权成功」之后的面板初始化就挂在这个处理块里，
// 跳过它，后面建球、建面板这些步骤都不会发生。
static BOOL aq_invoke_alert_handler(UIAlertAction *act) {
    if (!act) {
        aq_add(@"[弹窗] 按钮对象为空，取不到它背后的处理");
        return NO;
    }
    BOOL ran = NO;
    Class c = [act class];
    int depth = 0;
    while (c && depth < 4 && !ran) {
        unsigned int n = 0;
        Ivar *ivs = class_copyIvarList(c, &n);
        NSMutableString *names = [NSMutableString string];
        for (unsigned int i = 0; ivs && i < n; i++) {
            const char *ty = ivar_getTypeEncoding(ivs[i]);
            const char *nm = ivar_getName(ivs[i]);
            [names appendFormat:@"%s(%s) ", nm ? nm : "?", ty ? ty : "?"];
            if (!ty || ty[0] != '@' || ty[1] != '?') continue;
            id blk = object_getIvar(act, ivs[i]);
            if (!blk) continue;
            aq_add(@"[弹窗] 找到按钮处理块（字段 %s），按原样执行", nm ? nm : "?");
            @try {
                ((void (^)(UIAlertAction *))blk)(act);
                ran = YES;
            } @catch (NSException *e) {
                aq_add(@"[弹窗] 执行按钮处理块异常: %@", e.reason ?: @"?");
            }
        }
        if (n > 0) aq_add(@"[弹窗] 按钮 %@ 的字段: %@", NSStringFromClass(c), names);
        if (ivs) free(ivs);
        c = class_getSuperclass(c);
        depth++;
    }
    return ran;
}

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
                        aq_add(@"[弹窗] 成功提示按钮数=%lu", (unsigned long)a.actions.count);
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
                        BOOL tapDone = NO;
                        id handler = nil;
                        @try { handler = [target valueForKey:@"handler"]; } @catch (NSException *e) {}
                        if (handler) {
                            aq_add(@"已自动点击成功提示的「%@」", target.title ?: @"?");
                            ((void (^)(UIAlertAction *))handler)(target);
                            tapDone = YES;
                        } else if (aq_invoke_alert_handler(target)) {
                            // 私有字段里的处理块已经按原样执行，等价于用户亲手点了这个按钮。
                            aq_add(@"已执行成功提示「%@」背后的处理", target.title ?: @"?");
                            tapDone = YES;
                        } else {
                            // 连处理块都找不到时，退回到真的点一下界面上的那个按钮。
                            NSString *want = target.title.length ? target.title : @"确定";
                            BOOL tapped = aq_tap_alert_control(a.view, want);
                            if (!tapped) tapped = aq_tap_alert_control(a.view, @"确定");
                            if (tapped) {
                                aq_add(@"已真实点击成功提示的「%@」", want);
                                tapDone = YES;
                            }
                        }
                        if (tapDone) {
                            // 点完之后原版如果会自己建球、建面板，2 秒内就能在窗口列表里看到。
                            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                                           dispatch_get_main_queue(), ^{
                                aq_dump_windows(@"点确定后");
                            });
                        } else {
                            [a dismissViewControllerAnimated:NO completion:nil];
                            aq_add(@"成功提示按钮点不到，已关闭");
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

// 只读导出：把运行时经摘要函数处理过的“中文串”尽量都抓下来（去重、限量）。
// 菜单功能名是运行时解密的，文件里搜不到明文；但它初始化时会把这些名字拿去算摘要，
// 这里把它们全量记录下来，用于还原真实的菜单结构。全程只读，不改任何行为。
static NSMutableSet *aq_menuStrSet = nil;
static int aq_menuStrCount = 0;
static int aq_mem_read(uintptr_t src, void *dst, size_t len);   // 前置声明（定义在下面）

// 全量菜单记录：每个菜单名只记一次（名字 + 摘要前 8 字节），初始化结束后一次性汇总，
// 不再逐个刷屏。表定位成功后汇总会把「名字 => 表内值」整体带出来。
#define AQ_MREC_CAP 400
#define AQ_MREC_NAMELEN 96
static char     g_mRecName[AQ_MREC_CAP][AQ_MREC_NAMELEN];
static uint32_t g_mRecH0[AQ_MREC_CAP];
static uint32_t g_mRecH1[AQ_MREC_CAP];
static int      g_mRecN = 0;
static int      g_lastNewIdx = -1;
static int      g_mSummaryDone = 0;
static int      g_forceSummary = 0;
static uintptr_t g_tableBase = 0;
static uint64_t  g_tableCount = 0;
static int       g_tableOk = 0;
static void aq_menu_summary(void);   // 前置声明（定义在深挖探针之后）
static void aq_final_report(void);   // 前置声明（定义在状态 dump 之后）

// 记录「菜单名被处理时，原版代码的调用位置」。菜单名是运行时解密的，文件里搜不到明文，
// 所以只能从运行现场倒推：同一个位置反复处理不同菜单名，就说明它是遍历菜单表的函数。
// 这里把该位置前后几条机器码一起带出来，之后只需要分析这一小段，不用翻整个库。
static void *aq_menuCaller[24];
static int   aq_menuCallerHit[24];
static int   aq_menuCallerN = 0;
static void aq_note_menu_caller(void *ra) {
    if (!g_slide || !ra) return;
    uintptr_t a = (uintptr_t)ra;
    if (a < (uintptr_t)g_slide + 0x4000 || a >= (uintptr_t)g_slide + 0x13E0000ULL) return;
    for (int i = 0; i < aq_menuCallerN; i++) {
        if (aq_menuCaller[i] == ra) { aq_menuCallerHit[i]++; return; }
    }
    if (aq_menuCallerN >= 24) return;
    int k = aq_menuCallerN++;
    aq_menuCaller[k] = ra;
    aq_menuCallerHit[k] = 1;
    uint32_t w[8];
    memset(w, 0, sizeof(w));
    BOOL ok = aq_mem_read(a - 24, w, sizeof(w)) ? YES : NO;
    aq_add(@"[菜单调用点#%d] 库内偏移=0x%lX 机器码%@ %08X %08X %08X %08X %08X %08X %08X %08X",
           k, (long)(a - (uintptr_t)g_slide), ok ? @"" : @"(读不到)",
           w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
}

// 直接读当前 x29（帧链头）。摘要钩子由原版代码 BL 进来，stub 只是 br 跳板不改 x29，
// 所以这里拿到的就是「调用我们的那个函数」的帧（或它上一层），用它就能读回原版函数里
// 保存的寄存器，从而拿到它正在遍历的数组基址与元素个数。全程只读。
static inline __attribute__((always_inline)) uintptr_t aq_read_x29(void) {
    uintptr_t v = 0;
#if defined(__aarch64__)
    __asm__ volatile("mov %0, x29" : "=r"(v));
#endif
    return v;
}

// 兜底定位：这张「摘要→值」表是运行时建在堆上的，静态文件里没有。既然第一项名字的
// 摘要前 16 字节是唯一的，就在可写内存里按块搜它；命中处就是表里的一项。全程只读，
// 放后台线程，限制总扫描量，不拖主线程。
static uint8_t g_menuKey[16];
static int g_menuKeyReady = 0;
static int g_hashScanStarted = 0;

static void aq_hash_scan_async(void) {
    if (g_hashScanStarted || !g_menuKeyReady) return;
    g_hashScanStarted = 1;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        // 把已经记录下来的多个菜单摘要都拿来搜，命中越多越容易确认表的位置。
        // 线程启动时先做一份快照（数组后续可能继续增长）。
        uint32_t h0[8], h1[8];
        int hn = 0;
        for (int i = 0; i < g_mRecN && hn < 8; i++) {
            if (!g_mRecH0[i] && !g_mRecH1[i]) continue;
            h0[hn] = g_mRecH0[i];
            h1[hn] = g_mRecH1[i];
            hn++;
        }
        if (hn == 0) {
            uint64_t a = 0;
            memcpy(&a, g_menuKey, 8);
            h0[0] = (uint32_t)(a & 0xFFFFFFFFu);
            h1[0] = (uint32_t)((a >> 32) & 0xFFFFFFFFu);
            hn = 1;
        }
        int found[8];
        memset(found, 0, sizeof(found));
        int nfound = 0;

        vm_address_t addr = 0;
        size_t scanned = 0;
        const size_t capBytes = (size_t)(3u << 30);
        while (scanned < capBytes && nfound < 1) {
            vm_size_t sz = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = MACH_PORT_NULL;
            kern_return_t kr = vm_region_64(mach_task_self(), &addr, &sz,
                                            VM_REGION_BASIC_INFO_64,
                                            (vm_region_info_t)&info, &cnt, &obj);
            if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
            if (kr != KERN_SUCCESS || sz == 0) break;
            BOOL writable = (info.protection & (VM_PROT_READ | VM_PROT_WRITE))
                          == (VM_PROT_READ | VM_PROT_WRITE);
            size_t off = 0;
            while (writable && off < sz && scanned < capBytes && nfound < 1) {
                size_t chunk = (sz - off) < (size_t)(4u << 20) ? (sz - off) : (size_t)(4u << 20);
                uint8_t *buf = (uint8_t *)malloc(chunk);
                if (!buf) break;
                vm_size_t out = 0;
                if (vm_read_overwrite(mach_task_self(), addr + off, chunk,
                                      (vm_address_t)buf, &out) == KERN_SUCCESS && out == chunk) {
                    for (size_t i = 0; i + 0x28 <= chunk; i += 4) {
                        uint32_t a = 0, b = 0;
                        memcpy(&a, buf + i, 4);
                        for (int j = 0; j < hn; j++) {
                            if (found[j] || a != h0[j]) continue;
                            memcpy(&b, buf + i + 4, 4);
                            if (b != h1[j]) continue;
                            found[j] = 1;
                            nfound++;
                            uintptr_t at = (uintptr_t)(addr + off + i);
                            uint64_t val = 0;
                            memcpy(&val, buf + i + 0x20, 8);
                            aq_add(@"[哈希搜索] key%d 命中=0x%lX 对齐: %%0x10=%llu %%0x28=%llu "
                                   @"本项值=0x%llX 前一项=%08X",
                                   j, (long)at,
                                   (unsigned long long)(at & 0xF),
                                   (unsigned long long)(at % 0x28),
                                   (unsigned long long)val,
                                   i >= 4 ? *(uint32_t *)(buf + i - 4) : 0);
                            // 命中点前后各 0xC0 字节，按 0x10 一行，直接看结构排布与步长。
                            size_t lo = (i >= 0xC0) ? i - 0xC0 : 0;
                            size_t hi = i + 0xC0;
                            if (hi > chunk) hi = chunk;
                            for (size_t r = lo; r + 16 <= hi; r += 0x10) {
                                uint32_t w0 = 0, w1 = 0, w2 = 0, w3 = 0;
                                memcpy(&w0, buf + r, 4);
                                memcpy(&w1, buf + r + 4, 4);
                                memcpy(&w2, buf + r + 8, 4);
                                memcpy(&w3, buf + r + 12, 4);
                                aq_add(@"[哈希周边] 0x%lX %08X %08X %08X %08X",
                                       (long)(addr + off + r), w0, w1, w2, w3);
                            }
                            break;
                        }
                    }
                    scanned += chunk;
                }
                free(buf);
                off += chunk;
                usleep(1500);   // 后台低优先级，主动让出 CPU，避免拖慢游戏
            }
            addr += sz;
            if (addr < 0x100000000ULL) {
                if (addr == 0) break;
            }
            if (sz > ((vm_size_t)1 << 40)) break;
        }
        aq_add(@"[哈希搜索] 结束 扫描=%luMB 命中=%d/%d", (unsigned long)(scanned >> 20), nfound, hn);
        aq_final_report();   // 搜索一结束就把完整报告一次性打出来，不用再等定时兜底
    });
}

// 深入取证：原版把每个菜单名交给摘要函数时，它正在按 0x28 步长遍历一个「摘要→值」表。
// 我们从调用帧里把表的基址(x20)和项数(x21)读出来，再用刚算好的摘要在前几项里比对，
// 一旦命中就把该项的值一并带出。拿到这张表，就能把 244 个菜单名和它们对应的真实键对上。
static void aq_menu_deep_probe(const void *data, uint32_t len,
                               const unsigned char *md, uintptr_t fp) {
    static int deep = 0;
    static uintptr_t lastAddr = 0;
    if (deep >= 6 || !data || !len) return;
    deep++;
    if (deep == 1 && md && !g_menuKeyReady) {
        memcpy(g_menuKey, md, 16);
        g_menuKeyReady = 1;
    }
    if (deep == 2) aq_hash_scan_async();
    NSString *s = [[NSString alloc] initWithBytes:data
                                           length:(len < 60 ? len : 60)
                                         encoding:NSUTF8StringEncoding];
    if (!s) s = [NSString stringWithFormat:@"<%u字节>", (unsigned)len];
    uintptr_t cur = (uintptr_t)data;
    aq_add(@"[深挖#%d] 名字=%@ 名字地址=0x%lX 长度=%u 与上次差=%ld",
           deep, s, (long)cur, (unsigned)len,
           lastAddr ? (long)(cur - lastAddr) : 0L);
    lastAddr = cur;

    uintptr_t chain = 0;
    if (!aq_mem_read(fp, &chain, sizeof(chain))) chain = 0;
    aq_add(@"[深挖#%d] x29=0x%lX [x29]=0x%lX", deep, (long)fp, (long)chain);

    uint32_t k0 = 0, k1 = 0;
    if (md) { memcpy(&k0, md, 4); memcpy(&k1, md + 4, 4); }

    // 沿帧链往上逐层读回被保存的寄存器。真正持有「摘要→值」表的函数，其某一层
    // 会把表的基址留在 x20 里；这里对每层都做一次校验：从候选基址起按 0x28 步长
    // 扫若干项，只要有一项前 8 字节等于当前名字的摘要，就锁定这张表。
    // 每层帧往下多读一段，一次读回，避免逐项 syscall；再用几组常见的
    // “callee-saved 寄存器保存偏移”逐一尝试：(x20, x21) 究竟落在哪一对上。
    static const int cand[][2] = {
        {0x30, 0x28}, {0x38, 0x30}, {0x10, 0x08}, {0x28, 0x20}, {0x18, 0x10}
    };
    uintptr_t f = fp;
    int maxLvl = (deep <= 2) ? 12 : 4;
    for (int lvl = 0; lvl < maxLvl && f; lvl++) {
        uint8_t fr[0x48];
        if (!aq_mem_read(f - 0x40, fr, sizeof(fr))) {
            if (deep <= 2) aq_add(@"[深挖#%d 层%d] fp=0x%lX 读不到", deep, lvl, (long)f);
            break;
        }
        uint64_t x19 = 0;
        memcpy(&x19, fr + 0x38, 8);
        uint64_t x20 = 0, x21 = 0;
        memcpy(&x20, fr + 0x30, 8);
        memcpy(&x21, fr + 0x28, 8);
        if (deep <= 2 && lvl < 12)
            aq_add(@"[深挖#%d 层%d] fp=0x%lX x19=0x%llX x20=0x%llX x21=0x%llX",
                   deep, lvl, (long)f, (unsigned long long)x19,
                   (unsigned long long)x20, (unsigned long long)x21);

        if (md) {
            for (int ci = 0; ci < 5 && !g_tableOk; ci++) {
                uint64_t cb = 0, cn = 0;
                memcpy(&cb, fr + cand[ci][0], 8);
                memcpy(&cn, fr + cand[ci][1], 8);
                if (cb <= 0x10000ULL || cb >= 0x8000000000ULL) continue;
                if (cn == 0 || cn > 1024) continue;
                uint64_t lim = cn;
                size_t bytes = (size_t)lim * 0x28;
                uint8_t *tbl = (uint8_t *)malloc(bytes);
                if (!tbl) continue;
                BOOL rok = aq_mem_read((uintptr_t)cb, tbl, bytes) ? YES : NO;
                if (rok) {
                    for (uint64_t k = 0; k < lim; k++) {
                        uint32_t a = 0, b = 0;
                        memcpy(&a, tbl + k * 0x28, 4);
                        memcpy(&b, tbl + k * 0x28 + 4, 4);
                        if (a != k0 || b != k1) continue;
                        uint64_t val = 0;
                        memcpy(&val, tbl + k * 0x28 + 0x20, 8);
                        g_tableBase = (uintptr_t)cb;
                        g_tableCount = lim;
                        g_tableOk = 1;
                        aq_add(@"[深挖#%d 层%d 偏移组%d] ★命中 表基址=0x%llX 项数=%llu 序号=%llu 本项值=0x%llX",
                               deep, lvl, ci, (unsigned long long)cb,
                               (unsigned long long)lim, (unsigned long long)k,
                               (unsigned long long)val);
                        break;
                    }
                }
                free(tbl);
            }
        }
        uintptr_t nxt = 0;
        if (!aq_mem_read(f, &nxt, sizeof(nxt))) break;
        f = nxt;
    }

    // 外层帧里那个稳定指针（x19）多半是名字表/配置容器，把头 8 个字带出来。
    if (deep == 1 && chain) {
        uint64_t ox19 = 0;
        if (aq_mem_read(chain - 0x08, &ox19, sizeof(ox19)) && ox19 > 0x10000ULL) {
            uint32_t w[16];
            memset(w, 0, sizeof(w));
            if (aq_mem_read((uintptr_t)ox19, w, sizeof(w)))
                aq_add(@"[深挖#1] 外层x19=0x%llX 头部: %08X %08X %08X %08X %08X %08X %08X %08X",
                       (unsigned long long)ox19, w[0], w[1], w[2], w[3],
                       w[4], w[5], w[6], w[7]);
        }
    }
}

// 一次性汇总：菜单初始化结束（或到点兜底）后，把 244 个名字与真实表值整体列出来，
// 只输出这一大块，不再逐条刷屏。
static void aq_menu_summary(void) {
    if (g_mSummaryDone) return;
    // 表还没锁定时，若后台搜索仍在跑，就先不输出，等它出结果或到点兜底，
    // 避免刚跑完一版却只拿到半截数据、还得再跑第二遍。
    if (!g_forceSummary && !g_tableOk && g_hashScanStarted) return;
    g_mSummaryDone = 1;
    int n = g_mRecN;
    aq_add(@"===== 菜单映射汇总 共%d项 =====", n);
    if (g_tableOk && g_tableBase) {
        uint64_t cnt = g_tableCount;
        if (cnt == 0 || cnt > 4096) cnt = 0;
        uint8_t *tbl = NULL;
        if (cnt) {
            size_t bytes = (size_t)cnt * 0x28;
            tbl = (uint8_t *)malloc(bytes);
            if (tbl && !aq_mem_read(g_tableBase, tbl, bytes)) { free(tbl); tbl = NULL; }
        }
        aq_add(@"[汇总] 表基址=0x%lX 项数=%llu 已读表=%@", (long)g_tableBase,
               (unsigned long long)cnt, tbl ? @"是" : @"否");
        for (int i = 0; i < n; i++) {
            uint64_t val = 0;
            int hit = -1;
            NSString *nm = [NSString stringWithUTF8String:g_mRecName[i]] ?: @"?";
            if (tbl) {
                for (uint64_t k = 0; k < cnt; k++) {
                    uint32_t a = 0, b = 0;
                    memcpy(&a, tbl + k * 0x28, 4);
                    memcpy(&b, tbl + k * 0x28 + 4, 4);
                    if (a == g_mRecH0[i] && b == g_mRecH1[i]) {
                        hit = (int)k;
                        memcpy(&val, tbl + k * 0x28 + 0x20, 8);
                        break;
                    }
                }
            }
            aq_add(@"[映射] %@ => 0x%llX 表序号=%d", nm,
                   (unsigned long long)val, hit);
        }
        if (tbl) {
            for (uint64_t k = 0; k < cnt && k < 300; k++) {
                uint32_t a = 0, b = 0;
                uint64_t v = 0;
                memcpy(&a, tbl + k * 0x28, 4);
                memcpy(&b, tbl + k * 0x28 + 4, 4);
                memcpy(&v, tbl + k * 0x28 + 0x20, 8);
                aq_add(@"[表项] %llu %08X%08X => 0x%llX",
                       (unsigned long long)k, a, b, (unsigned long long)v);
            }
            free(tbl);
        }
    } else {
        aq_add(@"[汇总] 未锁定表基址，输出名字+摘要前缀供离线比对");
        for (int i = 0; i < n; i++) {
            NSString *nm = [NSString stringWithUTF8String:g_mRecName[i]] ?: @"?";
            aq_add(@"[映射] %@ => H=%08X%08X", nm,
                   g_mRecH0[i], g_mRecH1[i]);
        }
    }
    aq_add(@"===== 汇总结束 =====");
    aq_copy();
}

static BOOL aq_maybe_menu_string(const void *data, uint32_t len) {
    if (!data || len < 3 || len > 200) return NO;
    char buf[208];
    uint32_t n = len < 200 ? len : 200;
    memcpy(buf, data, n);
    buf[n] = 0;
    NSString *s = [NSString stringWithUTF8String:buf];
    if (!s) return NO;
    NSInteger total = (NSInteger)s.length;
    if (total < 2 || total > 30) return NO;
    NSInteger cjk = 0;
    for (NSInteger i = 0; i < total; i++) {
        unichar c = [s characterAtIndex:i];
        if (c >= 0x4E00 && c <= 0x9FFF) cjk++;
    }
    if (cjk < 1) return NO;
    if (!aq_menuStrSet) aq_menuStrSet = [NSMutableSet new];
    if ([aq_menuStrSet containsObject:s]) return NO;
    [aq_menuStrSet addObject:s];
    if (aq_menuStrCount >= 400) return NO;
    aq_menuStrCount++;
    // 不再逐个打印，改为只记录；初始化结束后由汇总一次性输出。
    g_lastNewIdx = -1;
    if (g_mRecN < AQ_MREC_CAP) {
        int idx = g_mRecN++;
        const char *u = [s UTF8String];
        if (u) {
            strncpy(g_mRecName[idx], u, AQ_MREC_NAMELEN - 1);
            g_mRecName[idx][AQ_MREC_NAMELEN - 1] = 0;
        } else {
            g_mRecName[idx][0] = 0;
        }
        g_mRecH0[idx] = 0;
        g_mRecH1[idx] = 0;
        g_lastNewIdx = idx;
    }
    return YES;
}

static int aq_my_sha(const void *data, uint32_t len, unsigned char *md) {
    uintptr_t aq_fp = aq_read_x29();
    int r = aq_real_sha ? aq_real_sha(data, len, md) : 0;
    if (aq_maybe_menu_string(data, len)) {
        int idx = g_lastNewIdx;
        if (md && idx >= 0 && idx < g_mRecN) {
            memcpy(&g_mRecH0[idx], md, 4);
            memcpy(&g_mRecH1[idx], md + 4, 4);
        }
        aq_note_menu_caller(__builtin_return_address(0));
        aq_menu_deep_probe(data, len, md, aq_fp);
        // 真实菜单正好 244 项；到这里立即汇总一次，输出完整映射大块。
        if (g_mRecN >= 244) aq_menu_summary();
    }
    return r;
}

static int aq_my_sha_update(void *ctx, const void *data, uint32_t len) {
    uintptr_t aq_fp = aq_read_x29();
    if (aq_maybe_menu_string(data, len)) {
        aq_note_menu_caller(__builtin_return_address(0));
        aq_menu_deep_probe(data, len, NULL, aq_fp);
    }
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
static id aq_menuA = nil;   // 菜单的两个配套对象，自己长期持有，避免初始化函数返回后被释放
static id aq_menuC = nil;
static BOOL aq_menuBuilt = NO;
static BOOL aq_menuTried = NO;
static BOOL aq_menuAsked = NO;       // 用户点过悬浮球、要求显示面板
static BOOL aq_menuVisible = NO;
static BOOL aq_menuShown = NO;       // 菜单是否已经正式显示
static BOOL aq_menuWanted = NO;      // 用户希望菜单开着还是关着（点悬浮球切换，初始关）
static double aq_menuShowAt = 0;     // 计划显示的时间点（先避开游戏加载期）
static BOOL aq_origPanelFailed = NO;  // 原版菜单一次都没画出来过：之后点球直接用备用面板
static double aq_lastToggleAt = 0;   // 上一次开合的时间，用来挡住快速连点造成的抖动
static BOOL aq_ballDiag2 = NO;
static UIWindow *aq_lastSceneWin = nil;   // 最近一个由原版构造函数内部建出来的覆盖窗口
static uint8_t aq_panelCfg[0x200];   // 悬浮球和菜单视图共用同一份配置
static int g_detailOnce = 0;         // 只在收尾的“总览”块里打一次配置/字段，平时不刷屏

// 绘制与菜单回调的观察点：只记录，随后照原样调用。
static void (*aq_origDrawMTK)(id, SEL, id) = NULL;
static void (*aq_origDidMove)(id, SEL) = NULL;
static void (*aq_orig73)(id, SEL, id) = NULL;
static int aq_m73Calls = 0;
static IMP aq_origM0 = NULL, aq_origM1 = NULL, aq_origM2 = NULL, aq_origM3 = NULL, aq_origM4 = NULL;
static IMP aq_origN0 = NULL, aq_origN1 = NULL, aq_origN2 = NULL;
static int aq_drawCount = 0;
static int aq_didMoveCount = 0;
static int aq_mCalls[5] = {0, 0, 0, 0, 0};
static int aq_nCalls[3] = {0, 0, 0};
static BOOL aq_drawExcLogged = NO;
// 补帧诊断：补了多少次、最近一次的帧序号与画面顶点数。存活行会带上它们，
// 一眼就能分清「根本没补」「补了但画面没内容」两种情况。
static int aq_fixCount = 0, aq_fixFC = 0, aq_fixVtx = 0;

// 穿透容器：只有点中里面的悬浮球才算命中，其余位置一律交还给游戏。
// 这里手写矩形判断，不用系统的 CGRectContainsPoint —— 那个符号在 CoreGraphics 里，
// 不额外链接框架时会报未定义符号。
static BOOL aq_rect_contains(CGRect r, CGPoint p) {
    return p.x >= r.origin.x && p.x <= r.origin.x + r.size.width &&
           p.y >= r.origin.y && p.y <= r.origin.y + r.size.height;
}

static id aq_pass_hit(id self, SEL _cmd, CGPoint p, id event) {
    @try {
        UIView *me = (UIView *)self;
        if (me.hidden || me.alpha < 0.01 || !me.userInteractionEnabled) return nil;
        // 必须继续让子视图自己做命中测试（return [sub hitTest:...]），
        // 直接 return sub 会把子视图里真正要接事件的开关/按钮/滑条挡掉。
        NSArray *subs = me.subviews;
        for (NSInteger i = (NSInteger)subs.count - 1; i >= 0; i--) {
            UIView *sub = subs[(NSUInteger)i];
            if (sub.isHidden || sub.alpha < 0.01) continue;
            CGPoint q = [sub convertPoint:p fromView:me];
            if (aq_rect_contains(sub.bounds, q)) {
                id hit = [sub hitTest:q withEvent:event];
                if (hit) return hit;
            }
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

// 窗口自己的命中判定也必须「空白处放行」。
// UIWindow 默认在没有任何子控件命中的位置返回窗口自身，而窗口是铺满全屏的，
// 结果就是它把下面的游戏窗口整个挡住——面板一建出来，点哪里都没反应，收起面板后
// 窗口还在，照样按不到。这里动态派生一个子类，把 hitTest 换成只认子控件的版本。
static Class aq_pass_window_class(Class base) {
    if (!base) base = [UIWindow class];
    NSString *name = [NSString stringWithFormat:@"AqPassWin_%@", NSStringFromClass(base)];
    Class C = NSClassFromString(name);
    if (C) return C;
    C = objc_allocateClassPair(base, name.UTF8String, 0);
    if (!C) return base;   // 派生失败就退回原类，不影响运行
    class_addMethod(C, @selector(hitTest:withEvent:), (IMP)aq_pass_hit, "@40@0:8{CGPoint=dd}16@32");
    objc_registerClassPair(C);
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
// budget：整个窗口最多打印多少个节点。以前不限量，自建面板有近千个控件时，
// 一次转储就是近千条记录、每条都要整串复制并写盘，直接把主线程卡死。
static void aq_dump_view_tree(id obj, NSString *indent, int depth, int *budget) {
    UIView *v = (UIView *)obj;
    if (!v || depth > 4) return;
    if (budget && *budget <= 0) return;
    if (budget) (*budget)--;
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
            aq_dump_view_tree(s, [indent stringByAppendingString:@"  "], depth + 1, budget);
        }
    } @catch (NSException *e) {
    }
}

// 递归看树里有没有指定类名，用来判断一个窗口是不是原版真正挂画面的那个。
static BOOL aq_tree_has_class(UIView *v, NSString *cls, int depth) {
    if (!v || depth > 6) return NO;
    if ([NSStringFromClass([v class]) isEqualToString:cls]) return YES;
    for (UIView *s in v.subviews) {
        if (aq_tree_has_class(s, cls, depth + 1)) return YES;
    }
    return NO;
}

// 把所有高层级窗口逐个翻一遍。日志里一直有一个层级 2100、被藏起来的窗口，
// 它的根控制器是普通控制器却挂着子视图，很可能才是原版真正准备的面板容器。
// 这里只读它、不改它；只有当确认里面装着原版的绘制画面或输入层时，才把它显示出来。
static void aq_scan_extra_windows(void) {
    @try {
        NSArray *ws = [UIApplication sharedApplication].windows;
        aq_add(@"[窗口] 逐个检查，共 %lu 个", (unsigned long)ws.count);
        for (UIWindow *w in ws) {
            if (![w isKindOfClass:[UIWindow class]]) continue;
            CGFloat lvl = w.windowLevel;
            if (lvl < 1000) continue;
            // 自己建的窗口（覆盖窗口、悬浮球、六页面板、信息窗）一律不转储：
            // 面板里有近千个控件，逐条打印会把主线程拖死。
            BOOL mine = (w == aq_menuWindow) || (aq_ballWindow && w == aq_ballWindow) ||
                        (w == g_win) || (lvl >= 2800);
            UIView *root = w.rootViewController ? w.rootViewController.view : nil;
            aq_add(@"[窗口] 层级=%.0f 类=%@ 隐藏=%d 是自建=%d 根=%@ 子视图=%lu",
                   lvl, NSStringFromClass([w class]), (int)w.isHidden, (int)mine,
                   w.rootViewController ? NSStringFromClass([w.rootViewController class]) : @"无",
                   (unsigned long)w.subviews.count);
            if (mine) continue;
            if (root) {
                int budget = 60;
                aq_dump_view_tree(root, [NSString stringWithFormat:@"[窗%.0f]", lvl], 0, &budget);
                BOOL holds = aq_tree_has_class(root, @"_0x1E6B7A93", 0) ||
                             aq_tree_has_class(root, @"_0x37C8E2B6", 0);
                if (holds && w.isHidden) {
                    aq_add(@"[窗口] 这个窗口里装着原版的绘制画面或输入层，先让它显示");
                    w.hidden = NO;
                }
            }
        }
    } @catch (NSException *e) {
        aq_add(@"[窗口] 检查异常: %@", e.reason ?: @"?");
    }
}

static id aq_hook_win_init(id self, SEL _cmd, CGRect f) {
    id r = aq_origWinInit ? aq_origWinInit(self, _cmd, f) : nil;
    if (r) aq_lastSceneWin = (UIWindow *)r;
    aq_overlaySeen = YES;
    aq_overlayFrame = f;
    aq_overlaySeenAt = aq_now();
    aq_add(@"[面板] 覆盖窗口被创建 frame=(%.0f,%.0f,%.0f,%.0f) 结果=%p",
           f.origin.x, f.origin.y, f.size.width, f.size.height, r);
    return r;
}

static void aq_hook_win_hidden(id self, SEL _cmd, BOOL hidden) {
    // 原版每帧都会把菜单的承载窗口藏起来（它按状态机走「隐藏入口」）。
    // 用户已经点开菜单时，这里只拦「隐藏」、放行「显示」，让窗口保持可见；
    // 只影响这一个窗口的隐藏位，不碰游戏主窗口，也不碰其他窗口。
    if (self == aq_menuWindow && hidden && aq_menuWanted) {
        static int keepLogs = 0;
        if (keepLogs < 3) {
            keepLogs++;
            uintptr_t ra = (uintptr_t)__builtin_return_address(0);
            aq_add(@"[菜单] 拦下原版隐藏承载窗口 调用点=0x%llX（库内偏移 0x%llX）",
                   (unsigned long long)ra, (unsigned long long)(ra - (uintptr_t)g_slide));
        }
        return;
    }
    if (aq_origWinHidden) aq_origWinHidden(self, _cmd, hidden);
    if (aq_selfBuilding || self == aq_ballWindow) return;
    if (self == aq_menuWindow) {
        // 菜单自己的承载窗口被藏起来也要记下来：画面显示与否往往就取决于这一下。
        aq_add(@"[菜单] 承载窗口 hidden=%d 调用点=0x%llX（库内偏移 0x%llX）",
               (int)hidden,
               (unsigned long long)(uintptr_t)__builtin_return_address(0),
               (unsigned long long)((uintptr_t)__builtin_return_address(0) - (uintptr_t)g_slide));
        return;
    }
    aq_add(@"[面板] 覆盖窗口 hidden=%d（原版自己改的可见性）", (int)hidden);
}

// 原版每帧都会走到「藏画面」这一步，那一刻它的栈帧就在这个调用的正上方。
// 它把状态机的中间值都存在自己的帧里，这里只读几个格子：先确认读法没错
// （画面对象和选择器应当出现在固定位置），再把帧里的小整数列出来，
// 看看它到底带着什么状态走到这一步，而不是继续靠猜。
static void aq_probe_state_frame(void) {
    static int probes = 0;
    if (probes >= 2) return;
    probes++;
    void *mine = __builtin_frame_address(0);
    if (!mine) { aq_add(@"[帧] 取不到自己的帧"); return; }
    void *caller = *(void **)mine;   // 上一级栈帧（原版绘制函数）
    char *top = (char *)pthread_get_stackaddr_np(pthread_self());
    size_t sz = pthread_get_stacksize_np(pthread_self());
    char *lo = top - sz;
    if ((char *)mine < lo || (char *)mine >= top) { aq_add(@"[帧] 自己的帧不在栈内，跳过"); return; }
    if (!caller || (uintptr_t)caller % 16 || (char *)caller < lo || (char *)caller >= top) {
        aq_add(@"[帧] 上一级帧不在栈内（%p），跳过", caller);
        return;
    }
    aq_add(@"[帧] 栈=[%p,%p) 上一级帧=%p", lo, top, caller);
    void *s0 = *(void **)((char *)caller - 0x358);
    void *s1 = *(void **)((char *)caller - 0x530);
    aq_add(@"[帧] 固定槽 -0x358=%p -0x530=%p（应依次是画面对象与选择器）", s0, s1);
    for (int off = 0x100; off <= 0x500; off += 8) {
        void *p = *(void **)((char *)caller - off);
        uintptr_t u = (uintptr_t)p;
        if (u == 0 || u >= 0x100000) continue;
        aq_add(@"[帧] -0x%x = 0x%llx", off, (unsigned long long)u);
    }
}

// 菜单画面自己的隐藏位：记录「是谁藏的」（调用返回地址），并按用户意愿决定
// 是否放行。其他视图的隐藏一律原样继续，不受影响。
static AqSetHiddenFn aq_origViewHidden = NULL;
static int aq_viewHiddenLogs = 0;
static int aq_viewShowLogs = 0;
static int aq_hideCalls = 0;   // 原版每帧对菜单视图发起隐藏的累计次数（纯观测）

static void aq_hook_view_hidden(id self, SEL _cmd, BOOL hidden) {
    // 面板画面的可见性由这份处理代码按用户意愿决定：实测原版每画一帧都会把
    // 画面重新藏起来（调用点固定在库内 0x913768）。用户要让菜单开着时，
    // 这里只放行「显示」、把「隐藏」拦下；只影响这个画面自己的隐藏位，
    // 不碰窗口、不碰游戏。
    if (hidden && self == aq_menuView) {
        aq_hideCalls++;
        aq_probe_state_frame();
        if (aq_hideCalls % 600 == 0) {
            uintptr_t ra6 = (uintptr_t)__builtin_return_address(0);
            aq_add(@"[菜单] 隐藏调用累计=%d 调用点=0x%llX（库内偏移 0x%llX）",
                   aq_hideCalls, (unsigned long long)ra6,
                   (unsigned long long)(ra6 - (uintptr_t)g_slide));
        }
        if (aq_viewHiddenLogs < 3) {
            aq_viewHiddenLogs++;
            uintptr_t ra = (uintptr_t)__builtin_return_address(0);
            aq_add(@"[菜单] 拦下原版隐藏动作 调用点=0x%llX（库内偏移 0x%llX）",
                   (unsigned long long)ra,
                   (unsigned long long)(ra - (uintptr_t)g_slide));
        }
        if (!aq_menuWanted) {
            if (aq_origViewHidden) aq_origViewHidden(self, _cmd, YES);
        }
        return;
    }
    // 原版主动「显示」这个画面，说明它认为该打开——这是要抓的关键信号。
    // 自建流程里的显示不算，免得把自己设的当成原版行为。
    if (!hidden && self == aq_menuView && !aq_selfBuilding && aq_viewShowLogs < 3) {
        aq_viewShowLogs++;
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        aq_add(@"[菜单] 原版主动显示菜单 调用点=0x%llX（库内偏移 0x%llX）",
               (unsigned long long)ra, (unsigned long long)(ra - (uintptr_t)g_slide));
    }
    if (aq_origViewHidden) aq_origViewHidden(self, _cmd, hidden);
}

static void aq_dump_cfg_ptr(const char *tag, const void *ptr);   // 前置声明（定义在下面）

// 上一版只盯了 initWithFrame:，但新系统上建窗口走的是 initWithWindowScene:。
// 我们自己建的那个窗口就没触发 initWithFrame: —— 原版若走同一条路，之前也是看不到的。
static id aq_hook_win_scene_init(id self, SEL _cmd, id scene) {
    id r = aq_origWinSceneInit ? aq_origWinSceneInit(self, _cmd, scene) : nil;
    if (r) aq_lastSceneWin = (UIWindow *)r;
    if (aq_selfBuilding) return r;
    aq_overlaySeen = YES;
    aq_overlaySeenAt = aq_now();
    aq_add(@"[面板] 覆盖窗口被创建（按场景）结果=%p", r);
    return r;
}

static id aq_hook_ball_init(id self, SEL _cmd, CGRect f, void *cfg) {
    aq_add(@"[面板] 悬浮球正在创建 frame=(%.0f,%.0f,%.0f,%.0f) 配置=%p（%@）",
           f.origin.x, f.origin.y, f.size.width, f.size.height, cfg,
           aq_selfBuilding ? @"我方建立" : @"游戏发起");
    aq_dump_cfg_ptr("悬浮球创建", cfg);
    id r = aq_origBallInit ? aq_origBallInit(self, _cmd, f, cfg) : nil;
    aq_ballSeen = YES;
    aq_ballFrame = f;
    aq_add(@"[面板] 悬浮球创建完成 结果=%p", r);
    return r;
}

static id aq_hook_view_init(id self, SEL _cmd, CGRect f, void *cfg, id a, id b) {
    aq_add(@"[面板] 菜单视图正在创建 frame=(%.0f,%.0f,%.0f,%.0f) 配置=%p（%@）",
           f.origin.x, f.origin.y, f.size.width, f.size.height, cfg,
           aq_selfBuilding ? @"我方建立" : @"游戏发起");
    aq_dump_cfg_ptr("菜单视图创建", cfg);
    id r = aq_origViewInit ? aq_origViewInit(self, _cmd, f, cfg, a, b) : nil;
    aq_viewSeen = YES;
    aq_viewFrame = f;
    aq_add(@"[面板] 菜单视图创建完成 结果=%p", r);
    return r;
}

// 把配置前 32 字节原样打出来：原版每帧到底改哪几个字节，一看就知道。
static void aq_log_cfg(const char *tag, int frame) {
    if (!g_detailOnce) return;
    uint8_t *p = aq_panelCfg;
    aq_add(@"[总览配置] %s 帧=%d %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X"
           @" %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
           tag, frame,
           p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
           p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
           p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23],
           p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31]);
}

// 配置的 0x20~0x7F 段：点悬浮球前后各打一次，看开关是否写在更靠后的位置。
static void aq_log_cfg_wide(const char *tag, int frame) {
    if (!g_detailOnce) return;
    uint8_t *p = aq_panelCfg;
    for (int base = 0x20; base < 0x80; base += 16) {
        aq_add(@"[总览配置] %s 帧=%d +%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
               tag, frame, base,
               p[base + 0], p[base + 1], p[base + 2], p[base + 3],
               p[base + 4], p[base + 5], p[base + 6], p[base + 7],
               p[base + 8], p[base + 9], p[base + 10], p[base + 11],
               p[base + 12], p[base + 13], p[base + 14], p[base + 15]);
    }
}

// 只读：把任意配置指针前 96 字节打成「前16字节 + 非零位置」摘要。
// 用来分辨「游戏自己的真实配置」和「我们自己传进去的空缓冲」，不改任何行为。
static void aq_dump_cfg_ptr(const char *tag, const void *ptr) {
    NSString *tagS = tag ? [NSString stringWithUTF8String:tag] : @"?";
    if (!ptr) { aq_add(@"[数据源] %@ 指针为空", tagS); return; }
    uint8_t b[96];
    memset(b, 0, sizeof(b));
    if (!aq_mem_read((uintptr_t)ptr, b, sizeof(b))) {
        aq_add(@"[数据源] %@ 指针=%p 读不到", tagS, ptr);
        return;
    }
    NSMutableString *hex = [NSMutableString string];
    for (int i = 0; i < 16; i++) [hex appendFormat:@"%02X", b[i]];
    NSMutableString *nz = [NSMutableString string];
    int cnt = 0;
    for (int i = 0; i < 96; i++) {
        if (b[i]) { if (cnt < 20) [nz appendFormat:@"+%02X=%02X ", i, b[i]]; cnt++; }
    }
    aq_add(@"[数据源] %@ 指针=%p 前16=%@ 非零=%d%@",
           tagS, ptr, hex, cnt, cnt ? [NSString stringWithFormat:@" [%@]", nz] : @"");
}

// 只读：递归找界面里的面板实例（菜单视图/悬浮球/覆盖窗口），打印每个实例持有的
// 配置指针与配置内容，并标出哪个是我们自己建的、哪个是游戏自己建的。
static void aq_scan_walk(UIView *v, int depth, const char *tag, int *found) {
    if (!v || depth > 12 || *found >= 10) return;
    NSString *tagS = tag ? [NSString stringWithUTF8String:tag] : @"?";
    NSString *cn = NSStringFromClass([v class]);
    BOOL isMenu = [cn isEqualToString:@"_0x1E6B7A93"];
    BOOL isBall = [cn isEqualToString:@"_0xD4E9A3C7"];
    BOOL isWin  = [cn isEqualToString:@"_0x8C2F4D71"];
    if (isMenu || isBall || isWin) {
        (*found)++;
        void *cfg = NULL, *yi = NULL, *jia = NULL, *slots = NULL, *loader = NULL;
        if (isMenu) {
            char *base = (char *)(__bridge void *)v;
            loader = *(void **)(base + 0x10);
            cfg    = *(void **)(base + 0x18);
            yi     = *(void **)(base + 0x20);
            jia    = *(void **)(base + 0x28);
            slots  = *(void **)(base + 0x30);
        } else if (isBall) {
            cfg    = *(void **)((char *)(__bridge void *)v + 0x10);
        }
        NSString *who = @"?";
        if (isMenu) who = (v == (UIView *)aq_menuView) ? @"我方" : @"游戏";
        else if (isBall) who = (v == (UIView *)aq_ballView) ? @"我方" : @"游戏";
        aq_add(@"[实例扫描] %@ 命中 %@ @%p(%@) 隐藏=%d 尺寸=%.0fx%.0f 配置=%p 配置是我方=%@",
               tagS, cn, v, who, (int)v.hidden, v.frame.size.width, v.frame.size.height,
               cfg, (cfg == (void *)aq_panelCfg) ? @"是" : @"否");
        if (isMenu)
            aq_add(@"[实例扫描]   %@ 加载器=%p 甲=%p 乙=%p 名额=%p", tagS, loader, jia, yi, slots);
        if (cfg) aq_dump_cfg_ptr(tag, cfg);
    }
    for (UIView *s in v.subviews) aq_scan_walk(s, depth + 1, tag, found);
}

static void aq_scan_menu_instances(const char *tag) {
    @try {
        NSArray<UIWindow *> *wins = aq_all_windows();
        int found = 0;
        for (UIWindow *w in wins) aq_scan_walk(w, 0, tag, &found);
        aq_add(@"[实例扫描] %@ 扫描结束，共 %d 个面板实例",
               [NSString stringWithUTF8String:tag] ?: @"?", found);
    } @catch (NSException *e) {
        aq_add(@"[实例扫描] %@ 异常: %@",
               [NSString stringWithUTF8String:tag] ?: @"?", e.reason ?: @"?");
    }
}

// 只读：列出一个对象所属类的方法清单。参数个数为 3 的（self / 选择器 / 一个参数）
// 就是"设置口"——面板的开关十有八九就在这一组里。只打印名字和签名，不改任何东西。
static void aq_list_methods(id obj, const char *tag, int maxShow, BOOL onlySetter) {
    if (!g_detailOnce) return;
    if (!obj) { aq_add(@"[总览方法] %s 为空", tag); return; }
    unsigned int n = 0;
    Method *ms = class_copyMethodList([obj class], &n);
    if (!ms) { aq_add(@"[总览方法] %s 读不到方法列表", tag); return; }
    NSMutableString *s = [NSMutableString string];
    int shown = 0, setters = 0;
    for (unsigned int i = 0; i < n; i++) {
        const char *nm = sel_getName(method_getName(ms[i]));
        unsigned args = method_getNumberOfArguments(ms[i]);
        if (!nm) continue;
        if (args == 3) setters++;
        if (onlySetter && args != 3) continue;
        if (shown < maxShow) {
            const char *ty = method_getTypeEncoding(ms[i]);
            [s appendFormat:@"%s(%u)%s ", nm, args, ty ? ty : ""];
            shown++;
        }
    }
    free(ms);
    aq_add(@"[总览方法] %s 共 %u 个，单参数设置口 %d 个，显示前 %d: %@",
           tag, n, setters, shown, s);
}

// 只读查看菜单视图自己的字段：哪个字段在「关闭/打开」之间变化，就是原版真正
// 维护的开关。只打印名字和值，不改任何东西；读失败就跳过，不影响程序。
static void aq_dump_menu_ivars(const char *tag) {
    if (!g_detailOnce) return;
    id mv = aq_menuView;
    if (!mv) return;
    unsigned int n = 0;
    Ivar *ivs = class_copyIvarList([mv class], &n);
    if (!ivs) { aq_add(@"[总览字段] %s 字段: 读不到", tag); return; }
    NSMutableString *m = [NSMutableString string];
    for (unsigned int i = 0; i < n && i < 48; i++) {
        const char *nm = ivar_getName(ivs[i]) ? ivar_getName(ivs[i]) : "?";
        const char *ty = ivar_getTypeEncoding(ivs[i]) ? ivar_getTypeEncoding(ivs[i]) : "";
        ptrdiff_t off = ivar_getOffset(ivs[i]);
        @try {
            const char *base = (const char *)(__bridge void *)mv;
            if (ty[0] == '@') {
                // 对象字段用运行时自带的读取口，避免 ARC 下直接解引用指针。
                id v = object_getIvar(mv, ivs[i]);
                [m appendFormat:@"%s=%@ ", nm, v ? NSStringFromClass([v class]) : @"空"];
            } else {
                size_t sz = 8;
                if (ty[0] == 'c' || ty[0] == 'B') sz = 1;
                else if (ty[0] == 's') sz = 2;
                else if (ty[0] == 'i' || ty[0] == 'I' || ty[0] == 'f') sz = 4;
                unsigned long long v = 0;
                memcpy(&v, base + off, sz);
                [m appendFormat:@"%s=0x%llX ", nm, v];
            }
        } @catch (NSException *e) {
            [m appendFormat:@"%s=读失败 ", nm];
        }
    }
    free(ivs);
    aq_add(@"[总览字段] %s 字段: %@", tag, m);
    static int aq_menuMethodsOnce = 0;
    if (!aq_menuMethodsOnce) {
        aq_menuMethodsOnce = 1;
        aq_list_methods(mv, "menuView", 110, NO);
    }
}

// 菜单视图真正持有的配置指针。这个指针指向的才是原版面板读写的配置结构，
// 本地那份只是创建时的影子。整块读出来，并按已知结构体布局解释首段。
static void aq_dump_real_cfg(void) {
    if (!g_detailOnce) return;
    if (!aq_menuView) { aq_add(@"[总览配置真] 菜单视图为空"); return; }
    SEL sel = NSSelectorFromString(@"_0xE4C8719B");
    if (![aq_menuView respondsToSelector:sel]) {
        aq_add(@"[总览配置真] 取不到读取口");
        return;
    }
    void *p = NULL;
    @try {
        p = ((void *(*)(id, SEL))objc_msgSend)(aq_menuView, sel);
    } @catch (NSException *e) {
        aq_add(@"[总览配置真] 读取异常: %@", e.reason ?: @"?");
        return;
    }
    aq_add(@"[总览配置真] 指针=%p", p);
    if (!p) return;
    uint8_t buf[0x100];
    memset(buf, 0, sizeof(buf));
    if (!aq_mem_read((uintptr_t)p, buf, sizeof(buf))) {
        aq_add(@"[总览配置真] 读不到");
        return;
    }
    for (int r = 0; r < 0x100; r += 0x10) {
        aq_add(@"[总览配置真] +%02X %02X%02X%02X%02X %02X%02X%02X%02X "
               @"%02X%02X%02X%02X %02X%02X%02X%02X",
               r, buf[r], buf[r+1], buf[r+2], buf[r+3],
               buf[r+4], buf[r+5], buf[r+6], buf[r+7],
               buf[r+8], buf[r+9], buf[r+10], buf[r+11],
               buf[r+12], buf[r+13], buf[r+14], buf[r+15]);
    }
    int32_t i4 = 0, i8 = 0;
    memcpy(&i4, buf + 4, 4);
    memcpy(&i8, buf + 8, 4);
    aq_add(@"[总览配置真] 首段推断: b0=%u i4=%d i8=%d b12=%u b13=%u b14=%u",
           (unsigned)buf[0], i4, i8, (unsigned)buf[12],
           (unsigned)buf[13], (unsigned)buf[14]);
}

// 界面库把「这一帧要画什么」放在上下文里的一个数据块中。这个块的特征是
// 前面几个小整数依次是「列表数 / 索引数 / 顶点数」，随后是列表指针和显示尺寸。
// 这里只在上下文自身那一块内存里按这个特征找一遍：能找到有内容的，就说明画面
// 已经生成、只差提交；一个都找不到，就说明界面内容根本没构建出来。
static void aq_dump_drawdata_detail(const char *tag);   // 定义在下方，按正确布局定位画面数据

static void aq_scan_drawdata(void *ctx, const char *tag) {
    if (!ctx) { aq_add(@"[画面数据] %s 没有界面上下文", tag); return; }
    // 先把上下文开头 32 字节原样打出来。它是哪一类对象，看这段就能确认；
    // 如果这里根本不是界面库的上下文，后面按上下文找画面数据自然找不到。
    {
        const unsigned char *h = (const unsigned char *)ctx;
        aq_add(@"[画面数据] %s 上下文头部 %02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
               tag,
               h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
               h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15],
               h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23],
               h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);
    }
    // 旧版在这里按「+16 是列表指针」扫，布局错位，读出的全是假数据。
    // 改为按正确布局定位，并打印第一份列表内部的真实数量。
    aq_dump_drawdata_detail(tag);
}

// ---- 绘制通道自检：只读查询画面能不能拿到可绘制对象、渲染通道是否可用，
//      以及 ImGui 的上下文和后端对象有没有建起来。全部只读，不改任何状态。
//      目的：面板画面 60 帧在跑却什么也画不出来时，分清是「拿不到可绘制对象」
//      还是「绘制内容为空」。
static void aq_log_draw_channel(const char *tag, BOOL withDrawable) {
    id mv = aq_menuView;
    if (!mv) return;
    @try {
        __unsafe_unretained id dev = nil, layer = nil, drawable = nil, desc = nil, slots = nil;
        CGSize ds = {0, 0};
        BOOL paused = NO;
        long fps = 0;
        SEL s;
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"device"))])
            dev = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"layer"))])
            layer = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"drawableSize"))])
            ds = ((CGSize (*)(id, SEL))objc_msgSend)(mv, s);
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"isPaused"))])
            paused = ((BOOL (*)(id, SEL))objc_msgSend)(mv, s);
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"preferredFramesPerSecond"))])
            fps = (long)((NSInteger (*)(id, SEL))objc_msgSend)(mv, s);
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"renderSlots"))])
            slots = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        if (withDrawable) {
            if ([mv respondsToSelector:(s = NSSelectorFromString(@"currentDrawable"))])
                drawable = ((id (*)(id, SEL))objc_msgSend)(mv, s);
            if ([mv respondsToSelector:(s = NSSelectorFromString(@"currentRenderPassDescriptor"))])
                desc = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        }
        void *ctx = *(void **)(g_slide + 0x1644470);
        void *backend = *(void **)(g_slide + 0x1640D08);
        // 只读观察：界面库每帧都会刷新自己输入输出块里的显示尺寸和帧时长。
        // 输入输出块起点在上下文 +8；显示尺寸在块内 +8/+12（即上下文 +0x10/+0x14），
        // 帧时长在块内 +0x20 之后。旧代码从块起点直接取前三个 float，读到的是
        // 标志位与显示宽度，才误报「尺寸=0、时间步=2160」。
        float ioSizeX = 0, ioSizeY = 0, ioDt = 0;
        if (ctx && malloc_size(ctx) > 0x30) {
            ioSizeX = *(const float *)((const char *)ctx + 0x10);
            ioSizeY = *(const float *)((const char *)ctx + 0x14);
            ioDt    = *(const float *)((const char *)ctx + 0x28);
        }
        __unsafe_unretained id loader = nil;
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"loader"))])
            loader = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        aq_add(@"[绘制通道] %s 可绘制=%d 渲染通道=%d 设备=%@ 图层=%@ 画布=%.0fx%.0f 暂停=%d 帧率=%ld 槽位=%lu 界面上下文=%p 渲染器=%p 显示尺寸=%.0fx%.0f 时间步=%.4f 构建器=%@",
               tag,
               withDrawable ? (int)(drawable != nil) : -1,
               withDrawable ? (int)(desc != nil) : -1,
               dev ? NSStringFromClass([dev class]) : @"无",
               layer ? NSStringFromClass([layer class]) : @"无",
               ds.width, ds.height, (int)paused, fps,
               [slots isKindOfClass:[NSArray class]] ? (unsigned long)[slots count] : 0UL,
               ctx, backend,
               ioSizeX, ioSizeY, ioDt,
               loader ? NSStringFromClass([loader class]) : @"无");
        static int scanTimes = 0;
        if (ctx && scanTimes < 4) {
            scanTimes++;
            aq_scan_drawdata(ctx, tag);
        }
    } @catch (NSException *e) {
        aq_add(@"[绘制通道] 自检失败: %@", e.reason ?: @"?");
    }
}

// 如果界面上下文在、渲染器却缺席，说明原版初始化这段没跑到；这里按原版
// 自己的初始化函数补建一次（只用原版代码，不碰卡密，不改机器码）。
static void aq_try_backend_init(void) {
    static BOOL tried = NO;
    if (tried || !g_slide || !aq_menuView) return;
    tried = YES;
    void *ctx = *(void **)(g_slide + 0x1644470);
    void *backend = *(void **)(g_slide + 0x1640D08);
    if (backend) {
        aq_add(@"[渲染器] 渲染后端已在（%p），不用补建", backend);
        return;
    }
    if (!ctx) {
        aq_add(@"[渲染器] 界面上下文还不存在，先不补建渲染后端");
        return;
    }
    SEL s = NSSelectorFromString(@"device");
    if (![aq_menuView respondsToSelector:s]) return;
    __unsafe_unretained id dev = ((id (*)(id, SEL))objc_msgSend)(aq_menuView, s);
    if (!dev) {
        aq_add(@"[渲染器] 视图还没有设备，先不补建渲染后端");
        return;
    }
    BOOL ok = ((BOOL (*)(id))(g_slide + 0x83DEE8))(dev);
    backend = *(void **)(g_slide + 0x1640D08);
    aq_add(@"[渲染器] 已补建渲染后端 结果=%d 渲染后端=%p 设备=%@",
           (int)ok, backend, NSStringFromClass([dev class]));
}

// 菜单视图当前真实使用的配置指针（原版点悬浮球后会把它自己的真实配置换进来，
// 不再是初始化时我们传进去的那份空缓冲）。只读，不改任何东西。
static void *aq_menu_real_cfg(void) {
    if (!aq_menuView) return NULL;
    unsigned int n = 0;
    Ivar *ivs = class_copyIvarList([aq_menuView class], &n);
    void *p = NULL;
    const char *base = (const char *)(__bridge void *)aq_menuView;
    for (unsigned int i = 0; ivs && i < n; i++) {
        const char *nm = ivar_getName(ivs[i]);
        if (!nm || !strstr(nm, "E4C8719B")) continue;
        p = *(void **)(base + ivar_getOffset(ivs[i]));
        break;
    }
    if (ivs) free(ivs);
    return p;
}

// 运行时把菜单视图每个成员的真实指针、以及它指向对象的「第 0 字节」打出来。
// 静态分析追不到「绘制门控读的那份配置到底来自哪个成员」，就在这里用运行时数据
// 直接看：哪个成员对象的第 0 字节是 0，哪个就最可能是那个门控源头。只读，不写。
static void aq_snap_menu_ivars(int frameNo) {
    if (!aq_menuView) return;
    unsigned int cnt = 0;
    Ivar *ivs = class_copyIvarList([aq_menuView class], &cnt);
    if (!ivs) return;
    const char *base = (const char *)(__bridge void *)aq_menuView;
    int shown = 0;
    for (unsigned int i = 0; i < cnt && shown < 24; i++) {
        const char *nm = ivar_getName(ivs[i]);
        if (!nm) continue;
        long off = ivar_getOffset(ivs[i]);
        void *val = *(void **)(base + off);
        uint8_t b0 = 0;
        BOOL ok = aq_mem_read((uintptr_t)val, &b0, 1) ? YES : NO;
        aq_add(@"[快照] 第 %d 帧 成员 %s off=%ld 值=%p 首字节=%s%02X",
               frameNo, nm, off, val, ok ? "" : "不可读:", ok ? b0 : 0);
        shown++;
    }
    free(ivs);
    // 顺带把我们自己那份配置和「真实配置」的第 0 字节并排打一次，方便对照。
    void *real = aq_menu_real_cfg();
    uint8_t rb0 = 0;
    BOOL rok = (real && aq_mem_read((uintptr_t)real, &rb0, 1)) ? YES : NO;
    aq_add(@"[快照] 第 %d 帧 我方配置首字节=%02X 真实配置=%p 首字节=%s%02X",
           frameNo, aq_panelCfg[0], real, rok ? "" : "不可读:", rok ? rb0 : 0);
}

// 渲染链状态一页纸：界面上下文 / 渲染后端 / 设备 / 命令队列 / 加载器 / 名额。
// 前缀用「渲染器」，不会被日志过滤规则吃掉（旧前缀「绘制通道」一直在被丢弃）。
static void aq_log_renderer_state(const char *tag) {
    NSString *tagS = tag ? [NSString stringWithUTF8String:tag] : @"?";
    if (!g_slide) { aq_add(@"[渲染器] %@ 无镜像", tagS); return; }
    void *ctx = *(void **)(g_slide + 0x1644470);
    void *backend = *(void **)(g_slide + 0x1640D08);
    __unsafe_unretained id dev = nil, q = nil, ld = nil, sl = nil;
    @try {
        if (aq_menuView) {
            SEL s;
            if ([aq_menuView respondsToSelector:(s = NSSelectorFromString(@"device"))])
                dev = ((id (*)(id, SEL))objc_msgSend)(aq_menuView, s);
            if ([aq_menuView respondsToSelector:(s = NSSelectorFromString(@"commandQueue"))])
                q = ((id (*)(id, SEL))objc_msgSend)(aq_menuView, s);
            if ([aq_menuView respondsToSelector:(s = NSSelectorFromString(@"loader"))])
                ld = ((id (*)(id, SEL))objc_msgSend)(aq_menuView, s);
            if ([aq_menuView respondsToSelector:(s = NSSelectorFromString(@"renderSlots"))])
                sl = ((id (*)(id, SEL))objc_msgSend)(aq_menuView, s);
        }
    } @catch (NSException *e) {}
    aq_add(@"[渲染器] %@ 界面上下文=%p 渲染后端=%p 设备=%@ 命令队列=%@ 加载器=%@ 名额=%@",
           tagS, ctx, backend,
           dev ? NSStringFromClass([dev class]) : @"无",
           q ? NSStringFromClass([q class]) : @"无",
           ld ? NSStringFromClass([ld class]) : @"无",
           sl ? NSStringFromClass([sl class]) : @"无");
}

// 全窗口里找真正的 Metal 画布（MTKView）实例，报它的代理 / 暂停 / 按需重绘 / 画布尺寸，
// 并在「没挂代理 / 被暂停 / 退化成按需重绘」时做最小自愈——对应三种「后端在、却没人驱动」
// 的典型状态。只动这三处属性，不碰其他逻辑；任何一步异常都吞掉，不影响游戏。
static void aq_probe_mtk_walk(UIView *v, int depth, const char *tag, int *found) {
    if (!v || depth > 16 || *found >= 6) return;
    NSString *tagS = tag ? [NSString stringWithUTF8String:tag] : @"?";
    Class mtkCls = NSClassFromString(@"MTKView");
    BOOL isMTK = (mtkCls && [v isKindOfClass:mtkCls]);
    if (isMTK) {
        (*found)++;
        __unsafe_unretained id dg = nil;
        BOOL paused = NO, needs = NO;
        CGSize ds = {0, 0};
        @try {
            SEL s;
            if ([v respondsToSelector:(s = NSSelectorFromString(@"delegate"))])
                dg = ((id (*)(id, SEL))objc_msgSend)(v, s);
            if ([v respondsToSelector:(s = NSSelectorFromString(@"isPaused"))])
                paused = ((BOOL (*)(id, SEL))objc_msgSend)(v, s);
            if ([v respondsToSelector:(s = NSSelectorFromString(@"enableSetNeedsDisplay"))])
                needs = ((BOOL (*)(id, SEL))objc_msgSend)(v, s);
            if ([v respondsToSelector:(s = NSSelectorFromString(@"drawableSize"))])
                ds = ((CGSize (*)(id, SEL))objc_msgSend)(v, s);
        } @catch (NSException *e) {}
        aq_add(@"[渲染器] %@ 画布 %@ @%p 隐藏=%d 窗口隐藏=%d 帧=%.0fx%.0f 画布=%.0fx%.0f 暂停=%d 按需=%d 代理=%@",
               tagS, NSStringFromClass([v class]), (__bridge void *)v, (int)v.hidden,
               v.window ? (int)v.window.hidden : -1,
               v.frame.size.width, v.frame.size.height, ds.width, ds.height,
               (int)paused, (int)needs,
               dg ? NSStringFromClass([dg class]) : @"无");
        @try {
            SEL sp = NSSelectorFromString(@"setPaused:");
            if (paused && [v respondsToSelector:sp])
                ((void (*)(id, SEL, BOOL))objc_msgSend)(v, sp, NO);
            SEL sn = NSSelectorFromString(@"setEnableSetNeedsDisplay:");
            if (needs && [v respondsToSelector:sn])
                ((void (*)(id, SEL, BOOL))objc_msgSend)(v, sn, NO);
            if (!dg && aq_menuView &&
                [aq_menuView respondsToSelector:NSSelectorFromString(@"drawInMTKView:")]) {
                SEL sd = NSSelectorFromString(@"setDelegate:");
                if ([v respondsToSelector:sd]) {
                    ((void (*)(id, SEL, id))objc_msgSend)(v, sd, aq_menuView);
                    aq_add(@"[渲染器] %@ 画布原本没代理，已把菜单视图挂上", tagS);
                }
            }
            SEL sdr = NSSelectorFromString(@"draw");
            if ([v respondsToSelector:sdr]) ((void (*)(id, SEL))objc_msgSend)(v, sdr);
        } @catch (NSException *e) {
            aq_add(@"[渲染器] %@ 画布自愈失败: %@", tagS, e.reason ?: @"?");
        }
    }
    for (UIView *sub in v.subviews) aq_probe_mtk_walk(sub, depth + 1, tag, found);
}

static void aq_probe_mtk_everywhere(const char *tag) {
    NSString *tagS = tag ? [NSString stringWithUTF8String:tag] : @"?";
    @try {
        int found = 0;
        for (UIWindow *w in aq_all_windows()) aq_probe_mtk_walk(w, 0, tag, &found);
        if (!found) aq_add(@"[渲染器] %@ 全窗口没找到 Metal 画布实例", tagS);
    } @catch (NSException *e) {
        aq_add(@"[渲染器] 画布扫描异常: %@", e.reason ?: @"?");
    }
}

// 面板状态单例只看不改。早期这里试过把它的数值开关全部拨到开启，结果第 40 帧
// 之后主线程卡死被系统结束——那属于「卡密之外」的写入，已整体移除。

static void aq_dump_state_singleton(const char *tag) {
    if (!g_detailOnce) return;
    Class S = NSClassFromString(@"_0xA7F3B2E9");
    if (!S) { aq_add(@"[总览状态] 面板状态类不在（%s）", tag); return; }
    SEL si = NSSelectorFromString(@"sharedInstance");
    if (![S respondsToSelector:si]) { aq_add(@"[总览状态] 没有共享入口（%s）", tag); return; }
    id obj = ((id (*)(id, SEL))objc_msgSend)(S, si);
    if (!obj) { aq_add(@"[总览状态] 共享实例为空（%s）", tag); return; }
    unsigned int n = 0;
    Method *ms = class_copyMethodList([obj class], &n);
    if (!ms) { aq_add(@"[总览状态] 读不到方法列表（%s）", tag); return; }
    NSMutableString *s = [NSMutableString string];
    for (unsigned int i = 0; i < n; i++) {
        const char *nm = sel_getName(method_getName(ms[i]));
        if (!nm || nm[0] != 'v') continue;                 // 这个库的读取方法都以 v 开头
        if (method_getNumberOfArguments(ms[i]) != 2) continue;
        const char *ty = method_getTypeEncoding(ms[i]);
        if (!ty) continue;
        @try {
            if (ty[0] == 'B') {
                BOOL v = ((BOOL (*)(id, SEL))objc_msgSend)(obj, method_getName(ms[i]));
                [s appendFormat:@"%s=%d ", nm, (int)v];
            } else if (ty[0] == 'd') {
                double v = ((double (*)(id, SEL))objc_msgSend)(obj, method_getName(ms[i]));
                [s appendFormat:@"%s=%.3f ", nm, v];
            } else if (ty[0] == 'q' || ty[0] == 'Q') {
                long long v = ((long long (*)(id, SEL))objc_msgSend)(obj, method_getName(ms[i]));
                [s appendFormat:@"%s=%lld ", nm, v];
            } else if (ty[0] == '@') {
                id v = ((id (*)(id, SEL))objc_msgSend)(obj, method_getName(ms[i]));
                [s appendFormat:@"%s=%@ ", nm, v ? NSStringFromClass([v class]) : @"空"];
            }
        } @catch (NSException *e) {
            [s appendFormat:@"%s=异常 ", nm];
        }
    }
    free(ms);
    aq_add(@"[总览状态] %s 面板状态: %@", tag, s);
    static int aq_stateMethodsOnce = 0;
    if (!aq_stateMethodsOnce) {
        aq_stateMethodsOnce = 1;
        aq_list_methods(obj, "stateSingleton", 400, NO);
    }

    // 自动配对：菜单名的摘要前 8 字节，很可能就是状态单例上读取口名里那串十六进制。
    // 逐个试几种命名（v + 小写/大写十六进制、无前缀），能响应的就把「中文名 → 读取口 → 当前值」
    // 直接对上。全程只读，不调用任何写入口。
    int matched = 0;
    for (int i = 0; i < g_mRecN; i++) {
        if (!g_mRecH0[i] && !g_mRecH1[i]) continue;
        char c1[40], c2[40], c3[40];
        snprintf(c1, sizeof(c1), "v%08x%08x", g_mRecH0[i], g_mRecH1[i]);
        snprintf(c2, sizeof(c2), "v%08X%08X", g_mRecH0[i], g_mRecH1[i]);
        snprintf(c3, sizeof(c3), "%08x%08x", g_mRecH0[i], g_mRecH1[i]);
        SEL cand = NULL;
        if ([obj respondsToSelector:sel_registerName(c1)]) cand = sel_registerName(c1);
        else if ([obj respondsToSelector:sel_registerName(c2)]) cand = sel_registerName(c2);
        else if ([obj respondsToSelector:sel_registerName(c3)]) cand = sel_registerName(c3);
        if (!cand) continue;
        matched++;
        Method m = class_getInstanceMethod([obj class], cand);
        const char *ty = m ? method_getTypeEncoding(m) : NULL;
        NSString *nm = [NSString stringWithUTF8String:g_mRecName[i]] ?: @"?";
        @try {
            if (ty && ty[0] == 'B') {
                BOOL v = ((BOOL (*)(id, SEL))objc_msgSend)(obj, cand);
                aq_add(@"[名字对应] %@ => %s (bool) 当前=%d",
                       nm, sel_getName(cand), (int)v);
            } else if (ty && ty[0] == 'd') {
                double v = ((double (*)(id, SEL))objc_msgSend)(obj, cand);
                aq_add(@"[名字对应] %@ => %s (double) 当前=%.3f",
                       nm, sel_getName(cand), v);
            } else if (ty && (ty[0] == 'q' || ty[0] == 'Q' || ty[0] == 'i' || ty[0] == 'I')) {
                long long v = ((long long (*)(id, SEL))objc_msgSend)(obj, cand);
                aq_add(@"[名字对应] %@ => %s (int) 当前=%lld",
                       nm, sel_getName(cand), v);
            } else {
                aq_add(@"[名字对应] %@ => %s (%s)", nm, sel_getName(cand), ty ? ty : "?");
            }
        } @catch (NSException *e) {
            aq_add(@"[名字对应] %@ => %s 读取异常", nm, sel_getName(cand));
        }
    }
    aq_add(@"[名字对应] 自动配对命中 %d / %d 项", matched, g_mRecN);
}

// 一次收尾报告：菜单映射 + 视图字段 + 真实配置 + 状态单例。
// 后台搜索结束或定时兜底时调用，保证每次运行只多出这一大块，一次拿全。
static void aq_final_report(void) {
    static int done = 0;
    if (done) return;
    done = 1;
    g_forceSummary = 1;
    aq_menu_summary();
    g_detailOnce = 1;
    aq_dump_menu_ivars("overview");
    aq_dump_real_cfg();
    aq_dump_state_singleton("overview");
    g_detailOnce = 0;
    aq_copy();
}

// 只读：把一个对象身上的实例变量（对象型 + 小整数/布尔）按"名字=值"打出来，
// 用来判断"绘制对象"(_0xB1D7F3A9) 里那些控制是否构建的开关处于什么状态。
static void aq_dump_obj_ivars(id obj, const char *tag) {
    if (!obj) { aq_add(@"[对象] %s 为空", tag); return; }
    @try {
        unsigned int n = 0;
        Ivar *ivs = class_copyIvarList([obj class], &n);
        NSMutableString *s = [NSMutableString string];
        int shown = 0;
        for (unsigned int i = 0; ivs && i < n && shown < 48; i++) {
            const char *ty = ivar_getTypeEncoding(ivs[i]);
            const char *nm = ivar_getName(ivs[i]);
            if (!ty) continue;
            if (ty[0] == '@') {
                id o = object_getIvar(obj, ivs[i]);
                if (!o) continue;
                [s appendFormat:@"%s=%@ ", nm ? nm : "?", NSStringFromClass([o class])];
                shown++;
            } else if (ty[0]=='i' || ty[0]=='I' || ty[0]=='B' || ty[0]=='c' || ty[0]=='C') {
                ptrdiff_t off = ivar_getOffset(ivs[i]);
                int v;
                if (ty[0]=='i' || ty[0]=='I') v = *(int *)((char *)(__bridge void *)obj + off);
                else v = (int)*(unsigned char *)((char *)(__bridge void *)obj + off);
                [s appendFormat:@"%s=%d ", nm ? nm : "?", v];
                shown++;
            }
        }
        if (ivs) free(ivs);
        aq_add(@"[对象] %s %@ 字段: %@", tag, NSStringFromClass([obj class]),
               s.length ? s : @"（空）");
    } @catch (NSException *e) {
        aq_add(@"[对象] %s 读取异常: %@", tag, e.reason ?: @"?");
    }
}

// 一次性深诊断：把「原版每帧开画之前就返回」的常见原因一次看全。
// 只读；只有图层确实是空的（没有设备）时，才用视图自己的设备补上——不改别的东西。
//   ① 画布能不能拿到可绘制对象（currentDrawable，原版最容易在第一行判它就是 nil）
//   ② 图层的设备/容量/是否只做帧缓冲等关键属性
//   ③ 面板状态单例里到底哪些开关还关着
//   ④ 菜单视图身上挂了哪些对象（内容构建回调对象在不在）
static void aq_deep_render_probe(void) {
    id mv = aq_menuView;
    if (!mv) return;
    @try {
        SEL s;
        id layer = nil, vdev = nil, ldev = nil, dg = nil;
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"layer"))])
            layer = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"device"))])
            vdev = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"delegate"))])
            dg = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        id drawable = nil;
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"currentDrawable"))])
            drawable = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        long fbOnly = -1, maxCnt = -1, presents = -1, allowTimeout = -1;
        if (layer) {
            if ([layer respondsToSelector:(s = NSSelectorFromString(@"device"))])
                ldev = ((id (*)(id, SEL))objc_msgSend)(layer, s);
            if ([layer respondsToSelector:(s = NSSelectorFromString(@"framebufferOnly"))])
                fbOnly = (long)((BOOL (*)(id, SEL))objc_msgSend)(layer, s);
            if ([layer respondsToSelector:(s = NSSelectorFromString(@"maximumDrawableCount"))])
                maxCnt = (long)((NSInteger (*)(id, SEL))objc_msgSend)(layer, s);
            if ([layer respondsToSelector:(s = NSSelectorFromString(@"presentsWithTransaction"))])
                presents = (long)((BOOL (*)(id, SEL))objc_msgSend)(layer, s);
            if ([layer respondsToSelector:(s = NSSelectorFromString(@"allowsNextDrawableTimeout"))])
                allowTimeout = (long)((BOOL (*)(id, SEL))objc_msgSend)(layer, s);
        }
        aq_add(@"[深诊] 可绘制=%d 视图设备=%@ 图层设备=%@ 只帧缓冲=%ld 最大画布=%ld 随事务=%ld 允许超时=%ld 代理=%@",
               (int)(drawable != nil),
               vdev ? NSStringFromClass([vdev class]) : @"无",
               ldev ? NSStringFromClass([ldev class]) : @"无",
               fbOnly, maxCnt, presents, allowTimeout,
               dg ? NSStringFromClass([dg class]) : @"无");
        // 唯一的补正：图层缺设备时，用视图自己的设备补上（其它情况一律不动）。
        if (layer && !ldev && vdev) {
            @try {
                ((void (*)(id, SEL, id))objc_msgSend)(layer, NSSelectorFromString(@"setDevice:"), vdev);
                aq_add(@"[深诊] 图层原本没有设备，已用视图设备补上（%s）", object_getClassName(vdev));
            } @catch (NSException *e) {
                aq_add(@"[深诊] 补图层设备异常: %@", e.reason ?: @"?");
            }
        }
        aq_dump_state_singleton("深诊");
        // 菜单视图身上挂的对象（前 40 个实例变量里的对象类型），确认内容构建回调对象在不在。
        unsigned int n = 0;
        Ivar *ivs = class_copyIvarList([mv class], &n);
        NSMutableString *objs = [NSMutableString string];
        int shown = 0;
        for (unsigned int i = 0; ivs && i < n && shown < 40; i++) {
            const char *ty = ivar_getTypeEncoding(ivs[i]);
            if (!ty || ty[0] != '@') continue;
            const char *nm = ivar_getName(ivs[i]);
            id o = object_getIvar(mv, ivs[i]);
            if (!o) continue;
            [objs appendFormat:@"%s=%@ ", nm ? nm : "?", NSStringFromClass([o class])];
            shown++;
        }
        if (ivs) free(ivs);
        aq_add(@"[深诊] 菜单视图挂载对象: %@", objs.length ? objs : @"（无对象型实例变量）");
    } @catch (NSException *e) {
        aq_add(@"[深诊] 失败: %@", e.reason ?: @"?");
    }
}

// 每帧开工前，给原版画面自己的「渲染名额」补一个。
// 实测这个名额是一个信号量；原版每帧开工前要先拿到一个名额，拿不到就整帧跳过，
// 于是画面在刷新、却一帧内容都没提交。这里只补名额，不改变任何其他逻辑。
static void aq_feed_render_slots(id mv) {
    static int logged = 0;
    if (!mv) return;
    SEL s = NSSelectorFromString(@"renderSlots");
    if (![mv respondsToSelector:s]) return;
    id slots = ((id (*)(id, SEL))objc_msgSend)(mv, s);
    if (!slots) return;
    const char *cn = object_getClassName(slots);
    if (!cn || strcmp(cn, "OS_dispatch_semaphore") != 0) {
        if (logged < 3) {
            logged++;
            aq_add(@"[绘制通道] 名额对象是 %@，不是信号量", NSStringFromClass([slots class]));
        }
        return;
    }
    // 名额本身也是一个普通对象指针，ARC 下直接按类型转，不能再加 __bridge。
    dispatch_semaphore_t sem = (dispatch_semaphore_t)slots;
    long r = dispatch_semaphore_signal(sem);
    if (logged < 3) {
        logged++;
        aq_add(@"[绘制通道] 已给渲染名额补 1 个（信号量返回 %ld）", r);
    }
}

// ---- 面板绘制/回调观察：原样执行，只记录前几帧和异常 ---------------------
// 闪退后日志停在哪一帧、哪一次回调，下一版就能直接看出问题在绘制还是在别处。
// 从对象的字段里按类名片段找它挂着的那个渲染对象实例。
static id aq_find_ivar_obj(id owner, const char *suffix) {
    if (!owner) return nil;
    unsigned int n = 0;
    Ivar *ivs = class_copyIvarList([owner class], &n);
    id found = nil;
    for (unsigned int i = 0; ivs && i < n; i++) {
        const char *nm = ivar_getName(ivs[i]);
        if (!nm || !strstr(nm, suffix)) continue;
        found = object_getIvar(owner, ivs[i]);
        break;
    }
    if (ivs) free(ivs);
    return found;
}

// 一次性：把三个从没查过的对象翻出来——覆盖窗口的根控制器、菜单视图上挂的
// 另一个回调对象、以及同一窗口里那个自带输入框的视图。原版到底在哪儿维护
// 「面板该不该显示」，最可能就藏在这些对象的字段里。只读，不改任何东西。
static void aq_dump_unknowns_once(void) {
    static int done = 0;
    if (done) return;
    done = 1;
    @try {
        id rootVC = aq_menuWindow ? (id)aq_menuWindow.rootViewController : nil;
        if (rootVC) {
            aq_list_methods(rootVC, "窗口根控制器", 90, NO);
            aq_dump_obj_ivars(rootVC, "窗口根控制器");
            SEL sv = NSSelectorFromString(@"view");
            if ([rootVC respondsToSelector:sv]) {
                id rv = ((id (*)(id, SEL))objc_msgSend)(rootVC, sv);
                if (rv) aq_dump_obj_ivars(rv, "根控制器视图");
            }
        } else {
            aq_add(@"[未知] 菜单窗口没有根控制器");
        }
    } @catch (NSException *e) { aq_add(@"[未知] 根控制器读取异常: %@", e.reason ?: @"?"); }
    @try {
        id cb = aq_find_ivar_obj(aq_menuView, "C8E2A541");
        if (cb) {
            aq_list_methods(cb, "回调对象乙", 90, NO);
            aq_dump_obj_ivars(cb, "回调对象乙");
        } else {
            aq_add(@"[未知] 菜单视图上没挂回调对象乙");
        }
    } @catch (NSException *e) { aq_add(@"[未知] 回调对象乙读取异常: %@", e.reason ?: @"?"); }
    @try {
        __block id found = nil;
        __block void (^walk)(id, int) = nil;
        walk = ^(id v, int d) {
            if (!v || d > 4 || found) return;
            if (![v isKindOfClass:[UIView class]]) return;
            NSString *cn = NSStringFromClass([(id)v class]);
            if ([cn rangeOfString:@"37C8E2B6"].location != NSNotFound) { found = v; return; }
            for (UIView *c in ((UIView *)v).subviews) walk(c, d + 1);
        };
        if (aq_menuWindow.rootViewController.view) walk(aq_menuWindow.rootViewController.view, 0);
        if (found) {
            aq_list_methods(found, "输入框视图", 90, NO);
            aq_dump_obj_ivars(found, "输入框视图");
        } else {
            aq_add(@"[未知] 没找到输入框视图");
        }
    } @catch (NSException *e) { aq_add(@"[未知] 输入框视图读取异常: %@", e.reason ?: @"?"); }
}

// 画面数据(ImDrawData)实测布局（arm64）：
//   +0  bool 有效位           +4  int  列表数
//   +8  int  总索引数         +12 int  总顶点数
//   +16 ImVec2 显示原点       +24 ImVec2 显示尺寸
//   +32 ImVec2 像素缩放       +40 ImDrawList** 列表指针
// 以前把 +16(显示原点)当成列表指针校验，永远失败，于是长期误判「顶点为 0」；
// +0x3DD0 那一带读出来天文化数字，也是同一处错位。现在按正确布局在上下文里定位，
// 只读、不改任何内存。
static BOOL aq_is_heap_ptr(uintptr_t p) {
    return p >= 0x100000000ULL && p < 0x300000000ULL;
}

// 某地址上是否像一份自洽的画面数据；像则返回可信度分数（越大越像），否则 0。
static int aq_drawdata_score(const unsigned char *p, int *outValid, int *outLists,
                             int *outIdx, int *outVtx) {
    uint8_t valid = p[0];
    if (valid > 1) return 0;
    int lists = *(const int *)(p + 4);
    int idx   = *(const int *)(p + 8);
    int vtx   = *(const int *)(p + 12);
    if (lists < 0 || lists > 64) return 0;
    if (idx < 0 || idx > 20000000) return 0;
    if (vtx < 0 || vtx > 20000000) return 0;
    float dx = *(const float *)(p + 24);
    float dy = *(const float *)(p + 28);
    float fx = *(const float *)(p + 32);
    float fy = *(const float *)(p + 36);
    if (!(dx >= 0.0f && dx < 20000.0f)) return 0;
    if (!(dy >= 0.0f && dy < 20000.0f)) return 0;
    if (!(fx >= 0.0f && fx < 8.0f)) return 0;
    if (!(fy >= 0.0f && fy < 8.0f)) return 0;
    uintptr_t clp = (uintptr_t)*(const void *const *)(p + 40);
    if (!aq_is_heap_ptr(clp)) return 0;
    if (outValid) *outValid = valid;
    if (outLists) *outLists = lists;
    if (outIdx)   *outIdx = idx;
    if (outVtx)   *outVtx = vtx;
    int score = 1;
    if (valid) score += 2;
    if (lists > 0) score += 1;
    if (vtx > 0) score += 4;
    if (idx > 0) score += 4;
    return score;
}

// 在一段内存里找最像画面数据的位置，返回相对偏移（找不到 -1），并回填字段与分数。
static long aq_scan_block(const unsigned char *base, size_t size,
                          int *oScore, int *oValid, int *oLists, int *oIdx, int *oVtx) {
    long bestOff = -1;
    int bestScore = 0, bV = 0, bL = 0, bI = 0, bX = 0;
    for (size_t o = 0; o + 48 <= size; o += 4) {
        const unsigned char *p = base + o;
        int v = 0, l = 0, i2 = 0, x2 = 0;
        int sc = aq_drawdata_score(p, &v, &l, &i2, &x2);
        if (sc > bestScore) {
            bestScore = sc; bestOff = (long)o;
            bV = v; bL = l; bI = i2; bX = x2;
        }
    }
    if (bestOff < 0) return -1;
    if (oScore) *oScore = bestScore;
    if (oValid) *oValid = bV;
    if (oLists) *oLists = bL;
    if (oIdx)   *oIdx = bI;
    if (oVtx)   *oVtx = bX;
    return bestOff;
}

// 定位真正的「这一帧要画什么」，返回它的绝对地址（找不到 NULL）。
// 两处都找并取更像的那份：
//   ① 上下文自身内存里（主画面数据）；
//   ② 视口对象里——反汇编确认收尾函数把有效位写到「视口对象+0x48」、顶点数累加到「+0x54」，
//      而视口对象挂在「上下文+0x4030」的数组里（计数在「上下文+0x4028」）。原版提交的
//      正是这份，所以必须连它一起扫。
// 视口对象里，列表指针数组可能在 +0x70 或 +0x80（引擎版本差异），两个都试：
// 取第一个「本身是堆指针、且前几项元素也都是堆指针」的当数组。
static uintptr_t aq_vp_list_array(const unsigned char *vp, int lists) {
    if (lists <= 0) return 0;
    const uintptr_t cands[2] = { (uintptr_t)*(const void *const *)(vp + 0x70),
                                 (uintptr_t)*(const void *const *)(vp + 0x80) };
    for (int c = 0; c < 2; c++) {
        uintptr_t arr = cands[c];
        if (!aq_is_heap_ptr(arr)) continue;
        int ok = 0, check = lists < 4 ? lists : 4;
        for (int k = 0; k < check; k++)
            if (aq_is_heap_ptr(((const uintptr_t *)arr)[k])) ok++;
        if (ok == check) return arr;
    }
    return 0;
}

// 视口对象 +0x48 是否像一份自洽画面数据：是则返回分数并回填字段，否则 -1。
// 反汇编确认收尾函数把有效位写到「视口+0x48」、列表数/+0x4C、索引/+0x50、顶点/+0x54。
static int aq_vp_score(const unsigned char *vp, int *oValid, int *oLists,
                       int *oIdx, int *oVtx, uintptr_t *oArr) {
    const unsigned char *b = vp + 0x48;
    uint8_t valid = b[0];
    if (valid > 1) return -1;
    int lists = *(const int *)(b + 4);
    int idx   = *(const int *)(b + 8);
    int vtx   = *(const int *)(b + 12);
    if (lists < 0 || lists > 64) return -1;
    if (idx < 0 || idx > 20000000) return -1;
    if (vtx < 0 || vtx > 20000000) return -1;
    uintptr_t arr = aq_vp_list_array(vp, lists);
    if (lists > 0 && !arr) return -1;   // 有列表数却找不到列表数组，判为不可信
    if (oValid) *oValid = valid;
    if (oLists) *oLists = lists;
    if (oIdx)   *oIdx = idx;
    if (oVtx)   *oVtx = vtx;
    if (oArr)   *oArr = arr;
    int score = 2;
    if (valid) score += 2;
    if (lists > 0) score += 2;
    if (vtx > 0) score += 4;
    if (idx > 0) score += 4;
    return score;
}

// 只读画面数据头部前 16 字节（两种布局在这段是一致的）：+4 列表数 / +8 索引 / +12 顶点。
// 返回列表数（读不出返回 -1）。
static int aq_dd_head(void *dd, int *oIdx, int *oVtx) {
    if (!dd) return -1;
    const unsigned char *p = (const unsigned char *)dd;
    int lists = *(const int *)(p + 4);
    if (lists < 0 || lists > 64) return -1;
    int idx = *(const int *)(p + 8);
    int vtx = *(const int *)(p + 12);
    if (idx < 0 || idx > 20000000) return -1;
    if (vtx < 0 || vtx > 20000000) return -1;
    if (oIdx) *oIdx = idx;
    if (oVtx) *oVtx = vtx;
    return lists;
}

static void *aq_find_drawdata(void *ctx, int *oValid, int *oLists, int *oIdx, int *oVtx) {
    if (!ctx) return NULL;
    // ① 视口对象优先：原版真正提交的就是「视口+0x48」这一份。
    size_t csize = malloc_size(ctx);
    if (csize >= 0x4038) {
        int cnt = *(const int *)((const char *)ctx + 0x4028);
        uintptr_t arr = (uintptr_t)*(const void *const *)((const char *)ctx + 0x4030);
        if (cnt >= 1 && cnt <= 8 && aq_is_heap_ptr(arr)) {
            for (int i = 0; i < cnt; i++) {
                uintptr_t vp = ((const uintptr_t *)arr)[i];
                if (!aq_is_heap_ptr(vp)) continue;
                int v = 0, l = 0, i2 = 0, x2 = 0; uintptr_t la = 0;
                int sc = aq_vp_score((const unsigned char *)vp, &v, &l, &i2, &x2, &la);
                if (sc <= 0) continue;
                if (oValid) *oValid = v;
                if (oLists) *oLists = l;
                if (oIdx)   *oIdx = i2;
                if (oVtx)   *oVtx = x2;
                return (void *)(vp + 0x48);
            }
        }
    }
    // ② 退路：在上下文自身内存里按标准布局扫一份。
    void *bestPtr = NULL;
    int bestScore = 0, bV = 0, bL = 0, bI = 0, bX = 0;
    if (csize >= 0x400) {
        if (csize > 0x9000) csize = 0x9000;
        int sc = 0, v = 0, l = 0, i2 = 0, x2 = 0;
        long off = aq_scan_block((const unsigned char *)ctx + 0x400, csize - 0x400,
                                 &sc, &v, &l, &i2, &x2);
        if (off >= 0 && sc > bestScore) {
            bestScore = sc; bestPtr = (void *)((char *)ctx + 0x400 + off);
            bV = v; bL = l; bI = i2; bX = x2;
        }
    }
    if (!bestPtr) return NULL;
    if (oValid) *oValid = bV;
    if (oLists) *oLists = bL;
    if (oIdx)   *oIdx = bI;
    if (oVtx)   *oVtx = bX;
    return bestPtr;
}

// 找到一次就记住地址，之后按固定位置直读，避免每帧全量扫描拖慢。
static void *aq_ddPtr = NULL;
static int aq_vtx_count(void) {
    if (!g_slide) return -1;
    void *ctx = *(void **)(g_slide + 0x1644470);
    if (!ctx) return -1;
    if (aq_ddPtr) {
        int i2 = 0, x2 = 0;
        if (aq_dd_head(aq_ddPtr, &i2, &x2) >= 0) return x2;
        aq_ddPtr = NULL;   // 结构变了，重新定位
    }
    int vtx = -1;
    void *p = aq_find_drawdata(ctx, NULL, NULL, NULL, &vtx);
    if (p) { aq_ddPtr = p; return vtx; }
    return -1;
}

// 把视口对象 +0x40~0xA0 的内存整段打出来（只读），既能看清 +0x48 起画面数据的真实字段，
// 也能确认列表数组到底在 +0x70 还是 +0x80。
static void aq_dump_viewport_raw(const char *tag, int idx, const unsigned char *vp) {
    NSString *tagS = tag ? ([NSString stringWithUTF8String:tag] ?: @"?") : @"?";
    aq_add(@"[原始] %@ 视口[%d]=%p", tagS, idx, (void *)vp);
    for (size_t o = 0x40; o + 16 <= 0xA0; o += 16) {
        uint32_t w0 = *(const uint32_t *)(vp + o), w1 = *(const uint32_t *)(vp + o + 4);
        uint32_t w2 = *(const uint32_t *)(vp + o + 8), w3 = *(const uint32_t *)(vp + o + 12);
        uintptr_t q0 = *(const uintptr_t *)(vp + o), q8 = *(const uintptr_t *)(vp + o + 8);
        aq_add(@"[原始]   +0x%03lX: %08X %08X %08X %08X  q0=%p q8=%p",
               (unsigned long)o, w0, w1, w2, w3, (void *)q0, (void *)q8);
    }
}

// 一次性把画面数据讲清楚：每个视口的原始内存、按 +0x48 解析出的有效位/列表/索引/顶点、
// 以及把列表数组里每份列表的 命令/索引/顶点 累加出来的真实总量。只读。
static void aq_dump_drawdata_detail(const char *tag) {
    if (!g_slide) return;
    void *ctx = *(void **)(g_slide + 0x1644470);
    if (!ctx) { aq_add(@"[画面数据2] %s 没有界面上下文", tag); return; }
    size_t cs = malloc_size(ctx);
    int vcnt = -1; uintptr_t varr = 0;
    if (cs >= 0x4038) {
        vcnt = *(const int *)((const char *)ctx + 0x4028);
        varr = (uintptr_t)*(const void *const *)((const char *)ctx + 0x4030);
    }
    aq_add(@"[画面数据2] %s 视口 数量=%d 数组=%p", tag, vcnt, (void *)varr);
    if (vcnt >= 1 && vcnt <= 8 && aq_is_heap_ptr(varr)) {
        for (int i = 0; i < vcnt && i < 4; i++) {
            uintptr_t vp = ((const uintptr_t *)varr)[i];
            if (!aq_is_heap_ptr(vp)) { aq_add(@"[画面数据2] %s 视口[%d] 指针无效 %p", tag, i, (void *)vp); continue; }
            aq_dump_viewport_raw(tag, i, (const unsigned char *)vp);
            int v = 0, l = 0, ii = 0, xx = 0; uintptr_t la = 0;
            int sc = aq_vp_score((const unsigned char *)vp, &v, &l, &ii, &xx, &la);
            if (sc <= 0) { aq_add(@"[画面数据2] %s 视口[%d] +0x48 不像画面数据", tag, i); continue; }
            aq_add(@"[画面数据2] %s 视口[%d] 画面 有效=%d 列表=%d 索引=%d 顶点=%d 数组=%p",
                   tag, i, v, l, ii, xx, (void *)la);
            if (la && l > 0) {
                int rv = 0, ri = 0, ct = 0;
                for (int k = 0; k < l; k++) {
                    uintptr_t L = ((const uintptr_t *)la)[k];
                    if (!aq_is_heap_ptr(L)) continue;
                    const unsigned char *q = (const unsigned char *)L;
                    // ImDrawList 内 命令/索引/顶点 三个动态数组，数量分别在 +8 /+0x18 /+0x28
                    ct += *(const int *)(q + 8);
                    ri += *(const int *)(q + 0x18);
                    rv += *(const int *)(q + 0x28);
                }
                aq_add(@"[画面数据2] %s 视口[%d] 列表内汇总 命令=%d 索引=%d 顶点=%d", tag, i, ct, ri, rv);
            }
        }
    }
    int v = 0, l = 0, i2 = 0, x2 = 0;
    void *dd = aq_find_drawdata(ctx, &v, &l, &i2, &x2);
    if (!dd) { aq_add(@"[画面数据2] %s 最终：没定位到画面数据", tag); return; }
    aq_add(@"[画面数据2] %s 最终 地址=%p 有效=%d 列表=%d 索引=%d 顶点=%d", tag, dd, v, l, i2, x2);
}

// 界面内容由「构建界面内容」这一步负责（0xDDB034），所有布局与控件调用都在它体内；
// 原版每帧走进「隐藏」分支，这一步被整段跳过，所以画面内容一直是空的。
//
// 2026-11 改成「启动子」：不再去求虚拟化的状态机开门（那条路一碰签名代码段就崩），
// 而是每帧按原版自己的顺序代它走三步：开帧 → 构建内容 → 收口生成画面数据。
// 这三步都是普通函数（不是虚拟化代码），帧序号与顶点数就是它们的验收指标：
// 开帧后帧序号必须 +1，收口后顶点数必须 > 0。
// 是否在前台。开帧/收尾会用到平台窗口结构，后台那套是废的；实测后台继续跑
// 会把主线程卡在错误里出不来，最后被系统按「退出超时」强杀（异常记录里就写着
// 后台退出 5 秒未响应）。所以后台一律不做这两步。
static BOOL aq_is_foreground(void) {
    Class appCls = NSClassFromString(@"UIApplication");
    if (!appCls) return YES;
    SEL sShared = NSSelectorFromString(@"sharedApplication");
    if (![appCls respondsToSelector:sShared]) return YES;
    id app = ((id (*)(id, SEL))objc_msgSend)((id)appCls, sShared);
    if (!app) return YES;
    SEL sState = NSSelectorFromString(@"applicationState");
    if (![app respondsToSelector:sState]) return YES;
    long st = ((long (*)(id, SEL))objc_msgSend)(app, sState);
    return st == 0;  // 0 = 前台活跃
}

// 注意：界面库在「从没开过帧」时两个计数分别是 0 和 -1，-1 是正常初值，
// 不能当异常。只有明显跑飞的值才判为读不到。
static int aq_frame_counters(int *ended) {
    if (!g_slide) return -1;
    void *ctx = *(void **)(g_slide + 0x1644470);
    if (!ctx) return -1;
    int fc = *(const int *)((const char *)ctx + 0x3da8);
    int fe = *(const int *)((const char *)ctx + 0x3dac);
    if (fc < 0 || fc > 200000000) return -1;
    if (fe < -1 || fe > 200000000) return -1;
    if (ended) *ended = fe;
    return fc;
}

static BOOL aq_openFramePresynced = NO;  // 首帧前的「收尾标记对齐」是否已做
static BOOL aq_openFrameDead = NO;       // 开帧入口出过问题，永久停手
static BOOL aq_skipEndLogged = NO;
static int  aq_openFrameStall = 0;       // 连续几次没能推进帧序号

static void aq_open_frame_once(int frameNo) {
    if (!g_slide || aq_openFrameDead) return;
    if (!aq_is_foreground()) return;  // 后台不碰开帧/收尾
    void *ctx = *(void **)(g_slide + 0x1644470);
    if (!ctx) return;
    int fe = -1;
    int fc = aq_frame_counters(&fe);
    if (fc < 0) {
        if (frameNo <= 3) aq_add(@"[启动子] 第 %d 帧读不到帧计数，跳过开帧", frameNo);
        return;
    }

    // 收尾段里有一条路没有判空：平台窗口结构为空、而计数又大于 1 时，它会直接
    // 去读空指针（实测异常地址 0x180 就出在这一段）。先把这两个值记下来。
    void *plat = *(void **)((char *)ctx + 0x3e28);
    int platCnt = *(const int *)((const char *)ctx + 0x3df8);

    // 关键修复：从没开过帧时两个计数是 0 / -1，开帧入口一看「不相等」，就会先去
    // 收尾一个根本不存在的上一帧。那次空收尾正是闪退的起点。第一次开帧前，先把
    // 「已收尾」标记对齐成当前帧号，让它跳过这段空收尾。
    if (!aq_openFramePresynced) {
        aq_openFramePresynced = YES;
        if (fc == 0 && fe == -1) {
            *(int *)((char *)ctx + 0x3dac) = 0;
            aq_add(@"[启动子] 首次开帧前对齐收尾标记 %d→0（跳过对空帧的收尾）", fe);
        } else {
            aq_add(@"[启动子] 首次开帧前状态 已结束=%d 帧序号=%d（未对齐）", fe, fc);
        }
        if (frameNo <= 3)
            aq_add(@"[启动子] 平台结构=%p 计数=%d", plat, platCnt);
    } else if (!plat && platCnt > 1) {
        // 同一段坏路在后续帧也可能踩到。平台结构为空且计数>1 时，把这次收尾让过去。
        *(int *)((char *)ctx + 0x3dac) = fc;
        if (!aq_skipEndLogged) {
            aq_skipEndLogged = YES;
            aq_add(@"[启动子] 平台结构为空且计数=%d，本次跳过收尾", platCnt);
        }
    }

    typedef void (*aq_newframe_fn)(void);
    // 0x102E5E4 和 0x10271E8 长得很像，但职责完全不同，之前一直调错了：
    //   0x10271E8 开头先给界面库挂的每帧回调发一次「帧开始」通知，末尾把帧序号 +1，
    //             这才是真正的「开始新的一帧」；
    //   0x102E5E4 只把已有窗口收进画面数据，帧序号由它调用时原地不动。
    // 一直调后者，所以帧序号永远 0、顶点永远 0。这里换成前者。
    aq_newframe_fn fn = (aq_newframe_fn)(uintptr_t)(g_slide + 0x10271E8);
    double t0 = aq_now();
    if (frameNo <= 3) aq_add(@"[启动子] 第 %d 帧 开始开帧 帧序号=%d 已结束=%d …", frameNo, fc, fe);
    @try {
        fn();
    } @catch (NSException *e) {
        aq_openFrameDead = YES;
        aq_add(@"[启动子] 第 %d 帧 开帧抛异常，已停手: %@", frameNo, e.reason ?: @"?");
        return;
    }
    int fe2 = -1;
    int fc2 = aq_frame_counters(&fe2);
    if (fc2 < 0) {
        aq_openFrameDead = YES;
        aq_add(@"[启动子] 第 %d 帧 开帧后读不到帧计数，已停手", frameNo);
        return;
    }
    if (frameNo <= 3 || frameNo % 300 == 0)
        aq_add(@"[启动子] 第 %d 帧 开帧完成 耗时=%.3f 秒 帧序号 %d→%d 已结束=%d",
               frameNo, aq_now() - t0, fc, fc2, fe2);

    // 连续多次开不出新帧，就别再对着一个坏状态反复调了。
    if (fc2 == fc) {
        aq_openFrameStall++;
        if (aq_openFrameStall >= 3) {
            aq_openFrameDead = YES;
            aq_add(@"[启动子] 连续 %d 次没能推进帧序号，已停止再开帧", aq_openFrameStall);
        }
    } else {
        aq_openFrameStall = 0;
    }
}

static BOOL aq_closeFrameDead = NO;

// 构建完内容后，替原版把这一帧收口，并把「这一帧要画什么」生成出来。
// 这一步是普通函数：开头给界面库挂的每帧回调发「帧收口」通知，然后把当前窗口
// 收进画面数据。它内部会先做一次「收尾上一帧」，而收尾段里有一条路没有判空：
// 平台窗口结构为空、计数又大于 1 时直接读空指针（异常地址 0x180）。遇到这种
// 情况就把「已收尾」标记对齐过去，让它跳过收尾、只生成画面数据。
static void aq_close_frame_once(int frameNo) {
    if (!g_slide || aq_closeFrameDead) return;
    if (!aq_is_foreground()) return;
    void *ctx = *(void **)(g_slide + 0x1644470);
    if (!ctx) return;
    int fe = -1;
    int fc = aq_frame_counters(&fe);
    if (fc < 0) return;
    if (fe == fc) return;  // 这一帧已经收过尾，不重复
    void *plat = *(void **)((char *)ctx + 0x3e28);
    int platCnt = *(const int *)((const char *)ctx + 0x3df8);
    if (!plat && platCnt > 1) {
        *(int *)((char *)ctx + 0x3dac) = fc;
        if (!aq_skipEndLogged) {
            aq_skipEndLogged = YES;
            aq_add(@"[启动子] 平台结构为空且计数=%d，跳过收尾直接生成画面", platCnt);
        }
    }
    typedef void (*aq_render_fn)(void);
    aq_render_fn fn = (aq_render_fn)(uintptr_t)(g_slide + 0x102E5E4);
    double t0 = aq_now();
    @try {
        fn();
    } @catch (NSException *e) {
        aq_closeFrameDead = YES;
        aq_add(@"[启动子] 第 %d 帧 收口抛异常，已停手: %@", frameNo, e.reason ?: @"?");
        return;
    }
    int fe2 = -1;
    int fc2 = aq_frame_counters(&fe2);
    if (frameNo <= 3 || frameNo % 300 == 0)
        aq_add(@"[启动子] 第 %d 帧 收口完成 耗时=%.3f 秒 帧序号=%d 已结束=%d",
               frameNo, aq_now() - t0, fc2, fe2);
}

// 把菜单画面设成透明覆盖层：清屏透明、视图与图层都不透明标记关掉。
// 这样画面只显示自己那份内容，不会再出现「红块刚出现就整屏黑、盖住游戏」。
// 只改这个菜单视图自己的显示属性，不碰游戏视图。
static BOOL aq_menuTransparentDone = NO;
static void aq_make_menu_transparent(void) {
    if (aq_menuTransparentDone || !aq_menuView) return;
    aq_menuTransparentDone = YES;
    id mv = aq_menuView;
    @try {
        SEL s;
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"setClearColor:"))]) {
            id clear = [UIColor clearColor];
            ((void (*)(id, SEL, id))objc_msgSend)(mv, s, clear);
        }
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"setOpaque:"))])
            ((void (*)(id, SEL, BOOL))objc_msgSend)(mv, s, NO);
        UIView *v = (UIView *)mv;
        v.backgroundColor = [UIColor clearColor];
        v.layer.opaque = NO;
        aq_add(@"[菜单] 已把画面设为透明覆盖（清屏透明，不遮挡游戏）");
    } @catch (NSException *e) {
        aq_add(@"[菜单] 透明化失败: %@", e.reason ?: @"?");
    }
}

// 直画：界面库每帧会生成一份画面数据，但原版的绘制流程在「提交到屏幕」之前就退出了，
// 这份数据从来没被送出去。这里用正确布局定位到真正的画面数据，再调用原版自己已经
// 暴露的公开接口替它走一遍标准提交：取可绘制对象 → 建命令缓冲 → 建渲染编码 → 交给
// 原版提交方法 → 结束编码 → 呈现。找到且有内容才提交，只提交一次；不改任何内存。
static BOOL aq_submitTried = NO;
static void aq_try_submit_frame(int frameNo) {
    if (aq_submitTried) return;
    if (!g_slide || !aq_menuView || !aq_is_foreground()) return;
    void *ctx = *(void **)(g_slide + 0x1644470);
    void *renderer = *(void **)(g_slide + 0x1640D08);
    if (!ctx || !renderer) return;
    int dv = 0, dl = 0, di = 0;
    void *dd = aq_find_drawdata(ctx, NULL, &dl, &di, &dv);
    if (!dd) {
        if (frameNo <= 4) aq_add(@"[直画] 还没定位到画面数据，等下一帧再试");
        return;
    }
    if (dv <= 0 && di <= 0) {
        if (frameNo <= 4 || frameNo % 120 == 0)
            aq_add(@"[直画] 画面数据仍为空（列表=%d 索引=%d 顶点=%d），暂不提交", dl, di, dv);
        return;
    }
    aq_submitTried = YES;   // 找到有内容的数据后只提交一次，避免反复撞坏状态
    aq_make_menu_transparent();
    @try {
        id mv = aq_menuView;
        SEL s;
        id drawable = nil, desc = nil, cq = nil, cb = nil, enc = nil;
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"currentDrawable"))])
            drawable = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"currentRenderPassDescriptor"))])
            desc = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        if ([mv respondsToSelector:(s = NSSelectorFromString(@"commandQueue"))])
            cq = ((id (*)(id, SEL))objc_msgSend)(mv, s);
        if (!drawable) { aq_add(@"[直画] 拿不到可绘制对象，本轮跳过"); return; }
        if (!desc)     { aq_add(@"[直画] 拿不到渲染通道描述，本轮跳过"); return; }
        if (!cq)       { aq_add(@"[直画] 拿不到命令队列，本轮跳过"); return; }
        SEL sCB = NSSelectorFromString(@"commandBuffer");
        if (![cq respondsToSelector:sCB]) { aq_add(@"[直画] 命令队列不支持建缓冲"); return; }
        cb = ((id (*)(id, SEL))objc_msgSend)(cq, sCB);
        if (!cb) { aq_add(@"[直画] 建命令缓冲失败"); return; }
        SEL sEnc = NSSelectorFromString(@"renderCommandEncoderWithDescriptor:");
        if (![cb respondsToSelector:sEnc]) { aq_add(@"[直画] 命令缓冲不支持渲染编码"); return; }
        enc = ((id (*)(id, SEL, id))objc_msgSend)(cb, sEnc, desc);
        if (!enc) { aq_add(@"[直画] 建渲染编码失败"); return; }
        SEL sDraw = NSSelectorFromString(@"renderDrawData:commandBuffer:commandEncoder:");
        id rendObj = (__bridge id)renderer;
        if (![rendObj respondsToSelector:sDraw]) { aq_add(@"[直画] 渲染器不支持提交"); return; }
        ((void (*)(id, SEL, void *, id, id))objc_msgSend)(rendObj, sDraw, dd, cb, enc);
        ((void (*)(id, SEL))objc_msgSend)(enc, NSSelectorFromString(@"endEncoding"));
        SEL sPres = NSSelectorFromString(@"presentDrawable:");
        if ([cb respondsToSelector:sPres])
            ((void (*)(id, SEL, id))objc_msgSend)(cb, sPres, drawable);
        ((void (*)(id, SEL))objc_msgSend)(cb, NSSelectorFromString(@"commit"));
        aq_add(@"[直画] 已用原版提交接口把这一帧送出去 画面数据=%p 索引=%d 顶点=%d t=%.2f",
               dd, di, dv, aq_now());
    } @catch (NSException *e) {
        aq_add(@"[直画] 提交异常，已停手: %@", e.reason ?: @"?");
    }
}

// ---- 只读枚举界面库窗口表：确认原版构建到底有没有“建/用”某个窗口 ----------
// 这是判断“原生面板能否复活”的关键：若 m1/m2/m3 真的发起过 Begin，窗口表里
// 就会出现对应窗口（即使它被判定为隐藏/折叠、Begin 返回 false）。全程只读，
// 用 vm_read_overwrite 读内存，坏指针只会返回失败，不会把进程带走。
static int aq_mem_read(uintptr_t src, void *dst, size_t len) {
    if (!src || !dst || !len) return 0;
    vm_size_t out = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)src,
                                         (vm_size_t)len, (vm_address_t)dst, &out);
    return (kr == KERN_SUCCESS && out == (vm_size_t)len);
}

static void aq_dump_imwin(const char *tag, int frameNo) {
    if (!g_slide) return;
    uintptr_t ctx = 0;
    if (!aq_mem_read((uintptr_t)g_slide + 0x1644470, &ctx, sizeof(ctx)) || !ctx) {
        aq_add(@"[窗口表] %s 帧%d：取不到上下文", tag, frameNo);
        return;
    }
    uintptr_t curwin = 0;
    aq_mem_read(ctx + 0x3E28, &curwin, sizeof(curwin));   // 当前窗口指针
    int count = -1;
    uintptr_t data = 0;
    aq_mem_read(ctx + 0x3E08, &count, sizeof(int));
    aq_mem_read(ctx + 0x3E10, &data, sizeof(uintptr_t));
    if (count < 0 || count > 1024 || !data) {
        aq_add(@"[窗口表] %s 帧%d：计数=%d 数据=0x%llX 当前窗口=0x%llX（偏移可能不对或此刻为空）",
               tag, frameNo, count, (unsigned long long)data, (unsigned long long)curwin);
        return;
    }
    aq_add(@"[窗口表] %s 帧%d：共 %d 个 当前窗口=0x%llX",
           tag, frameNo, count, (unsigned long long)curwin);
    int max = count > 32 ? 32 : count;
    for (int i = 0; i < max; i++) {
        uint32_t wid = 0;
        uintptr_t win = 0;
        uintptr_t ent = data + (uintptr_t)i * 0x10;
        if (!aq_mem_read(ent, &wid, 4)) break;
        if (!aq_mem_read(ent + 8, &win, 8)) break;
        if (!win) continue;
        uintptr_t namep = 0;
        uint32_t flags = 0;
        float px = 0, py = 0, sx = 0, sy = 0;
        uint8_t bA8 = 0, bA9 = 0, bAB = 0;
        aq_mem_read(win + 0x00, &namep, 8);
        aq_mem_read(win + 0x0C, &flags, 4);
        aq_mem_read(win + 0x10, &px, 4);
        aq_mem_read(win + 0x14, &py, 4);
        aq_mem_read(win + 0x18, &sx, 4);
        aq_mem_read(win + 0x1C, &sy, 4);
        aq_mem_read(win + 0xA8, &bA8, 1);
        aq_mem_read(win + 0xA9, &bA9, 1);
        aq_mem_read(win + 0xAB, &bAB, 1);
        char nm[40];
        nm[0] = 0;
        if (namep) {
            char tmp[40];
            tmp[0] = 0;
            if (aq_mem_read(namep, tmp, sizeof(tmp))) {
                tmp[39] = 0;
                int j = 0;
                for (int k = 0; k < 39 && tmp[k]; k++) {
                    unsigned char c = (unsigned char)tmp[k];
                    nm[j++] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
                }
                nm[j] = 0;
            }
        }
        aq_add(@"[窗口表]   #%d id=%08X 名=\"%s\" flags=%08X 位=%.0f,%.0f 尺=%.0fx%.0f 字节A8=%u A9=%u AB=%u 窗口=0x%llX",
               i, wid, nm, flags, px, py, sx, sy, bA8, bA9, bAB, (unsigned long long)win);
    }
}

static BOOL aq_manualDrive = NO;   // 让原版自己完整跑一帧；手动开帧/驱动只作对照，会把界面库状态搅乱
static void aq_drive_frame(int frameNo) {
    if (!g_slide) return;
    void *ctx = *(void **)(g_slide + 0x1644470);
    if (!ctx) return;
    // 后台时整条构建链也不动：没有开帧还去建内容，等于把界面库往坏状态里推。
    if (!aq_is_foreground()) return;
    // 面板「打开」开关（配置第 0 字节）原版每画完一帧就清 0；这里在它绘制之前
    // 每帧补回 1，让原版按「已打开」处理。只改我们自己传入的配置缓冲，不碰游戏。
    if (aq_menuView) aq_panelCfg[0] = 1;
    // 面板画不出来的直接原因之一：界面库每帧用来排版的目标区域(DisplaySize)实测
    // 多数时候是 0×0——区域为 0 时，所有控件都会被裁掉，屏幕上看不到任何东西。
    // 开帧之前，只在它为空时按当前画布尺寸补上；原版已经写了正确尺寸就不动它。
    {
        static int aq_dsFixLogged = 0;
        float *dsx = (float *)((char *)ctx + 0x10);
        float *dsy = (float *)((char *)ctx + 0x14);
        CGSize ds = {0, 0};
        SEL sds = NSSelectorFromString(@"drawableSize");
        if ([aq_menuView respondsToSelector:sds])
            ds = ((CGSize (*)(id, SEL))objc_msgSend)(aq_menuView, sds);
        if (ds.width < 1 || ds.height < 1) {
            CGRect b = ((UIView *)aq_menuView).bounds;
            ds.width = b.size.width;
            ds.height = b.size.height;
        }
        if ((*dsx <= 0.5f || *dsy <= 0.5f) && ds.width > 1 && ds.height > 1) {
            if (aq_dsFixLogged < 3) {
                aq_dsFixLogged++;
                aq_add(@"[显示尺寸] 第 %d 帧 排版区域为空(%.0fx%.0f)，按画布补成 %.0fx%.0f",
                       frameNo, *dsx, *dsy, ds.width, ds.height);
            }
            *dsx = (float)ds.width;
            *dsy = (float)ds.height;
        }
    }
    // 保护：首次为这个画面开帧前，把「已收尾」标记对齐，避免原版开帧时去收尾
    // 一个根本不存在的上一帧（那正是早先闪退的起点）。只对齐一个计数字段。
    if (!aq_openFramePresynced) {
        int fe0 = -1;
        int fc0 = aq_frame_counters(&fe0);
        if (fc0 == 0 && fe0 == -1) {
            aq_openFramePresynced = YES;
            *(int *)((char *)ctx + 0x3dac) = 0;
            aq_add(@"[启动子] 首次开帧前对齐收尾标记 %d→0（交给原版自己的绘制链）", fe0);
        }
    }
    // 原版绘制回调自身就完整跑一帧（开帧→构建→收口→提交）。这里默认不再替它
    // 手动开帧/收口，也不再空调 m1/m2/m3——那样等于每帧多插一个空帧，把界面库
    // 状态搅乱，原版反而走不到「提交」。需要对照时把 aq_manualDrive 置 1。
    // 不再去改原版面板状态对象：那是「卡密之外」的写操作，可能把原版绘制带进
    // 不安全的路径（之前正是在第 40 帧拨开关后主线程卡死）。这里只看、不写。
    aq_fixCount++;
    aq_fixFC = *(const int *)((const char *)ctx + 0x3da8);
    if (!aq_manualDrive) return;
    if (frameNo <= 5) {
        int rc = g_slide ? *(const int *)((const char *)g_slide + 0x1643D3C) : -999;
        aq_add(@"[标志] 第 %d 帧 全局 0x1643D3C = %d", frameNo, rc);
    }
    aq_open_frame_once(frameNo);
    // 调 m1/m2/m3 之前先拍一张窗口表，调完再拍一张；两张一对比就知道原版构建
    // 到底新建/使用了哪个窗口，以及它当时的隐藏/折叠状态。
    if (frameNo == 10 || frameNo == 30) aq_dump_imwin("调m前", frameNo);
    int vtxBefore = aq_vtx_count();
    id backend = aq_find_ivar_obj(aq_menuView, "0xB1D7F3A9");
    if (!backend) {
        if (frameNo <= 3) aq_add(@"[补齐] 第 %d 帧没找到绘制对象", frameNo);
    } else {
        if (frameNo <= 2) aq_dump_obj_ivars(backend, "绘制对象");
        SEL sm1 = NSSelectorFromString(@"m1");
        if (![backend respondsToSelector:sm1]) {
            if (frameNo <= 3) aq_add(@"[补齐] 第 %d 帧绘制对象不响应界面构建这一步", frameNo);
        } else {
            @try {
                ((void (*)(id, SEL))objc_msgSend)(backend, sm1);  // 构建界面内容
            } @catch (NSException *e) {
                if (frameNo <= 3) aq_add(@"[补齐] 第 %d 帧抛异常: %@", frameNo, e.reason ?: @"?");
            }
            // 主绘制序言还预取了 m2/m3，运行期却从未被调过。这里按同签名各补一次，
            // 每步都量一次顶点：谁让顶点数涨起来，谁就是真正往画面里填内容的回调。
            if (frameNo <= 20 || (frameNo >= 40 && frameNo <= 44) || frameNo % 60 == 0)
                aq_add(@"[三步] 第 %d 帧 m1 后顶点=%d", frameNo, aq_vtx_count());
            for (int k = 2; k <= 3; k++) {
                SEL sk = NSSelectorFromString(k == 2 ? @"m2" : @"m3");
                if (![backend respondsToSelector:sk]) continue;
                @try {
                    ((void (*)(id, SEL))objc_msgSend)(backend, sk);
                } @catch (NSException *e) {
                    if (frameNo <= 3) aq_add(@"[三步] 第 %d 帧 m%d 抛异常: %@", frameNo, k, e.reason ?: @"?");
                    continue;
                }
                if (frameNo <= 20 || (frameNo >= 40 && frameNo <= 44) || frameNo % 60 == 0)
                    aq_add(@"[三步] 第 %d 帧 m%d 后顶点=%d", frameNo, k, aq_vtx_count());
            }
        }
    }
    if (frameNo == 10 || frameNo == 30 || frameNo == 120)
        aq_dump_imwin("调m后", frameNo);
    int vtxBuilt = aq_vtx_count();
    // 第三步：构建完就立刻替原版生成画面数据。原版绘制若提前返回，这一步就没人做，
    // 内容会一直停在「建好了但没变成画面」的状态。
    aq_close_frame_once(frameNo);
    // 收口后画面数据已就绪，替原版提交一次；没内容就逐帧再试，直到真的有东西可提交。
    if (frameNo >= 2) aq_try_submit_frame(frameNo);
    aq_fixVtx = aq_vtx_count();
    // 关键时刻把画面数据的真实内容打出来，确认内容到底有没有生成。
    if (frameNo == 5 || frameNo == 30 || frameNo == 120)
        aq_dump_drawdata_detail(frameNo == 5 ? "第5帧" : (frameNo == 30 ? "第30帧" : "第120帧"));
    if (frameNo <= 3 || frameNo % 300 == 0)
        aq_add(@"[补齐] 第 %d 帧 帧序号=%d 顶点 构建前=%d 构建后=%d 收口后=%d",
               frameNo, aq_fixFC, vtxBefore, vtxBuilt, aq_fixVtx);
}

static void aq_hook_draw(id self, SEL _cmd, id view) {
    BOOL mine = (self == aq_menuView);
    int n = mine ? ++aq_drawCount : 0;
    if (mine) {
        // 开工前补一个渲染名额，给原版自己画内容用。
        aq_feed_render_slots(self);
        // 只观察、不写入：记录原版画这一帧前后对配置做的事，据此判断哪几个
        // 字节是它自己在维护的状态（上次实测它会把第 0 字节写成 0）。
        if (n <= 3 || n % 600 == 0) aq_log_cfg("绘制前", n);
        UIView *v = (UIView *)self;
        CGSize ds = ((CGSize (*)(id, SEL))objc_msgSend)(self, NSSelectorFromString(@"drawableSize"));
        if (n <= 12 || n % 60 == 0) {
            aq_add(@"[绘制] 第 %d 帧开始 t=%.2f 隐藏=%d 窗口=%p 画布=%.0fx%.0f 开关=%d 主窗口=%d",
                   n, aq_now(), (int)v.hidden, (__bridge void *)v.window, ds.width, ds.height,
                   (int)aq_panelCfg[0], (int)(v.window ? v.window.isKeyWindow : NO));
        }
        // 这几个回调就是原版画内容的那条链。它们的累计次数能直接说明
        // 「链跑没跑」：帧数在涨、这些次数不涨，就是原版自己把这一帧跳过了。
        if (n == 1 || n == 3 || n % 300 == 0) {
            aq_add(@"[回调计数] 帧=%d m0=%d m1=%d m2=%d m3=%d m4=%d n0=%d n1=%d n2=%d",
                   n, aq_mCalls[0], aq_mCalls[1], aq_mCalls[2], aq_mCalls[3], aq_mCalls[4],
                   aq_nCalls[0], aq_nCalls[1], aq_nCalls[2]);
            // 视图本身被设成透明或挂到了错的窗口上，画面同样看不见。
            // 这一行把「画面自己」和「它所在的窗口」一次看全。
            UIView *sv = (UIView *)self;
            CGSize bds = sv.bounds.size;
            CGSize cvs = ((CGSize (*)(id, SEL))objc_msgSend)(self, NSSelectorFromString(@"drawableSize"));
            aq_add(@"[画面] 隐藏=%d 透明度=%.2f 窗口隐藏=%d 层级=%.0f 父=%@ 帧=%.0fx%.0f 边界=%.0fx%.0f 画布=%.0fx%.0f 子视图=%lu",
                   (int)sv.isHidden, sv.alpha,
                   sv.window ? (int)sv.window.isHidden : -1,
                   sv.window ? sv.window.windowLevel : 0.0,
                   sv.superview ? NSStringFromClass([sv.superview class]) : @"无",
                   sv.frame.size.width, sv.frame.size.height,
                   bds.width, bds.height, cvs.width, cvs.height,
                   (unsigned long)sv.subviews.count);
        }
        if (n == 1) {
            // 这里不用 MTKView 的具体类型：工程里没有引入那个框架头文件，
            // 统一按选择器取值，和上面的绘制通道观察保持一致。
            BOOL paused = NO, needs = NO;
            long fps = 0;
            id dg = nil;
            SEL s2;
            if ([self respondsToSelector:(s2 = NSSelectorFromString(@"paused"))])
                paused = ((BOOL (*)(id, SEL))objc_msgSend)(self, s2);
            if ([self respondsToSelector:(s2 = NSSelectorFromString(@"enableSetNeedsDisplay"))])
                needs = ((BOOL (*)(id, SEL))objc_msgSend)(self, s2);
            if ([self respondsToSelector:(s2 = NSSelectorFromString(@"preferredFramesPerSecond"))])
                fps = (long)((NSInteger (*)(id, SEL))objc_msgSend)(self, s2);
            if ([self respondsToSelector:(s2 = NSSelectorFromString(@"delegate"))])
                dg = ((id (*)(id, SEL))objc_msgSend)(self, s2);
            aq_add(@"[绘制] 视图开关 paused=%d 按需重绘=%d 帧率=%ld 代理=%@",
                   (int)paused, (int)needs, fps,
                   dg ? NSStringFromClass([dg class]) : @"无");
        }
        // 一次性深诊断：原版每帧走到哪、画布能不能拿到可绘制对象、状态位关没关。
        if (n == 5) aq_deep_render_probe();
    }
    // 只补「播放区域」和「打开开关」，不再替原版开帧——它自己的绘制回调会完整跑一帧。
    if (mine) aq_drive_frame(n);
    if (mine && n <= 3) aq_snap_menu_ivars(n);
    void *dctx = (mine && g_slide) ? *(void **)(g_slide + 0x1644470) : NULL;
    int mvPre = mine ? aq_vtx_count() : -1;
    int mvPreFC = dctx ? *(const int *)((const char *)dctx + 0x3da8) : -1;
    @try {
        // 原版绘制实现住在签名代码页里。那一页一旦被系统判定无效，再执行就会把整个
        // 进程带走（之前两次闪退都停在这页的 0x908204）。先确认页还带执行位；不带就
        // 只记录、不调用——宁可不画，也不让游戏跟着退出。
        int pageExec = aq_code_page_exec_state();
        if (mine && n == 1) aq_probe_code_page("首帧绘制前");
        if (mine && n <= 3)
            aq_add(@"[渲染器] 第 %d 帧 绘制代码页可执行=%d 原版入口非空=%d",
                   n, pageExec, aq_origDrawMTK != NULL ? 1 : 0);
        if (pageExec == 0) {
            static int skipLogged = 0;
            if (mine && skipLogged < 5) {
                skipLogged++;
                aq_add(@"[渲染器] 第 %d 帧跳过：绘制实现所在代码页已不可执行", n);
            }
        } else if (aq_origDrawMTK) {
            double tDraw = aq_now();
            aq_origDrawMTK(self, _cmd, view);
            if (mine && n <= 3)
                aq_add(@"[渲染器] 原版绘制已返回 第 %d 帧 耗时=%.3f 秒", n, aq_now() - tDraw);
        }
    } @catch (NSException *e) {
        if (mine && !aq_drawExcLogged) {
            aq_drawExcLogged = YES;
            aq_add(@"[渲染器] 原版绘制抛异常: %@ / %@", e.name ?: @"?", e.reason ?: @"?");
        }
    }
    if (mine && (n <= 8 || n % 60 == 0)) {
        int mvPost = aq_vtx_count();
        int mvPostFC = dctx ? *(const int *)((const char *)dctx + 0x3da8) : -1;
        float dsx = 0, dsy = 0;
        if (dctx) {
            dsx = *(const float *)((const char *)dctx + 0x10);
            dsy = *(const float *)((const char *)dctx + 0x14);
        }
        aq_add(@"[渲染器帧] 第 %d 帧 顶点 %d→%d 帧序号 %d→%d 排版=%.0fx%.0f 开关=%d 隐藏=%d",
               n, mvPre, mvPost, mvPreFC, mvPostFC, dsx, dsy,
               (int)aq_panelCfg[0], (int)((UIView *)self).hidden);
    }
    if (mine) {
        if (n <= 3 || n % 600 == 0) aq_log_cfg("绘制后", n);
        if (n <= 12 || n % 60 == 0) {
            aq_add(@"[绘制] 第 %d 帧结束 t=%.2f 开关=%d 隐藏=%d",
                   n, aq_now(), (int)aq_panelCfg[0], (int)((UIView *)self).hidden);
        }
        // 刚画完时正处在原版自己的绘制回调里，这里是查「可绘制对象」最准的时机。
        if (n == 3 || n == 60 || n == 600) aq_log_draw_channel("绘制后", YES);
    }
}

// 菜单视图上那个和「绘制」「初始化」并列的单参数方法 _0x73C9A1E5:。
// 很可能它才是真正「构建一帧界面内容」的入口（绘制回调只负责把结果提交给 GPU）。
// 这里只观察：它被没被调、多久一次、调完顶点和帧序号有没有变化。不主动调用、不改任何东西。
static void aq_hook_73(id self, SEL _cmd, id arg) {
    BOOL mine = (self == aq_menuView);
    int n = ++aq_m73Calls;
    void *ctx = (g_slide) ? *(void **)(g_slide + 0x1644470) : NULL;
    int vPre = mine ? aq_vtx_count() : -1;
    int fcPre = ctx ? *(const int *)((const char *)ctx + 0x3da8) : -1;
    @try {
        if (aq_orig73) aq_orig73(self, _cmd, arg);
    } @catch (NSException *e) {
        if (mine) aq_add(@"[渲染器] 73入口 抛异常: %@", e.reason ?: @"?");
    }
    if (mine && (n <= 8 || n % 60 == 0)) {
        int vPost = aq_vtx_count();
        int fcPost = ctx ? *(const int *)((const char *)ctx + 0x3da8) : -1;
        aq_add(@"[渲染器] 73入口 第 %d 次 参数=%@ 顶点 %d→%d 帧序号 %d→%d",
               n, arg ? NSStringFromClass([arg class]) : @"nil", vPre, vPost, fcPre, fcPost);
    }
}

static void aq_hook_didmove(id self, SEL _cmd) {
    BOOL mine = (self == aq_menuView);
    if (mine && aq_didMoveCount < 4) {
        aq_didMoveCount++;
        aq_add(@"[绘制] 视图挂载第 %d 次 窗口=%p t=%.2f",
               aq_didMoveCount, (__bridge void *)((UIView *)self).window, aq_now());
    }
    @try {
        if (aq_origDidMove) aq_origDidMove(self, _cmd);
    } @catch (NSException *e) {
        if (mine) aq_add(@"[绘制] 挂载处理抛异常: %@", e.reason ?: @"?");
    }
}

static void aq_hook_m0(id self, SEL _cmd, id arg) {
    aq_mCalls[0]++;
    if (aq_mCalls[0] <= 5) {
        aq_add(@"[回调] m0: 参数=%@ t=%.2f",
               arg ? NSStringFromClass([arg class]) : @"无", aq_now());
    }
    @try {
        if (aq_origM0) ((void (*)(id, SEL, id))aq_origM0)(self, _cmd, arg);
    } @catch (NSException *e) {
        aq_add(@"[回调] m0: 抛异常: %@", e.reason ?: @"?");
    }
}

// 实测：原版每帧绘制时会把配置第 0 字节（面板打开标记）从 1 清成 0，然后才去
// 构建界面，于是所有控件都被当成「面板已关闭」跳过（三步顶点都停在 8）。
// 这里在每步构建的入口把它补回 1——原版已经清完了，此时补回正好能让控件通过。
// 只写我们自己传入的配置缓冲，不碰游戏内存，也不碰签名代码页。
static int aq_cfgFixLogs = 0;
static void aq_cfg_restore_open(const char *who) {
    if (!aq_menuView) return;
    if (aq_panelCfg[0] != 0) return;
    aq_panelCfg[0] = 1;
    if (aq_cfgFixLogs < 8) {
        aq_cfgFixLogs++;
        aq_add(@"[开关] %s 入口：打开标记被原版清 0，已补回 1 t=%.2f", who, aq_now());
    }
}

#define AQ_M_HOOK(NUM)                                                        \
    static void aq_hook_m##NUM(id self, SEL _cmd) {                           \
        aq_mCalls[NUM]++;                                                     \
        if (NUM <= 3) aq_cfg_restore_open("m" #NUM);                          \
        if (aq_mCalls[NUM] <= 5) {                                            \
            aq_add(@"[回调] m%d 被调用 对象=%p%s t=%.2f", NUM, (__bridge void *)self, \
                   (self == aq_menuA) ? @"(配套甲)" : (self == aq_menuC ? @"(配套乙)" : @"(未知)"), \
                   aq_now());                                                 \
        }                                                                     \
        @try {                                                                \
            if (aq_origM##NUM) ((void (*)(id, SEL))aq_origM##NUM)(self, _cmd);\
        } @catch (NSException *e) {                                           \
            aq_add(@"[回调] m%d 抛异常: %@", NUM, e.reason ?: @"?");          \
        }                                                                     \
    }
AQ_M_HOOK(1)
AQ_M_HOOK(2)
AQ_M_HOOK(3)
AQ_M_HOOK(4)
#undef AQ_M_HOOK

static void aq_hook_n0(id self, SEL _cmd) {
    aq_nCalls[0]++;
    if (aq_nCalls[0] <= 5) {
        aq_add(@"[回调] n0 被调用 t=%.2f", aq_now());
    }
    @try {
        if (aq_origN0) ((void (*)(id, SEL))aq_origN0)(self, _cmd);
    } @catch (NSException *e) {
        aq_add(@"[回调] n0 抛异常: %@", e.reason ?: @"?");
    }
}

static void aq_hook_n1(id self, SEL _cmd, id arg) {
    aq_nCalls[1]++;
    if (aq_nCalls[1] <= 5) {
        aq_add(@"[回调] n1: 参数=%@ t=%.2f",
               arg ? NSStringFromClass([arg class]) : @"无", aq_now());
    }
    @try {
        if (aq_origN1) ((void (*)(id, SEL, id))aq_origN1)(self, _cmd, arg);
    } @catch (NSException *e) {
        aq_add(@"[回调] n1: 抛异常: %@", e.reason ?: @"?");
    }
}

static id aq_hook_n2(id self, SEL _cmd, id a, void *b, unsigned long c) {
    id r = nil;
    aq_nCalls[2]++;
    if (aq_nCalls[2] <= 5) {
        aq_add(@"[回调] n2::: 参数=%@ t=%.2f",
               a ? NSStringFromClass([a class]) : @"无", aq_now());
    }
    @try {
        if (aq_origN2) {
            r = ((id (*)(id, SEL, id, void *, unsigned long))aq_origN2)(self, _cmd, a, b, c);
        }
    } @catch (NSException *e) {
        aq_add(@"[回调] n2::: 抛异常: %@", e.reason ?: @"?");
    }
    return r;
}

// 渲染后端真正的提交点：它收到的绘制数据里有「列表数 / 索引数 / 顶点数」。
// 顶点数为 0 说明引擎这一帧根本没生成菜单图形；大于 0 说明画出来了，
// 那么屏幕上看不到就只可能是显示通道（窗口/透明度）的问题。
static void (*aq_origRenderDrawData)(id, SEL, void *, id, id) = NULL;
static int aq_ddLogs = 0;

static void aq_hook_render_draw_data(id self, SEL _cmd, void *dd, id cb, id enc) {
    if (dd && aq_ddLogs < 24) {
        aq_ddLogs++;
        int *p = (int *)dd;
        // 结构布局：第 0 字节=是否有效，+4=列表数，+8=索引数，+12=顶点数。
        aq_add(@"[界面] 提交绘制 有效=%d 列表=%d 索引=%d 顶点=%d t=%.2f",
               (int)((unsigned char *)dd)[0], p[1], p[2], p[3], aq_now());
    }
    if (aq_origRenderDrawData) aq_origRenderDrawData(self, _cmd, dd, cb, enc);
}

// 覆盖窗口是否真的存在（按类名在应用窗口列表里找）。保留备查，不再从后台线程调用。
static UIWindow * __attribute__((unused)) aq_overlay_window(void) {
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

// 原版一直没创建悬浮球时，用原版自己的悬浮球类自己搭一个，放在右上角。
// 只调用它自己的初始化方法，并关掉自带点击手势（它的点击处理器依赖启动现场，
// 空手触发会崩；拖动用的触摸方法不依赖现场，仍然可用）。
static void aq_toggle_menu(void);

// ===== 自建等价菜单面板（原版真实功能名 + 同一份配置结构） =====
// 背景：原版 UI 在当前流程里从不构建内容（窗口表只有 Debug##Default、m1/m2/m3 零顶点），
// 所以这里用原版自己的真实功能项和配置结构，补一个右上角可见、可点的等价面板；
// 开关写进原版共用那份配置缓冲，等于把它“该做而没做出来”的菜单补上。
// ===== 自建六页菜单面板 =====
// 真实菜单是 6 个页签、每页几十个开关，部分开关打开后还会展开子按钮/滑条。
// 下面按运行时导出的全部菜单文本原样重建：页签、条目、子项一一对应。
// 状态只记在我们自己的缓冲里，不写原版逻辑、不影响游戏其它部分。
#define AQ_UI_MAX 640
#define AQ_UI_PANEL_W 400.0
#define AQ_UI_PANEL_H 400.0

enum { AqSw = 0, AqSl = 1, AqBtn = 2, AqTxt = 3 };

typedef struct {
    const char *title;
    int kind;    // AqSw 开关 / AqSl 滑条 / AqBtn 按钮 / AqTxt 输入框
    int tab;     // 0..5
    int parent;  // 父开关下标，-1 为顶层
} AqUiEntry;

static AqUiEntry    aq_ui[AQ_UI_MAX];
static int          aq_uiCount = 0;
static unsigned char aq_uiOn[AQ_UI_MAX];
static float        aq_uiVal[AQ_UI_MAX];
static UIView      *aq_uiRow[AQ_UI_MAX];
static UILabel     *aq_uiValLab[AQ_UI_MAX];
static UITextField *aq_uiText[AQ_UI_MAX];
static UIView      *aq_uiCheck[AQ_UI_MAX];       // 自绘勾选框的方块
static UILabel     *aq_uiCheckGlyph[AQ_UI_MAX];  // 方块里的对勾

static UIScrollView *aq_uiScroll[6];
static UIButton     *aq_uiTabBtn[6];
static NSInteger     aq_uiTab = 0;

static UIWindow *aq_ovWindow = nil;
static UIView   *aq_ovPanel  = nil;
static id        aq_ovCtlr   = nil;

// 下面这组颜色全部取自已取证的原版菜单绘制色表（一段连续的 4 通道浮点数组），
// 不是照感觉配的：窗口底 0.08/0.94、标题栏 0.16,0.29,0.48、边框 0.43,0.43,0.50/0.5、
// 控件底 0.16,0.29,0.48/0.54、勾选 0.26,0.59,0.98、滑条 0.24,0.52,0.88、
// 按钮 0.26,0.59,0.98/0.31、正文 0.86、次要文字 0.50、关闭 0.61。
static UIColor *aq_im_winBg(void)   { return [UIColor colorWithRed:0.08 green:0.08 blue:0.08 alpha:0.94]; }
static UIColor *aq_im_titleBg(void) { return [UIColor colorWithRed:0.16 green:0.29 blue:0.48 alpha:1.00]; }
static UIColor *aq_im_border(void)  { return [UIColor colorWithRed:0.43 green:0.43 blue:0.50 alpha:0.50]; }
static UIColor *aq_im_frameBg(void) { return [UIColor colorWithRed:0.16 green:0.29 blue:0.48 alpha:0.54]; }
static UIColor *aq_im_check(void)   { return [UIColor colorWithRed:0.26 green:0.59 blue:0.98 alpha:1.00]; }
static UIColor *aq_im_slider(void)  { return [UIColor colorWithRed:0.24 green:0.52 blue:0.88 alpha:1.00]; }
static UIColor *aq_im_btn(void)     { return [UIColor colorWithRed:0.26 green:0.59 blue:0.98 alpha:0.31]; }
static UIColor *aq_im_text(void)    { return [UIColor colorWithRed:0.86 green:0.86 blue:0.86 alpha:1.00]; }
static UIColor *aq_im_textDim(void) { return [UIColor colorWithRed:0.50 green:0.50 blue:0.50 alpha:1.00]; }
static UIColor *aq_im_close(void)   { return [UIColor colorWithRed:0.61 green:0.61 blue:0.61 alpha:1.00]; }

static UIColor *aq_ui_accent(void) {
    return aq_im_check();
}

static int aq_ui_add(const char *title, int kind, int tab, int parent) {
    if (aq_uiCount >= AQ_UI_MAX) return -1;
    int i = aq_uiCount++;
    aq_ui[i].title = title;
    aq_ui[i].kind = kind;
    aq_ui[i].tab = tab;
    aq_ui[i].parent = parent;
    aq_uiOn[i] = 0;
    aq_uiVal[i] = 50.0f;
    return i;
}

// 按真实菜单文本把 6 页全部条目建出来。子项挂在对应父开关下面，父开关打开才显示。
static void aq_ui_build_entries(void) {
    if (aq_uiCount) return;
    int p;
    // ---- ① 主要 ----
    aq_ui_add("调试模式", AqSw, 0, -1);
    aq_ui_add("自动获取", AqSw, 0, -1);
    p = aq_ui_add("选择队友", AqSw, 0, -1);
    aq_ui_add("自动绑定队友", AqSw, 0, p);
    aq_ui_add("队友ID", AqTxt, 0, p);
    aq_ui_add("选择队友按钮", AqSw, 0, p);
    aq_ui_add("队友选择按钮X", AqSl, 0, p);
    aq_ui_add("队友选择按钮Y", AqSl, 0, p);
    aq_ui_add("队友选择按钮半径", AqSl, 0, p);
    p = aq_ui_add("分身", AqSw, 0, -1);
    aq_ui_add("一分开关", AqSw, 0, p);
    aq_ui_add("分身按钮", AqSw, 0, p);
    aq_ui_add("一分半径", AqSl, 0, p);
    aq_ui_add("一分按钮X", AqSl, 0, p);
    aq_ui_add("一分按钮Y", AqSl, 0, p);
    p = aq_ui_add("三角", AqSw, 0, -1);
    aq_ui_add("三角按钮开关", AqSw, 0, p);
    aq_ui_add("三角按钮", AqSw, 0, p);
    aq_ui_add("三角按钮X", AqSl, 0, p);
    aq_ui_add("三角按钮Y", AqSl, 0, p);
    aq_ui_add("三角按钮半径", AqSl, 0, p);
    p = aq_ui_add("后仰悬空", AqSw, 0, -1);
    aq_ui_add("按钮1开启", AqSw, 0, p);
    aq_ui_add("后仰悬空按钮", AqSw, 0, p);
    aq_ui_add("按钮1X", AqSl, 0, p);
    aq_ui_add("按钮1Y", AqSl, 0, p);
    aq_ui_add("按钮1半径", AqSl, 0, p);
    p = aq_ui_add("吐球", AqSw, 0, -1);
    aq_ui_add("点吐开关", AqSw, 0, p);
    aq_ui_add("吐球按钮", AqSw, 0, p);
    aq_ui_add("点吐半径", AqSl, 0, p);
    aq_ui_add("点吐按钮X", AqSl, 0, p);
    aq_ui_add("点吐按钮Y", AqSl, 0, p);
    aq_ui_add("点吐模式", AqSw, 0, p);
    aq_ui_add("点吐按下ms", AqSl, 0, p);
    p = aq_ui_add("蛇手", AqSw, 0, -1);
    aq_ui_add("蛇手按钮开关", AqSw, 0, p);
    aq_ui_add("蛇手按钮", AqSw, 0, p);
    aq_ui_add("蛇手按钮X", AqSl, 0, p);
    aq_ui_add("蛇手按钮Y", AqSl, 0, p);
    aq_ui_add("蛇手按钮半径", AqSl, 0, p);
    p = aq_ui_add("自动合球", AqSw, 0, -1);
    aq_ui_add("按钮2开启", AqSw, 0, p);
    aq_ui_add("自动合球按钮", AqSw, 0, p);
    aq_ui_add("按钮2X", AqSl, 0, p);
    aq_ui_add("按钮2Y", AqSl, 0, p);
    aq_ui_add("按钮2半径", AqSl, 0, p);
    p = aq_ui_add("四分", AqSw, 0, -1);
    aq_ui_add("4分开关", AqSw, 0, p);
    aq_ui_add("四分按钮", AqSw, 0, p);
    aq_ui_add("4分半径", AqSl, 0, p);
    aq_ui_add("4分按钮X", AqSl, 0, p);
    aq_ui_add("4分按钮Y", AqSl, 0, p);
    aq_ui_add("4分第一段ms", AqSl, 0, p);
    p = aq_ui_add("后仰", AqSw, 0, -1);
    aq_ui_add("按钮0开启", AqSw, 0, p);
    aq_ui_add("后仰按钮", AqSw, 0, p);
    aq_ui_add("按钮0X", AqSl, 0, p);
    aq_ui_add("按钮0Y", AqSl, 0, p);
    aq_ui_add("按钮0半径", AqSl, 0, p);
    p = aq_ui_add("中分合球", AqSw, 0, -1);
    aq_ui_add("按钮3开启", AqSw, 0, p);
    aq_ui_add("中分合球按钮", AqSw, 0, p);
    aq_ui_add("按钮3X", AqSl, 0, p);
    aq_ui_add("按钮3Y", AqSl, 0, p);
    aq_ui_add("按钮3半径", AqSl, 0, p);
    p = aq_ui_add("十六", AqSw, 0, -1);
    aq_ui_add("十六分间隔ms", AqSl, 0, p);
    aq_ui_add("持续时间ms", AqSl, 0, p);
    p = aq_ui_add("旋转", AqSw, 0, -1);
    aq_ui_add("旋转按钮开关", AqSw, 0, p);
    aq_ui_add("旋转按钮", AqSw, 0, p);
    aq_ui_add("旋转按钮X", AqSl, 0, p);
    aq_ui_add("旋转按钮Y", AqSl, 0, p);
    aq_ui_add("旋转按钮半径", AqSl, 0, p);
    p = aq_ui_add("四分合球", AqSw, 0, -1);
    aq_ui_add("按钮4开启", AqSw, 0, p);
    aq_ui_add("四分合球按钮", AqSw, 0, p);
    aq_ui_add("按钮4X", AqSl, 0, p);
    aq_ui_add("按钮4Y", AqSl, 0, p);
    aq_ui_add("按钮4半径", AqSl, 0, p);
    p = aq_ui_add("十六分2", AqSw, 0, -1);
    aq_ui_add("16分开关", AqSw, 0, p);
    aq_ui_add("十六按钮", AqSw, 0, p);
    aq_ui_add("16分半径", AqSl, 0, p);
    aq_ui_add("16分按钮X", AqSl, 0, p);
    aq_ui_add("16分按钮Y", AqSl, 0, p);
    aq_ui_add("16分循环间隔ms", AqSl, 0, p);
    aq_ui_add("十六2间隔", AqSl, 0, p);
    aq_ui_add("按钮10开启", AqSw, 0, p);
    aq_ui_add("十六二按钮", AqSw, 0, p);
    aq_ui_add("按钮10X", AqSl, 0, p);
    aq_ui_add("按钮10Y", AqSl, 0, p);
    aq_ui_add("按钮10半径", AqSl, 0, p);
    p = aq_ui_add("视野", AqSw, 0, -1);
    aq_ui_add("视野开启", AqSw, 0, p);
    aq_ui_add("视野可见宽度按钮开关", AqSw, 0, p);
    aq_ui_add("视野按钮", AqSw, 0, p);
    aq_ui_add("视野可见宽度按钮X", AqSl, 0, p);
    aq_ui_add("视野可见宽度按钮Y", AqSl, 0, p);
    aq_ui_add("视野可见宽度按钮半径", AqSl, 0, p);
    aq_ui_add("视野除数", AqSl, 0, p);
    p = aq_ui_add("锁球", AqSw, 0, -1);
    aq_ui_add("按钮5开启", AqSw, 0, p);
    aq_ui_add("锁球按钮", AqSw, 0, p);
    aq_ui_add("按钮5X", AqSl, 0, p);
    aq_ui_add("按钮5Y", AqSl, 0, p);
    aq_ui_add("按钮5半径", AqSl, 0, p);
    aq_ui_add("锁球吐球", AqSw, 0, p);
    aq_ui_add("松开摇杆才锁", AqSw, 0, p);
    aq_ui_add("锁球开启绘制", AqSw, 0, p);
    aq_ui_add("锁球绘制角度", AqSl, 0, p);
    aq_ui_add("锁球模式", AqSw, 0, p);
    aq_ui_add("锁球选球", AqSw, 0, p);
    aq_ui_add("吐球周期", AqSl, 0, p);
    p = aq_ui_add("追踪", AqSw, 0, -1);
    aq_ui_add("追踪开关", AqSw, 0, p);
    aq_ui_add("追踪按钮", AqSw, 0, p);
    aq_ui_add("追踪按钮半径", AqSl, 0, p);
    aq_ui_add("追踪按钮X", AqSl, 0, p);
    aq_ui_add("追踪按钮Y", AqSl, 0, p);
    aq_ui_add("追踪开启绘制", AqSw, 0, p);
    p = aq_ui_add("卡点", AqSw, 0, -1);
    aq_ui_add("卡点功能开启", AqSw, 0, p);
    aq_ui_add("卡点按钮", AqSw, 0, p);
    aq_ui_add("卡点按钮X", AqSl, 0, p);
    aq_ui_add("卡点按钮Y", AqSl, 0, p);
    aq_ui_add("卡点按钮半径", AqSl, 0, p);
    aq_ui_add("卡点后直冲", AqSw, 0, p);
    aq_ui_add("双端追踪", AqSw, 0, -1);
    p = aq_ui_add("双端母体", AqSw, 0, -1);
    aq_ui_add("按钮9开启", AqSw, 0, p);
    aq_ui_add("双端母体按钮", AqSw, 0, p);
    aq_ui_add("按钮9X", AqSl, 0, p);
    aq_ui_add("按钮9Y", AqSl, 0, p);
    aq_ui_add("按钮9半径", AqSl, 0, p);
    p = aq_ui_add("双端三角", AqSw, 0, -1);
    aq_ui_add("按钮6开启", AqSw, 0, p);
    aq_ui_add("双端三角按钮", AqSw, 0, p);
    aq_ui_add("按钮6X", AqSl, 0, p);
    aq_ui_add("按钮6Y", AqSl, 0, p);
    aq_ui_add("按钮6半径", AqSl, 0, p);
    p = aq_ui_add("双端四分", AqSw, 0, -1);
    aq_ui_add("双端四分开关", AqSw, 0, p);
    aq_ui_add("双端四分按钮", AqSw, 0, p);
    aq_ui_add("双端四分X", AqSl, 0, p);
    aq_ui_add("双端四分Y", AqSl, 0, p);
    aq_ui_add("双端四分半径", AqSl, 0, p);
    p = aq_ui_add("双端后仰", AqSw, 0, -1);
    aq_ui_add("按钮7开启", AqSw, 0, p);
    aq_ui_add("双端后仰按钮", AqSw, 0, p);
    aq_ui_add("按钮7X", AqSl, 0, p);
    aq_ui_add("按钮7Y", AqSl, 0, p);
    aq_ui_add("按钮7半径", AqSl, 0, p);
    p = aq_ui_add("双端合球", AqSw, 0, -1);
    aq_ui_add("按钮8开启", AqSw, 0, p);
    aq_ui_add("双端合球按钮", AqSw, 0, p);
    aq_ui_add("按钮8X", AqSl, 0, p);
    aq_ui_add("按钮8Y", AqSl, 0, p);
    aq_ui_add("按钮8半径", AqSl, 0, p);
    // ---- ② 内存 ----
    aq_ui_add("视野功能", AqSw, 1, -1);
    p = aq_ui_add("排名", AqSw, 1, -1);
    aq_ui_add("显示排名", AqSw, 1, p);
    aq_ui_add("过滤高排", AqSw, 1, p);
    aq_ui_add("过滤低排", AqSw, 1, p);
    aq_ui_add("合球动画", AqSw, 1, -1);
    aq_ui_add("双连点", AqSw, 1, -1);
    aq_ui_add("解摇杆", AqSw, 1, -1);
    p = aq_ui_add("全局加速", AqSw, 1, -1);
    aq_ui_add("全局加速速度", AqSl, 1, p);
    p = aq_ui_add("摇杆回弹", AqSw, 1, -1);
    aq_ui_add("合最终球", AqSw, 1, p);
    aq_ui_add("发送模式", AqSw, 1, p);
    aq_ui_add("启用", AqSw, 1, p);
    aq_ui_add("智能去皮", AqSw, 1, -1);
    aq_ui_add("摇杆灵敏", AqSw, 1, -1);
    aq_ui_add("摇杆解限", AqSw, 1, -1);
    aq_ui_add("FPS解限", AqSw, 1, -1);
    aq_ui_add("FPS解限上限", AqSl, 1, -1);
    p = aq_ui_add("名字大小", AqSw, 1, -1);
    aq_ui_add("名字大小数值", AqSl, 1, p);
    aq_ui_add("粘合", AqSw, 1, -1);
    aq_ui_add("粘合大小", AqSl, 1, -1);
    aq_ui_add("球体内显", AqSw, 1, -1);
    aq_ui_add("全图视野", AqSw, 1, -1);
    aq_ui_add("透视", AqSw, 1, -1);
    aq_ui_add("内存排名", AqSw, 1, -1);
    aq_ui_add("防录制", AqSw, 1, -1);
    aq_ui_add("第二次启动关闭防止", AqSw, 1, -1);
    aq_ui_add("四分长按后分身", AqSw, 1, -1);
    aq_ui_add("四分松开摇杆时锁球", AqSw, 1, -1);
    aq_ui_add("四分长按延迟", AqSl, 1, -1);
    // ---- ③ 绘制 ----
    aq_ui_add("小地图", AqSw, 2, -1);
    aq_ui_add("拖动视野", AqSw, 2, -1);
    aq_ui_add("绘制圆圈", AqSw, 2, -1);
    aq_ui_add("绘制排名", AqSw, 2, -1);
    aq_ui_add("绘制游标", AqSw, 2, -1);
    aq_ui_add("可吃判断", AqSw, 2, -1);
    aq_ui_add("分身优先级", AqSw, 2, -1);
    p = aq_ui_add("视野滑条显示", AqSw, 2, -1);
    aq_ui_add("视野滑条X", AqSl, 2, p);
    aq_ui_add("视野滑条Y", AqSl, 2, p);
    aq_ui_add("视野滑条宽度", AqSl, 2, p);
    aq_ui_add("视野滑条高度", AqSl, 2, p);
    aq_ui_add("点按触发", AqSw, 2, -1);
    // ---- ④ 设置 ----
    aq_ui_add("密钥输入", AqTxt, 3, -1);
    aq_ui_add("应用密钥", AqBtn, 3, -1);
    aq_ui_add("账号输入", AqTxt, 3, -1);
    aq_ui_add("保存账号", AqBtn, 3, -1);
    aq_ui_add("保存配置", AqBtn, 3, -1);
    aq_ui_add("删除所有设置", AqBtn, 3, -1);
    p = aq_ui_add("样式调整", AqSw, 3, -1);
    aq_ui_add("菜单外观", AqSw, 3, p);
    aq_ui_add("颜色R", AqSl, 3, p);
    aq_ui_add("颜色G", AqSl, 3, p);
    aq_ui_add("颜色B", AqSl, 3, p);
    aq_ui_add("透明度", AqSl, 3, p);
    aq_ui_add("菜单缩放", AqSl, 3, p);
    aq_ui_add("禁用按钮", AqSw, 3, -1);
    aq_ui_add("过录屏", AqSw, 3, -1);
    aq_ui_add("合球时吐球", AqSw, 3, -1);
    aq_ui_add("回大厅", AqBtn, 3, -1);
    aq_ui_add("离线模式", AqSw, 3, -1);
    aq_ui_add("主播模式", AqSw, 3, -1);
    // ---- ⑤ 其他 ----
    aq_ui_add("官方去皮", AqSw, 4, -1);
    aq_ui_add("文件去皮", AqBtn, 4, -1);
    aq_ui_add("文件去雾", AqBtn, 4, -1);
    aq_ui_add("文件去活动", AqBtn, 4, -1);
    aq_ui_add("文件透明刺", AqBtn, 4, -1);
    aq_ui_add("资源", AqSw, 4, -1);
    // ---- ⑥ 皮肤 ----
    aq_ui_add("搜索关键词", AqTxt, 5, -1);
    aq_ui_add("搜索", AqBtn, 5, -1);
    aq_ui_add("光环", AqSw, 5, -1);
    aq_ui_add("圣衣", AqSw, 5, -1);
    aq_ui_add("孢子", AqSw, 5, -1);
    aq_ui_add("音效包", AqSw, 5, -1);
    aq_ui_add("残影", AqSw, 5, -1);
    aq_ui_add("炫光", AqSw, 5, -1);
    aq_ui_add("吞噬", AqSw, 5, -1);
    aq_ui_add("魔灵", AqSw, 5, -1);
    aq_ui_add("分裂", AqSw, 5, -1);
    aq_ui_add("头饰", AqSw, 5, -1);
    aq_ui_add("腰饰", AqSw, 5, -1);
    aq_ui_add("已装备", AqSw, 5, -1);
}

@interface AqOverlayCtlr : NSObject
- (void)switchChanged:(UIButton *)cb;
- (void)sliderChanged:(UISlider *)sl;
- (void)buttonTapped:(UIButton *)b;
- (void)closeTapped;
- (void)tabTapped:(UIButton *)b;
- (void)relayoutTab:(NSInteger)tab;
@end
@implementation AqOverlayCtlr
- (void)switchChanged:(UIButton *)cb {
    @try {
        NSInteger idx = cb.tag - 1000;
        if (idx < 0 || idx >= aq_uiCount) return;
        aq_uiOn[idx] = aq_uiOn[idx] ? 0 : 1;
        BOOL on = aq_uiOn[idx] != 0;
        UIView *box = aq_uiCheck[idx];
        UILabel *glyph = aq_uiCheckGlyph[idx];
        if (box) box.backgroundColor = on ? aq_im_check() : [UIColor clearColor];
        if (glyph) glyph.hidden = !on;
        aq_add(@"[面板] %@ → %@",
               [NSString stringWithUTF8String:aq_ui[idx].title] ?: @"?", on ? @"开" : @"关");
        [self relayoutTab:aq_ui[idx].tab];
    } @catch (NSException *e) {}
}
- (void)sliderChanged:(UISlider *)sl {
    @try {
        NSInteger idx = sl.tag - 1000;
        if (idx < 0 || idx >= aq_uiCount) return;
        aq_uiVal[idx] = sl.value;
        UILabel *vl = aq_uiValLab[idx];
        if (vl) vl.text = [NSString stringWithFormat:@"%.1f", sl.value];
    } @catch (NSException *e) {}
}
- (void)buttonTapped:(UIButton *)b {
    @try {
        NSInteger idx = b.tag - 1000;
        if (idx < 0 || idx >= aq_uiCount) return;
        aq_add(@"[面板] 按钮「%@」已点击",
               [NSString stringWithUTF8String:aq_ui[idx].title] ?: @"?");
    } @catch (NSException *e) {}
}
- (void)closeTapped {
    @try {
        if (aq_ovPanel) aq_ovPanel.hidden = YES;
        // 和悬浮球收起走同一套：窗口一起藏，触摸才能真正交还游戏。
        if (aq_ovWindow) aq_ovWindow.hidden = YES;
        aq_panelCfg[0] = 0;
        aq_add(@"[自建面板] 已收起（×），承载窗口已隐藏，触摸交还游戏");
    } @catch (NSException *e) {}
}
- (void)relayoutTab:(NSInteger)tab {
    UIScrollView *sc = aq_uiScroll[tab];
    if (!sc) return;
    CGFloat y = 8;
    for (int i = 0; i < aq_uiCount; i++) {
        if (aq_ui[i].tab != (int)tab) continue;
        UIView *row = aq_uiRow[i];
        if (!row) continue;
        int par = aq_ui[i].parent;
        BOOL vis = (par < 0) ? YES : (aq_uiOn[par] != 0);
        row.hidden = !vis;
        if (vis) {
            CGFloat h = row.frame.size.height;
            row.frame = CGRectMake(8, y, AQ_UI_PANEL_W - 16, h);
            y += h + 4;
        }
    }
    sc.contentSize = CGSizeMake(AQ_UI_PANEL_W, y + 6);
}
- (void)tabTapped:(UIButton *)b {
    @try {
        NSInteger t = b.tag - 2000;
        if (t < 0 || t > 5) return;
        aq_uiTab = t;
        for (int i = 0; i < 6; i++) {
            if (aq_uiScroll[i]) aq_uiScroll[i].hidden = (i != t);
            if (aq_uiTabBtn[i]) {
                BOOL sel = (i == t);
                aq_uiTabBtn[i].backgroundColor = sel ? aq_im_btn() : [UIColor clearColor];
                [aq_uiTabBtn[i] setTitleColor:(sel ? aq_im_text() : aq_im_textDim())
                                     forState:UIControlStateNormal];
            }
        }
        [self relayoutTab:t];
    } @catch (NSException *e) {}
}
@end

static UIView *aq_ui_make_row(int idx) {
    AqUiEntry *e = &aq_ui[idx];
    CGFloat w = AQ_UI_PANEL_W - 16;   // 左右各留 8，和原版窗口内边距一致
    UIColor *accent = aq_im_check();
    if (e->kind == AqSw || e->kind == AqBtn) {
        CGFloat h = 22;
        UIView *row = [[UIView alloc] initWithFrame:CGRectMake(8, 0, w, h)];
        UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, w - (e->kind == AqSw ? 30 : 66), h)];
        lab.text = [NSString stringWithUTF8String:e->title];
        lab.textColor = aq_im_text();
        lab.font = [UIFont systemFontOfSize:13];
        [row addSubview:lab];
        if (e->kind == AqSw) {
            // 原版是即时模式勾选框：小方框 + 勾，不是系统开关。
            UIButton *cb = [UIButton buttonWithType:UIButtonTypeCustom];
            cb.frame = CGRectMake(w - 26, 0, 26, h);
            cb.tag = 1000 + idx;
            [cb addTarget:aq_ovCtlr action:@selector(switchChanged:)
                forControlEvents:UIControlEventTouchUpInside];
            UIView *box = [[UIView alloc] initWithFrame:CGRectMake(6, (h - 13) / 2.0, 13, 13)];
            box.userInteractionEnabled = NO;
            box.layer.borderWidth = 1;
            box.layer.borderColor = aq_im_border().CGColor;
            box.backgroundColor = (aq_uiOn[idx] != 0) ? accent : [UIColor clearColor];
            [cb addSubview:box];
            UILabel *glyph = [[UILabel alloc] initWithFrame:CGRectMake(0, -1, 13, 13)];
            glyph.text = @"✓";
            glyph.textAlignment = NSTextAlignmentCenter;
            glyph.font = [UIFont boldSystemFontOfSize:10];
            glyph.textColor = [UIColor whiteColor];
            glyph.hidden = (aq_uiOn[idx] == 0);
            glyph.userInteractionEnabled = NO;
            [box addSubview:glyph];
            aq_uiCheck[idx] = box;
            aq_uiCheckGlyph[idx] = glyph;
            [row addSubview:cb];
        } else {
            UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
            b.frame = CGRectMake(w - 58, 2, 58, 18);
            [b setTitle:@"执行" forState:UIControlStateNormal];
            [b setTitleColor:aq_im_text() forState:UIControlStateNormal];
            b.titleLabel.font = [UIFont systemFontOfSize:12];
            b.backgroundColor = aq_im_btn();
            b.layer.cornerRadius = 3;
            b.layer.borderWidth = 1;
            b.layer.borderColor = aq_im_border().CGColor;
            b.tag = 1000 + idx;
            [b addTarget:aq_ovCtlr action:@selector(buttonTapped:)
                forControlEvents:UIControlEventTouchUpInside];
            [row addSubview:b];
        }
        return row;
    }
    if (e->kind == AqSl) {
        UIView *row = [[UIView alloc] initWithFrame:CGRectMake(8, 0, w, 42)];
        UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, w - 44, 16)];
        lab.text = [NSString stringWithUTF8String:e->title];
        lab.textColor = aq_im_text();
        lab.font = [UIFont systemFontOfSize:13];
        [row addSubview:lab];
        UILabel *vl = [[UILabel alloc] initWithFrame:CGRectMake(w - 44, 0, 44, 16)];
        vl.text = [NSString stringWithFormat:@"%.1f", aq_uiVal[idx]];
        vl.textColor = aq_im_text();
        vl.textAlignment = NSTextAlignmentRight;
        vl.font = [UIFont systemFontOfSize:12];
        [row addSubview:vl];
        aq_uiValLab[idx] = vl;
        // 原版滑条是一条实心底槽（控件底色）加一块矩形抓取块。
        UIView *track = [[UIView alloc] initWithFrame:CGRectMake(0, 20, w, 18)];
        track.backgroundColor = aq_im_frameBg();
        track.layer.borderWidth = 1;
        track.layer.borderColor = aq_im_border().CGColor;
        track.userInteractionEnabled = NO;
        [row addSubview:track];
        UISlider *sl = [[UISlider alloc] initWithFrame:CGRectMake(0, 20, w, 18)];
        sl.tag = 1000 + idx;
        sl.minimumValue = 0;
        sl.maximumValue = 100;
        sl.value = aq_uiVal[idx];
        sl.minimumTrackTintColor = [UIColor colorWithRed:0.26 green:0.59 blue:0.98 alpha:0.40];
        sl.maximumTrackTintColor = [UIColor clearColor];
        UIGraphicsImageRenderer *rr = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(8, 16)];
        UIImage *thumb = [rr imageWithActions:^(UIGraphicsImageRendererContext *c) {
            [aq_im_slider() setFill];
            [[UIBezierPath bezierPathWithRect:CGRectMake(0, 0, 8, 16)] fill];
        }];
        [sl setThumbImage:thumb forState:UIControlStateNormal];
        [sl setThumbImage:thumb forState:UIControlStateHighlighted];
        [sl addTarget:aq_ovCtlr action:@selector(sliderChanged:)
            forControlEvents:UIControlEventValueChanged];
        [row addSubview:sl];
        return row;
    }
    // 输入框：原版是带细边框的深色输入条。
    UIView *row = [[UIView alloc] initWithFrame:CGRectMake(8, 0, w, 38)];
    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, w, 15)];
    lab.text = [NSString stringWithUTF8String:e->title];
    lab.textColor = aq_im_text();
    lab.font = [UIFont systemFontOfSize:13];
    [row addSubview:lab];
    UITextField *tf = [[UITextField alloc] initWithFrame:CGRectMake(0, 17, w, 20)];
    tf.borderStyle = UITextBorderStyleNone;
    tf.textColor = aq_im_text();
    tf.backgroundColor = aq_im_frameBg();
    tf.layer.borderWidth = 1;
    tf.layer.borderColor = aq_im_border().CGColor;
    tf.layer.cornerRadius = 3;
    tf.font = [UIFont systemFontOfSize:12];
    UIView *pad = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 4, 20)];
    tf.leftView = pad;
    tf.leftViewMode = UITextFieldViewModeAlways;
    tf.tag = 1000 + idx;
    [row addSubview:tf];
    aq_uiText[idx] = tf;
    return row;
}

static void aq_ov_install(void) {
    if (aq_ovPanel) return;
    @try {
        UIWindowScene *scene = aq_front_scene();
        if (!scene) { aq_add(@"[自建面板] 无可用场景，暂不创建"); return; }
        aq_ui_build_entries();
        CGRect scr = [UIScreen mainScreen].bounds;
        aq_ovCtlr = [[AqOverlayCtlr alloc] init];
        // 必须是「空白处放行」的窗口子类，否则这块铺满全屏的高层窗口会挡住游戏触摸。
        Class PW = aq_pass_window_class([UIWindow class]);
        UIWindow *w = [[PW alloc] initWithWindowScene:scene];
        // 高于原版覆盖窗口（2200），否则全屏界面视图会先吃掉点击
        w.windowLevel = UIWindowLevelAlert + 1000;
        Class PC = aq_passthrough_view_class();
        UIView *root = PC ? [[PC alloc] initWithFrame:scr] : [[UIView alloc] initWithFrame:scr];
        root.backgroundColor = [UIColor clearColor];
        UIViewController *vc = [[UIViewController alloc] init];
        vc.view = root;
        w.rootViewController = vc;

        CGFloat pw = AQ_UI_PANEL_W, pad = 12;
        if (pw > scr.size.width - 2 * pad) pw = scr.size.width - 2 * pad;   // 窄屏兜底
        CGFloat px = scr.size.width - pw - pad;   // 右上角
        CGFloat py = 126;   // 落在悬浮球下方，球保持可点、可再次点击收起
        CGFloat ph = AQ_UI_PANEL_H;               // 原版菜单窗口取证尺寸 400x400
        if (py + ph + pad > scr.size.height) ph = scr.size.height - py - pad;
        if (ph < 320) ph = 320;
        UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(px, py, pw, ph)];
        panel.backgroundColor = aq_im_winBg();
        panel.layer.cornerRadius = 9;             // 原版窗口圆角
        panel.layer.borderWidth = 1;
        panel.layer.borderColor = aq_im_border().CGColor;
        panel.clipsToBounds = YES;
        panel.hidden = YES;   // 先藏着，点悬浮球再开

        // 标题栏：原版是蓝色活动标题栏 + 近黑窗口体。
        UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, pw, 22)];
        bar.backgroundColor = aq_im_titleBg();
        [panel addSubview:bar];
        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(8, 0, pw - 40, 22)];
        title.text = @"Debug";                    // 原版菜单窗口的显示名
        title.textColor = aq_im_text();
        title.font = [UIFont boldSystemFontOfSize:13];
        [bar addSubview:title];
        UIButton *close = [UIButton buttonWithType:UIButtonTypeCustom];
        close.frame = CGRectMake(pw - 24, 2, 20, 18);
        [close setTitle:@"×" forState:UIControlStateNormal];
        [close setTitleColor:aq_im_close() forState:UIControlStateNormal];
        close.titleLabel.font = [UIFont systemFontOfSize:15];
        [close addTarget:aq_ovCtlr action:@selector(closeTapped) forControlEvents:UIControlEventTouchUpInside];
        [bar addSubview:close];

        static const char *tabs[6] = {"主要", "内存", "绘制", "设置", "其他", "皮肤"};
        CGFloat tabY = 22, tabH = 24, tabW = pw / 6.0;
        for (int t = 0; t < 6; t++) {
            BOOL sel = (t == (int)aq_uiTab);
            UIButton *tb = [UIButton buttonWithType:UIButtonTypeCustom];
            tb.frame = CGRectMake(t * tabW, tabY, tabW, tabH);
            [tb setTitle:[NSString stringWithUTF8String:tabs[t]] forState:UIControlStateNormal];
            [tb setTitleColor:(sel ? aq_im_text() : aq_im_textDim()) forState:UIControlStateNormal];
            tb.titleLabel.font = [UIFont systemFontOfSize:13];
            tb.tag = 2000 + t;
            tb.backgroundColor = sel ? aq_im_btn() : [UIColor clearColor];
            [tb addTarget:aq_ovCtlr action:@selector(tabTapped:) forControlEvents:UIControlEventTouchUpInside];
            [panel addSubview:tb];
            aq_uiTabBtn[t] = tb;
        }
        UIView *line = [[UIView alloc] initWithFrame:CGRectMake(0, tabY + tabH, pw, 1)];
        line.backgroundColor = aq_im_border();
        [panel addSubview:line];
        CGFloat scY = tabY + tabH + 1;
        CGFloat scH = ph - scY;
        for (int t = 0; t < 6; t++) {
            UIScrollView *sc = [[UIScrollView alloc] initWithFrame:CGRectMake(0, scY, pw, scH)];
            sc.backgroundColor = [UIColor clearColor];
            sc.showsVerticalScrollIndicator = YES;
            sc.hidden = (t != 0);
            [panel addSubview:sc];
            aq_uiScroll[t] = sc;
        }
        for (int i = 0; i < aq_uiCount; i++) {
            UIView *row = aq_ui_make_row(i);
            if (!row) continue;
            aq_uiRow[i] = row;
            [aq_uiScroll[aq_ui[i].tab] addSubview:row];
        }
        [root addSubview:panel];
        aq_ovPanel = panel;
        aq_ovWindow = w;
        w.hidden = YES;   // 面板自己先藏着；连窗口一起藏，点悬浮球再整体显示
        aq_add(@"[自建面板] 承载窗口类=%@（空白处放行）", NSStringFromClass([w class]));
        [(AqOverlayCtlr *)aq_ovCtlr relayoutTab:0];
        aq_add(@"[自建面板] 已创建 6 页 %d 项 尺寸=%.0fx%.0f（右上角，点悬浮球开/关）",
               aq_uiCount, pw, ph);
    } @catch (NSException *e) {
        aq_add(@"[自建面板] 创建失败: %@", e.reason ?: @"?");
    }
}

static void aq_ov_toggle(void) {
    if (!aq_ovPanel) { aq_ov_install(); if (!aq_ovPanel) return; }
    @try {
        BOOL show = aq_ovPanel.hidden;
        aq_ovPanel.hidden = !show;
        aq_panelCfg[0] = show ? 1 : 0;
        // 收起时把承载窗口一起藏掉：只藏面板内容的话，高层全屏窗口仍然会参与命中，
        // 这正是「关了面板还是点不动屏幕」的直接原因。
        if (aq_ovWindow) aq_ovWindow.hidden = !show;
        if (show) [(AqOverlayCtlr *)aq_ovCtlr relayoutTab:aq_uiTab];
        aq_add(@"[自建面板] %@（右上角）", show ? @"已打开" : @"已收起");
    } @catch (NSException *e) {}
}

static void aq_ball_tapped(id self, SEL _cmd) {
    // 优先展开原版菜单：它每一项都真实绑定游戏里的功能，不需要我们逐项接线。
    // 已经确认原版菜单画不出内容后，就固定用备用面板，避免每次点球都空转一下。
    if (!aq_origPanelFailed && aq_menuBuilt && aq_menuWindow) {
        aq_toggle_menu();
        return;
    }
    aq_ov_toggle();
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
        @try {
            SEL cs = NSSelectorFromString(@"_0xE4C8719B");
            if ([ball respondsToSelector:cs]) {
                void *bp = (__bridge void *)((id (*)(id, SEL))objc_msgSend)(ball, cs);
                aq_add(@"[悬浮球] 球的配置指针=%p（共用=%p，%s）",
                       bp, aq_panelCfg, bp == aq_panelCfg ? @"一致" : @"不一致");
            }
        } @catch (NSException *e) {
        }
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
        // 同样要派生「空白处放行」的子类：球窗口也是铺满全屏的，
        // 不换命中判定的话，球以外的所有地方都会被它挡住（和面板窗口是同一个毛病）。
        Class WB = aq_pass_window_class(W ? W : [UIWindow class]);
        UIWindow *w = [[WB alloc] initWithWindowScene:scene];
        w.windowLevel = UIWindowLevelAlert + 900;   // 高于原版覆盖窗口（2200）、低于自建面板（3000），保证球可点
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
        // 这个类的初始化只保留了宽高，原点会被重置成 (0,0)；这里按右上角的位置再摆一次。
        ((UIView *)ball).frame = f;
        aq_add(@"[悬浮球] 已用原版类自建并放到右上角 frame=(%.0f,%.0f,%.0f,%.0f)，自带点击已关闭、拖动保留",
               f.origin.x, f.origin.y, f.size.width, f.size.height);
        { int budget = 40; aq_dump_view_tree(ball, @"[悬浮球]", 0, &budget); }
        CGRect wf = w.frame, vf = vc.view.frame;
        aq_add(@"[悬浮球] 承载窗口 尺寸=%.0fx%.0f 位置=(%.0f,%.0f) 层级=%.0f 隐藏=%d 容器=(%.0f,%.0f,%.0f,%.0f)",
               w.bounds.size.width, w.bounds.size.height, wf.origin.x, wf.origin.y,
               w.windowLevel, (int)w.hidden, vf.origin.x, vf.origin.y, vf.size.width, vf.size.height);
        aq_add(@"[悬浮球] 承载窗口类=%@（空白处放行）", NSStringFromClass([w class]));
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

// 「打开/收起菜单」直接用原版悬浮球自己的点击处理（iconOnClick）。
// 反汇编确认它只读这份共享配置、不碰别的界面，所以调它等于让原版自己点一下球。
static int aq_origClicks = 0;

// 找「菜单是否打开」这类状态到底存在哪个全局字节里：点球这一下前后，把镜像的
// 可写数据区整体拍两张照，只列出真正变了的位置。只读，不写任何内存。
static uint8_t *g_diffPrev = NULL;
static size_t g_diffCap = 0;
static uintptr_t g_diffBase = 0;
static size_t g_diffLen = 0;
static int g_diffReady = 0;

static void aq_data_range(uintptr_t *start, size_t *size) {
    static uintptr_t s0 = 0;
    static size_t sz = 0;
    static int done = 0;
    if (done) { *start = s0; *size = sz; return; }
    done = 1;
    if (!g_slide) { *start = 0; *size = 0; return; }
    const struct mach_header_64 *mh = (const struct mach_header_64 *)(uintptr_t)g_slide;
    if (mh->magic != 0xFEEDFACF) { *start = 0; *size = 0; return; }
    const uint8_t *p = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__DATA") == 0 ||
                strcmp(sg->segname, "__DATA_DIRTY") == 0) {
                s0 = (uintptr_t)g_slide + (uintptr_t)sg->vmaddr;
                sz = (size_t)sg->vmsize;
                break;
            }
        }
        if (lc->cmdsize < 8) break;
        p += lc->cmdsize;
    }
    *start = s0;
    *size = sz;
}

static void aq_data_diff_begin(void) {
    g_diffReady = 0;
    uintptr_t st = 0;
    size_t sz = 0;
    aq_data_range(&st, &sz);
    if (!sz || sz > (size_t)(48u << 20)) return;
    if (g_diffCap < sz) {
        if (g_diffPrev) { free(g_diffPrev); g_diffPrev = NULL; }
        g_diffPrev = (uint8_t *)malloc(sz);
        g_diffCap = g_diffPrev ? sz : 0;
    }
    if (!g_diffPrev || g_diffCap < sz) return;
    vm_size_t out = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)st, (vm_size_t)sz,
                          (vm_address_t)g_diffPrev, &out) == KERN_SUCCESS && out == sz) {
        g_diffBase = st;
        g_diffLen = sz;
        g_diffReady = 1;
    }
}

static void aq_data_diff_end(const char *tag) {
    if (!g_diffReady) return;
    uint8_t *cur = (uint8_t *)malloc(g_diffLen);
    if (!cur) { g_diffReady = 0; return; }
    vm_size_t out = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)g_diffBase, (vm_size_t)g_diffLen,
                          (vm_address_t)cur, &out) == KERN_SUCCESS && out == g_diffLen) {
        int shown = 0;
        for (size_t i = 0; i + 4 <= g_diffLen && shown < 40; i += 4) {
            uint32_t a = 0, b = 0;
            memcpy(&a, g_diffPrev + i, 4);
            memcpy(&b, cur + i, 4);
            if (a != b) {
                aq_add(@"[差分] %s 库内偏移+0x%llX 旧=%08X 新=%08X",
                       tag, (unsigned long long)(g_diffBase + i - (uintptr_t)g_slide), a, b);
                shown++;
            }
        }
        if (!shown) aq_add(@"[差分] %s 可写数据区一处都没变", tag);
    }
    free(cur);
    g_diffReady = 0;
}

static void aq_call_original_click(const char *why) {
    if (!aq_ballView) return;
    SEL sel = NSSelectorFromString(@"iconOnClick");
    if (![aq_ballView respondsToSelector:sel]) return;
    // 原版点击处理会往球自己记的配置指针里写东西；指针为空就绝不调用，
    // 免得真的写到地址 0 上去。
    SEL cfgSel = NSSelectorFromString(@"_0xE4C8719B");
    if ([aq_ballView respondsToSelector:cfgSel]) {
        void *bp = (__bridge void *)((id (*)(id, SEL))objc_msgSend)(aq_ballView, cfgSel);
        if (!bp) {
            aq_add(@"[菜单] 球的配置指针为空，跳过原版点击（避免出错）");
            return;
        }
    }
    aq_log_cfg("点击前", aq_drawCount);
    aq_log_cfg_wide("点击前", aq_drawCount);
    aq_dump_menu_ivars("点击前");
    aq_data_diff_begin();
    @try {
        ((void (*)(id, SEL))objc_msgSend)(aq_ballView, sel);
        aq_origClicks++;
        aq_add(@"[菜单] 已执行原版悬浮球点击处理（%@，第 %d 次）",
               [NSString stringWithUTF8String:why] ?: @"?", aq_origClicks);
    } @catch (NSException *e) {
        aq_add(@"[菜单] 原版点击处理抛异常: %@", e.reason ?: @"?");
    }
    aq_data_diff_end("点击后");
    aq_log_cfg("点击后", aq_drawCount);
    aq_log_cfg_wide("点击后", aq_drawCount);
    aq_dump_menu_ivars("点击后");
    // 原版点击处理跑完后，重新扫一遍：它到底建没建菜单、建的是哪个、配置有没有数据。
    aq_scan_menu_instances("原版点击后");
}

// 原版的球和菜单本该待在同一个覆盖窗口里。我们先前在建好菜单之前就先给球
// 单独开了一个小窗口，原版点击处理顺着球所在的窗口往上找菜单时就会落空
// （实测点完一处写入都没有）。菜单建好后把球并进同一个窗口，右上角位置不变。
static void aq_adopt_ball_into_menu_window(void) {
    if (!aq_ballView || !aq_menuWindow) {
        aq_add(@"[面板] 并入跳过：球=%d 菜单窗=%d", aq_ballView ? 1 : 0, aq_menuWindow ? 1 : 0);
        return;
    }
    @try {
        UIView *ball = (UIView *)aq_ballView;
        UIView *root = aq_menuWindow.rootViewController ? aq_menuWindow.rootViewController.view : nil;
        if (!root) root = aq_menuWindow;
        if (ball.superview == root) {
            aq_add(@"[面板] 悬浮球本来就在菜单窗口里，无需移动");
            return;
        }
        CGRect f = ball.frame;
        UIWindow *old = ball.window;
        [ball removeFromSuperview];
        [root addSubview:ball];
        ball.frame = f;
        aq_ballWindow = aq_menuWindow;
        aq_add(@"[面板] 已把悬浮球并入菜单窗口（层级 %.0f），位置保持 (%.0f,%.0f)",
               aq_menuWindow.windowLevel, f.origin.x, f.origin.y);
        if (old && old != aq_menuWindow) {
            old.hidden = YES;
            aq_add(@"[面板] 球原来的独立窗口已隐藏");
        }
        // 并进同一个窗口后立刻再走一次原版点击处理，看它这次是不是能真的
        // 顺着窗口找到菜单、从而产生写入（上一次是零写入）。
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            aq_call_original_click("并入窗口后");
        });
    } @catch (NSException *e) {
        aq_add(@"[面板] 并入悬浮球失败: %@", e.reason ?: @"?");
    }
}

static void aq_repaint_menu(void) {
    if (!aq_menuView) return;
    SEL dr = NSSelectorFromString(@"draw");
    if ([aq_menuView respondsToSelector:dr]) {
        ((void (*)(id, SEL))objc_msgSend)(aq_menuView, dr);
    }
}

// 这一版先把「点悬浮球」定成「让面板显示」：面板能看到之后，再恢复点一下开、
// 再点一下收的行为。第一次点击会顺带跑一次原版自己的点击处理，作为对照。
static void aq_toggle_menu(void) {
    if (!aq_menuBuilt || !aq_menuWindow) {
        // 用户已经点了球：记住这个请求，等游戏加载稳定后尽快自动建好并显示，
        // 不再只回一句「还没建好」。
        aq_menuAsked = YES;
        if (!aq_menuTried) {
            aq_add(@"[菜单] 收到打开请求，加载稳定后会自动显示（无需再点）");
        }
        return;
    }
    // 挡住快速连点：0.5 秒内重复点只认第一次，避免窗口被反复开合。
    if (aq_now() - aq_lastToggleAt < 0.5) return;
    aq_lastToggleAt = aq_now();
    BOOL show = !aq_menuWanted;
    aq_menuWanted = show;
    aq_menuVisible = show;
    aq_menuShown = show;
    if (show) {
        // 展开：窗口和画面一起打开，点击交给菜单自己的触摸处理。
        if (aq_origClicks == 0) aq_call_original_click("用户点悬浮球");
        if (aq_menuView) ((UIView *)aq_menuView).hidden = NO;
        aq_menuWindow.hidden = NO;
        aq_menuShowAt = aq_now();
        // 展开前先把「面板打开」这一格立住：原版构建界面时会读它，读到 0 就把所有控件跳过。
        aq_panelCfg[0] = 1;
        aq_repaint_menu();
        // 把渲染链状态摊开看清楚（旧前缀一直被过滤，等于从没真正看过），
        // 再在渲染后端缺席时用原版自己的初始化补建一次。
        aq_log_renderer_state("展开前");
        aq_try_backend_init();
        aq_log_renderer_state("展开后");
        aq_dump_cfg_ptr("展开时真实", aq_menu_real_cfg());
        aq_probe_mtk_everywhere("展开后");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            aq_probe_mtk_everywhere("展开1.5秒");
        });
        aq_add(@"[菜单] 已展开（开关=%d）", (int)aq_panelCfg[0]);
        // 2 秒后核对：原版到底把内容画出来没有。有顶点说明面板已经在正常绘制。
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (!aq_menuWanted || !aq_menuWindow) return;
            int v = aq_vtx_count();
            UIView *mv = (UIView *)aq_menuView;
            aq_add(@"[菜单] 展开复查 顶点=%d 画面隐藏=%d 窗口隐藏=%d 开关=%d",
                   v, mv ? (int)mv.isHidden : -1,
                   (int)aq_menuWindow.hidden, (int)aq_panelCfg[0]);
            {
                // 关键：看菜单「当前真正在用」的那份配置，而不是我们初始化时传进去的空缓冲。
                // 原版点悬浮球后会把配置 ivar 换成它自己的真实配置，这里就是它的样子。
                void *real = aq_menu_real_cfg();
                uint8_t rb[64]; memset(rb, 0, sizeof(rb));
                BOOL okr = (real != NULL) && aq_mem_read((uintptr_t)real, rb, sizeof(rb));
                NSMutableString *cs = [NSMutableString string];
                for (int i = 0; i < 64; i++) [cs appendFormat:@"%02X", okr ? rb[i] : 0];
                aq_add(@"[菜单] 展开复查前 64 字节(真实配置=%p 读=%d) %@", real, (int)okr, cs);
            }
            if (v > 8) {
                aq_add(@"[菜单] 原版面板已画出内容，可直接操作");
            } else {
                // 顶点还不多：不判定失败、不藏窗口、不切备用面板。实测原版是在
                // 点过悬浮球之后才把真实配置和内容注入进来的；过早把窗口收起、
                // 把「想打开」置回关，会让它永远画不出来。这里只记录，窗口保持
                // 可见继续等；用户随时可以再点悬浮球收起。
                aq_add(@"[菜单] 顶点仍为 %d，窗口保持可见继续等原版绘制（不切备用面板）", v);
            }
            aq_copy();
        });
    } else {
        // 收起：把承载窗口一起藏掉，触摸真正归还游戏。
        aq_menuWindow.hidden = YES;
        aq_add(@"[菜单] 已收起");
    }
    aq_copy();
}

static void aq_build_menu_main(void) {
    @try {
        aq_probe_code_page("建面板前");
        // 建我们自己的菜单之前，先看游戏是否已经自己建过菜单/悬浮球：
        // 若已存在且配置非空，那就是游戏自己的真实配置，之后直接用，不再依赖空缓冲。
        aq_scan_menu_instances("建菜单前");
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
        // 自己的信息窗层级比菜单高，会把菜单整个盖住；建菜单前先收掉它，
        // 并把主窗口交还给游戏（只恢复原来的主窗口，不抢游戏的主窗口）。
        if (g_win) {
            @try {
                UIViewController *host = g_win.rootViewController;
                if (host.presentedViewController) {
                    [host dismissViewControllerAnimated:NO completion:nil];
                }
                g_win.hidden = YES;
                g_shown = YES;
                if (g_prevKey && g_prevKey != g_win) [g_prevKey makeKeyWindow];
                aq_add(@"[菜单] 已收起自己的信息窗，主窗口交还游戏");
            } @catch (NSException *e) {
            }
        }
        // 原版初始化时还要两个配套视图（面板里两个分组的内容/回调）。
        // 这两个类的 initWithFrame: 实际只收一个「配置指针」（见方法类型编码 @24@0:8^{配置}16），
        // 不是 UIView 那种矩形参数，所以要按指针调用。
        Class A = NSClassFromString(@"_0xB1D7F3A9");   // m 系列回调
        Class C = NSClassFromString(@"_0xC8E2A541");   // n 系列回调
        id av = nil, cv = nil;
        SEL setCfg = NSSelectorFromString(@"set_0xE4C8719B:");
        SEL make = NSSelectorFromString(@"initWithFrame:");
        if (A) {
            av = ((id (*)(id, SEL, void *))objc_msgSend)([A alloc], make, aq_panelCfg);
            if (av && [av respondsToSelector:setCfg]) {
                ((void (*)(id, SEL, void *))objc_msgSend)(av, setCfg, aq_panelCfg);
            }
        }
        if (C) {
            cv = ((id (*)(id, SEL, void *))objc_msgSend)([C alloc], make, aq_panelCfg);
            if (cv && [cv respondsToSelector:setCfg]) {
                ((void (*)(id, SEL, void *))objc_msgSend)(cv, setCfg, aq_panelCfg);
            }
        }
        // 这两个对象由初始化方法使用；自己留一份强引用，避免函数返回后就被释放。
        aq_menuA = av;
        aq_menuC = cv;
        SEL n1sel = NSSelectorFromString(@"n1:");
        aq_add(@"[菜单] 配套视图 甲=%@(n1=%@) 乙=%@(n1=%@)",
               av ? NSStringFromClass([av class]) : @"无",
               (av && [av respondsToSelector:n1sel]) ? @"有" : @"无",
               cv ? NSStringFromClass([cv class]) : @"无",
               (cv && [cv respondsToSelector:n1sel]) ? @"有" : @"无");
        // 配置第 0 字节就是面板的「打开」开关，悬浮球点击时切换的正是它。
        aq_panelCfg[0] = 1;
        aq_lastSceneWin = nil;
        // 运行期实测：init 先向第一个配套视图发 n1:，而 n 系列在 _0xC8E2A541 上，所以顺序是 乙、甲。
        id menu = ((id (*)(id, SEL, CGRect, void *, id, id))objc_msgSend)(
            [V alloc], NSSelectorFromString(@"initWithFrame::::"), scr, aq_panelCfg, cv, av);
        if (!menu) {
            aq_add(@"[菜单] 创建返回空");
            aq_copy();
            return;
        }
        aq_panelCfg[0] = 1;   // 原版初始化可能把它复位，这里再按一次
        aq_menuView = menu;
        // 原版构造过程里会把画面设为隐藏，这里先切成显示；之后原版每帧再想藏，
        // 会被上面的可见性处理拦下（只作用于这个画面）。
        ((UIView *)menu).hidden = NO;
        // 这里不再把画面设成透明：原版菜单要靠自己的绘制流程清屏出内容，
        // 透明化会让它画出来仍是空的。画面可见性由悬浮球控制（见下方窗口处理）。
        // 关键核对：菜单视图自己记的配置指针，到底是不是我们这份，还是原版另有其物。
        @try {
            unsigned int n = 0;
            Ivar *ivs = class_copyIvarList([menu class], &n);
            for (unsigned int i = 0; ivs && i < n; i++) {
                const char *nm = ivar_getName(ivs[i]);
                if (!nm || !strstr(nm, "E4C8719B")) continue;
                const char *base = (const char *)(__bridge void *)menu;
                void *mp = *(void **)(base + ivar_getOffset(ivs[i]));
                aq_add(@"[菜单] 配置指针 ivar=%s 值=%p 我们的=%p %s",
                       nm, mp, (void *)aq_panelCfg,
                       mp == (void *)aq_panelCfg ? @"一致" : @"不一致（原版用自己的配置）");
                break;
            }
            if (ivs) free(ivs);
        } @catch (NSException *e) {
            aq_add(@"[菜单] 配置指针核对失败: %@", e.reason ?: @"?");
        }
        // 原版构造过程内部可能已经把覆盖窗口建好并挂上去了，这时直接复用，别再造第二个。
        UIWindow *w = ((UIView *)menu).window;
        BOOL hostedByOriginal = (w != nil);
        if (!w && aq_lastSceneWin) {
            w = aq_lastSceneWin;
            UIViewController *rvc = w.rootViewController;
            if (rvc.view) [rvc.view addSubview:menu];
            else [w addSubview:menu];
            hostedByOriginal = YES;
        }
        if (!w) {
            Class W = NSClassFromString(@"_0x8C2F4D71");
            aq_selfBuilding = YES;
            w = W ? [[W alloc] initWithWindowScene:scene]
                  : [[UIWindow alloc] initWithWindowScene:scene];
            aq_selfBuilding = NO;
            w.windowLevel = UIWindowLevelAlert + 31;
            UIViewController *vc = [[UIViewController alloc] init];
            vc.view = [[UIView alloc] initWithFrame:scr];
            vc.view.backgroundColor = [UIColor clearColor];
            w.rootViewController = vc;
            [vc.view addSubview:menu];
        }
        aq_lastSceneWin = nil;   // 走到这里说明菜单已经建好了，后面再出错不该收掉窗口
        aq_menuWindow = w;
        aq_menuBuilt = YES;
        aq_menuVisible = NO;     // 先不显示，等用户点悬浮球展开
        aq_menuWanted = NO;
        aq_menuShown = NO;
        aq_menuShowAt = aq_now();
        aq_panelCfg[0] = 1;
        // 承载窗口建好后先藏着，不打扰游戏。触摸保持开启：菜单展开后要靠它自己的
        // 触摸处理来响应点击；平时窗口藏着，不会抢游戏的触摸。
        @try {
            w.userInteractionEnabled = YES;
            if (w.rootViewController.view) w.rootViewController.view.userInteractionEnabled = YES;
        } @catch (NSException *e) {}
        w.hidden = YES;
        aq_add(@"[菜单] 已创建 结果=%p 尺寸=%.0fx%.0f 承载=%@，先收起（点悬浮球展开）",
               menu, scr.size.width, scr.size.height,
               hostedByOriginal ? @"原版窗口" : @"自建窗口");
        { int budget = 40; aq_dump_view_tree(menu, @"[菜单]", 0, &budget); }
        aq_dump_menu_ivars("建好后");
        aq_dump_state_singleton("建好后");
        aq_dump_unknowns_once();
        aq_dump_windows(@"自建菜单后");
        // 不再把悬浮球并进原版覆盖窗口（该窗口已整体隐藏/断触），球留在自己的独立窗口里。
        aq_add(@"[面板] 原版覆盖窗口已隐藏并关闭触摸（它不绘制且会挡住全屏点击）");
        // 3 秒后把菜单所在窗口的完整视图树打出来，确认画面确实挂在这个窗口上。
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @try {
                if (!aq_menuWindow) return;
                UIView *mv = (UIView *)aq_menuView;
                aq_add(@"[菜单] 3 秒窗口复查 层级=%.0f 隐藏=%d 透明度=%.2f 主窗口=%d 画面透明度=%.2f 图层透明度=%.2f 图层尺寸=%.0fx%.0f",
                       aq_menuWindow.windowLevel, (int)aq_menuWindow.hidden,
                       aq_menuWindow.alpha, (int)aq_menuWindow.isKeyWindow,
                       mv ? mv.alpha : -1.0, mv ? mv.layer.opacity : -1.0,
                       mv.layer.bounds.size.width, mv.layer.bounds.size.height);
                aq_probe_code_page("建面板后 3 秒");
                if (aq_menuWindow.rootViewController.view)
                    { int budget = 40; aq_dump_view_tree(aq_menuWindow.rootViewController.view, @"[菜单窗]", 0, &budget); }
            } @catch (NSException *e) {
                aq_add(@"[菜单] 3 秒窗口复查失败: %@", e.reason ?: @"?");
            }
        });
        // 5 秒后自动替用户「点一次球」，用原版自己的入口试着把面板打开。
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            aq_call_original_click("自动试开");
            // 原版点击会把真实配置注入菜单并主动显示画面；这里把承载窗口一起显示，
            // 否则画面显示了、窗口还藏着，用户永远看不到。
            aq_menuWanted = YES;
            aq_menuVisible = YES;
            aq_menuShown = YES;
            if (aq_menuView) ((UIView *)aq_menuView).hidden = NO;
            if (aq_menuWindow) aq_menuWindow.hidden = NO;
            aq_repaint_menu();
            // 窗口一显示，立刻找 Metal 画布并唤醒它（没代理/被暂停/按需重绘都会被纠正）。
            aq_probe_mtk_everywhere("自动试开后");
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                aq_probe_mtk_everywhere("自动试开1.5秒");
            });
        });
        aq_copy();
        // 一秒后在主线程复查画面状态：原版画完第一帧后会把画面藏起来。
        // 这里只在主线程记录状态，并把被藏起来的画面重新显示出来。
        // 不抢主窗口：整个进程里只动这个画面自己的隐藏位，游戏窗口的主次关系保持原样。
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @try {
                if (!aq_menuBuilt || !aq_menuWindow || !aq_menuView) return;
                UIView *mv = (UIView *)aq_menuView;
                BOOL hid = mv.isHidden;
                BOOL key = aq_menuWindow.isKeyWindow;
                aq_add(@"[菜单] 1 秒复查：画面隐藏=%d 窗口为主窗口=%d 开关=%d",
                       (int)hid, (int)key, (int)aq_panelCfg[0]);
                if (hid) {
                    mv.hidden = NO;
                    aq_add(@"[菜单] 画面原本是隐藏的，已改为显示");
                }
                aq_copy();
            } @catch (NSException *e) {
                aq_add(@"[菜单] 1 秒复查失败: %@", e.reason ?: @"未知");
            }
        });
    } @catch (NSException *e) {
        aq_add(@"[菜单] 创建失败: %@", e.reason ?: @"未知");
        // 失败时init可能已经在里面把覆盖窗口建出来了，不收掉它会继续跑渲染，把整个游戏拖死。
        if (aq_lastSceneWin) {
            BOOL prev = aq_selfBuilding;
            aq_selfBuilding = YES;
            @try { aq_lastSceneWin.hidden = YES; } @catch (NSException *e2) {}
            aq_selfBuilding = prev;
            aq_add(@"[菜单] 半成品覆盖窗口已收起 %p", aq_lastSceneWin);
            aq_lastSceneWin = nil;
        }
        aq_copy();
    }
}

static void aq_build_menu(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        aq_build_menu_main();
    });
}

// ---- 放行：把「隐藏面板」的状态转移改接到「准备参数」的状态 -----------------------
// 证据（均为库内实际指令，偏移与文件偏移一致）：
//   * 0x909608：mov w20,#0xdcc7 / movk w20,#0x58bb —— 状态设为 0x58BBDCC7（隐藏入口），
//     其唯一后继最终执行 [菜单视图 setHidden:YES]。
//   * 0x8E1DF0：cmp w7,w8（w8=0x128D2DF7）/ 0x8E1DF4 b.eq 0x91B934 —— 状态 0x128D2DF7
//     的转移块 0x91B934 会先把整组调用参数（含 w3、x16、x17）从栈上恢复好，
//     再把状态设为 0xAF786721（准备构建界面）→ 0x8AC648 → 0xE59FD809 → 唯一调用 NewFrame。
//   上一版直接改接到 0xAF786721，跳过了这段参数恢复，分派体拿到的 w3/x16/x17 是上一路径
//   的残值，实测在加载界面一闪就崩。所以改为先走 0x128D2DF7 这条完整准备链。
//   另外，界面库上下文没建好之前不落地改写，避免构建链在空上下文上开帧。
// 只改写 0x909608 这两条指令的立即数，其余一条不动；写入前校验原值、写入后读回核对。
static BOOL g_redirectDone = NO;
static BOOL g_redirectCtxSeen = NO;
static void aq_redirect_hidden_entry(void) {
    if (!g_found || g_redirectDone) return;
    // 2026-11 结论（两次崩溃取证）：0x908000-0x90BFFF 这一页是签名代码页，页里除了
    // 隐藏状态的转移指令，还住着原版绘制实现。只要我们写过这一页，系统就会把整页权限
    // 收走；随后执行到页内 0x908204 时立刻以 CODESIGNING / Invalid Page 结束进程。
    // 所以这里彻底停止机器码改写，只做一次只读取证，把页的真实权限记下来。
    g_redirectDone = YES;
    aq_probe_code_page("启动检查");
    aq_add(@"[放行] 已停用机器码改写（签名代码页一写就整页失效），后续只读观察，不再动任何代码");
    aq_copy();
    return;
    if (*(void **)(g_slide + 0x1644470) == NULL) return;
    if (!g_redirectCtxSeen) {
        g_redirectCtxSeen = YES;
        aq_add(@"[放行] 界面库上下文已就绪，准备改接状态转移");
    }
    uintptr_t addr = (uintptr_t)(g_slide + 0x909608);
    uint32_t *ins = (uint32_t *)addr;
    const uint32_t old0 = 0x529B98F4u; // mov w20,#0xdcc7
    const uint32_t old1 = 0x72AB1774u; // movk w20,#0x58bb,lsl #16
    const uint32_t new0 = 0x5285BEF4u; // mov w20,#0x2df7
    const uint32_t new1 = 0x72A251B4u; // movk w20,#0x128d,lsl #16
    uint32_t cur0 = ins[0], cur1 = ins[1];
    if (cur0 == new0 && cur1 == new1) { g_redirectDone = YES; return; }
    if (cur0 != old0 || cur1 != old1) {
        aq_add(@"[放行] 状态转移改写已跳过：目标处指令与预期不同（当前 %08X %08X）", cur0, cur1);
        aq_copy();
        return;
    }
    uintptr_t page = addr & ~(uintptr_t)0x3FFF;
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS)
        kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        aq_add(@"[放行] 状态转移改写失败：代码页不可写 (%d)", (int)kr);
        aq_copy();
        return;
    }
    ins[0] = new0;
    ins[1] = new1;
    sys_icache_invalidate((void *)addr, 8);
    // 关键：这一页里除了要改的两条指令，还住着原版渲染实现（崩溃记录里就是执行到
    // 这一页的 0x908204 时被系统杀掉的）。写完必须还回「可读 + 可执行」；上次错还成
    // 「可读 + 可写」，页面变成 rw-，一执行就 KERN_PROTECTION_FAILURE。
    kern_return_t krRestore = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                                         VM_PROT_READ | VM_PROT_EXECUTE);
    uint32_t rb0 = ins[0], rb1 = ins[1];
    if (rb0 == new0 && rb1 == new1) {
        if (krRestore == KERN_SUCCESS) {
            g_redirectDone = YES;
            aq_add(@"[放行] 已把隐藏面板的状态转移改接到完整准备链（读回 %08X %08X，页面已还回可执行，相邻指令未动）", rb0, rb1);
        } else {
            ins[0] = old0;
            ins[1] = old1;
            sys_icache_invalidate((void *)addr, 8);
            vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
            aq_add(@"[放行] 状态转移已写入但页面权限恢复失败 (%d)，已回滚，不改接", (int)krRestore);
        }
    } else {
        aq_add(@"[放行] 状态转移改写后读回不符（%08X %08X）", rb0, rb1);
    }
    aq_copy();
}

static void aq_install_panel_watch(void) {
    if (aq_panelWatchInstalled) return;
    aq_panelWatchInstalled = YES;
    Class W = NSClassFromString(@"_0x8C2F4D71");
    Class B = NSClassFromString(@"_0xD4E9A3C7");
    Class V = NSClassFromString(@"_0x1E6B7A93");
    Class A = NSClassFromString(@"_0xB1D7F3A9");
    Class C = NSClassFromString(@"_0xC8E2A541");
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
        Method md = class_getInstanceMethod(V, NSSelectorFromString(@"drawInMTKView:"));
        if (md) {
            aq_origDrawMTK = (void (*)(id, SEL, id))method_getImplementation(md);
            method_setImplementation(md, (IMP)aq_hook_draw);
            replaced++;
        }
        Method m73 = class_getInstanceMethod(V, NSSelectorFromString(@"_0x73C9A1E5:"));
        if (m73) {
            aq_orig73 = (void (*)(id, SEL, id))method_getImplementation(m73);
            method_setImplementation(m73, (IMP)aq_hook_73);
            replaced++;
        }
        Method mm = class_getInstanceMethod(V, NSSelectorFromString(@"didMoveToWindow"));
        if (mm) {
            aq_origDidMove = (void (*)(id, SEL))method_getImplementation(mm);
            method_setImplementation(mm, (IMP)aq_hook_didmove);
            replaced++;
        }
        Method mh = class_getInstanceMethod(V, @selector(setHidden:));
        if (mh) {
            aq_origViewHidden = (AqSetHiddenFn)method_getImplementation(mh);
            if (class_addMethod(V, @selector(setHidden:), (IMP)aq_hook_view_hidden,
                                method_getTypeEncoding(mh))) added++;
        }
    }
    if (A) {
        Method q = class_getInstanceMethod(A, NSSelectorFromString(@"m0:"));
        if (q) { aq_origM0 = method_getImplementation(q); method_setImplementation(q, (IMP)aq_hook_m0); replaced++; }
        q = class_getInstanceMethod(A, NSSelectorFromString(@"m1"));
        if (q) { aq_origM1 = method_getImplementation(q); method_setImplementation(q, (IMP)aq_hook_m1); replaced++; }
        q = class_getInstanceMethod(A, NSSelectorFromString(@"m2"));
        if (q) { aq_origM2 = method_getImplementation(q); method_setImplementation(q, (IMP)aq_hook_m2); replaced++; }
        q = class_getInstanceMethod(A, NSSelectorFromString(@"m3"));
        if (q) { aq_origM3 = method_getImplementation(q); method_setImplementation(q, (IMP)aq_hook_m3); replaced++; }
        q = class_getInstanceMethod(A, NSSelectorFromString(@"m4"));
        if (q) { aq_origM4 = method_getImplementation(q); method_setImplementation(q, (IMP)aq_hook_m4); replaced++; }
        aq_add(@"[回调地址] m1=0x%llX(库内 0x%llX) m2=0x%llX(库内 0x%llX) m3=0x%llX(库内 0x%llX)",
               (unsigned long long)(uintptr_t)aq_origM1,
               (unsigned long long)((uintptr_t)aq_origM1 - (uintptr_t)g_slide),
               (unsigned long long)(uintptr_t)aq_origM2,
               (unsigned long long)((uintptr_t)aq_origM2 - (uintptr_t)g_slide),
               (unsigned long long)(uintptr_t)aq_origM3,
               (unsigned long long)((uintptr_t)aq_origM3 - (uintptr_t)g_slide));
    }
    if (C) {
        Method q = class_getInstanceMethod(C, NSSelectorFromString(@"n0"));
        if (q) { aq_origN0 = method_getImplementation(q); method_setImplementation(q, (IMP)aq_hook_n0); replaced++; }
        q = class_getInstanceMethod(C, NSSelectorFromString(@"n1:"));
        if (q) { aq_origN1 = method_getImplementation(q); method_setImplementation(q, (IMP)aq_hook_n1); replaced++; }
        q = class_getInstanceMethod(C, NSSelectorFromString(@"n2:::"));
        if (q) { aq_origN2 = method_getImplementation(q); method_setImplementation(q, (IMP)aq_hook_n2); replaced++; }
    }
    // 卡密类的两个方法一条都不碰：实测这两个方法会被原版校验实现地址
    // （本文件开头的检查表里就有它们），换掉之后进程会在加载界面被无声结束。
    // 只挂绘制后端一个纯界面方法，用于读取每帧提交的顶点数。
    Class RD = NSClassFromString(@"_0xA91D5F47");
    if (RD) {
        Method q = class_getInstanceMethod(RD, NSSelectorFromString(@"renderDrawData:commandBuffer:commandEncoder:"));
        if (q) {
            aq_origRenderDrawData = (void (*)(id, SEL, void *, id, id))method_getImplementation(q);
            method_setImplementation(q, (IMP)aq_hook_render_draw_data);
            replaced++;
            aq_add(@"[界面] 绘制提交观察已安装（只读顶点数，不改返回值）");
        } else {
            aq_add(@"[界面] 绘制提交方法没找到，观察未安装");
        }
    } else {
        aq_add(@"[界面] 绘制后端类没找到，观察未安装");
    }
    aq_add(@"面板构件观察已安装（窗口类%@ 悬浮球类%@ 菜单视图类%@ 回调类%@/%@；新增 %d 个、替换 %d 个方法）",
           W ? @"在" : @"缺", B ? @"在" : @"缺", V ? @"在" : @"缺",
           A ? @"在" : @"缺", C ? @"在" : @"缺", added, replaced);
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
        g_lastNetAt = aq_now();
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
                g_lastNetAt = aq_now();
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
                // 这里只在收尾时做一次兜底记录；老接口在新系统上只是提示废弃，不影响运行。
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
                g_prevKey = app.keyWindow;
#pragma clang diagnostic pop
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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            UIWindow *w = app.keyWindow;
#pragma clang diagnostic pop
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
    // 界面库上下文就绪后再改接状态转移；未就绪时每次心跳重试（不早改，避免空上下文开帧）。
    if (g_found) aq_redirect_hidden_entry();
    // 覆盖窗口一出现，等 0.5 秒只做一次快照记录。
    // 绝对不能在后台队列里动窗口（上一版就是在这里从后台线程调用窗口置前，
    // 面板刚出来零点几秒后定时队列和主线程一起卡住，随后被系统结束）。
    if (g_found && aq_overlaySeen && !aq_overlayForced && aq_now() >= aq_overlaySeenAt + 0.5) {
        aq_overlayForced = YES;
        dispatch_async(dispatch_get_main_queue(), ^{
            aq_dump_windows(@"覆盖窗口出现后");
        });
    }
    // 4.5 秒还没见过覆盖窗口：把窗口构成记清楚，说明原版根本没走到创建。
    if (g_found && !aq_overlaySeen && !aq_panelMissingLogged && aq_now() >= 4.5) {
        aq_panelMissingLogged = YES;
        aq_add(@"[面板] 4.5 秒了仍未见覆盖窗口创建（原版没走到这一步）");
        dispatch_async(dispatch_get_main_queue(), ^{
            aq_dump_windows(@"未见覆盖窗口时");
        });
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
        dispatch_async(dispatch_get_main_queue(), ^{
            aq_dump_windows(@"28秒悬浮球复查");
            if (aq_ballView) {
                UIView *bv = (UIView *)aq_ballView;
                aq_add(@"[悬浮球] 28 秒复查 隐藏=%d 透明度=%.2f 父视图=%@",
                       (int)bv.isHidden, bv.alpha,
                       bv.superview ? NSStringFromClass([bv.superview class]) : @"无");
            }
            aq_copy();
        });
    }
    // 建面板的时机很关键：26 秒时游戏还在狂下资源（前面几次都是建完零点几秒进程就没了），
    // 所以等加载安静下来再建 —— 35 秒后连续 4 秒没有网络动作就动手，最晚拖到 70 秒。
    if (g_found && aq_ballBuilt && !aq_menuTried) {
        double quiet = aq_now() - g_lastNetAt;
        // 用户主动点过球时，35 秒一到就建（游戏主界面此时已加载完成），不再只等网络安静。
        BOOL due = (aq_now() >= 70.0) || (aq_now() >= 35.0 && quiet >= 4.0) ||
                   (aq_menuAsked && aq_now() >= 35.0);
        if (due) {
            aq_menuTried = YES;
            aq_add(@"[菜单] %.0f 秒：游戏已安静 %.1f 秒，开始自建面板", aq_now(), quiet);
            aq_build_menu();
        }
    }
    // 每 5 秒记一次存活：上一版日志停在 26 秒，但分不清是当场退出还是后面的显示动作才出事，
    // 有了这行就能从最后一条记录准确看出进程活到了第几秒。
    if (g_found) {
        static double nextAlive = 0;
        if (aq_now() >= nextAlive) {
            // 前 12 秒每秒一行，用来精确定位「加载界面闪退」停在哪个时刻；
            // 之后恢复 5 秒一行，避免日志太长。
            nextAlive = aq_now() + (aq_now() < 12.0 ? 1.0 : 5.0);
            aq_add(@"[存活] %.0f 秒 面板已建=%d 已绘制=%d 帧 补帧=%d 次 帧序号=%d 顶点=%d",
                   aq_now(), (int)aq_menuBuilt, aq_drawCount,
                   aq_fixCount, aq_fixFC, aq_fixVtx);
        }
    }
    // 菜单显示后每秒报一次存活和已绘制的帧数，闪退时能看出停在哪一帧。
    if (g_found && aq_menuShown && aq_now() - aq_menuShowAt <= 15.0) {
        static double nextLive = 0;
        if (aq_now() >= nextLive) {
            nextLive = aq_now() + 1.0;
            double t = aq_now() - aq_menuShowAt;
            dispatch_async(dispatch_get_main_queue(), ^{
                UIView *mv = (UIView *)aq_menuView;
                int hid = mv ? (int)mv.isHidden : -1;
                int winHid = aq_menuWindow ? (int)aq_menuWindow.hidden : -1;
                int key = aq_menuWindow ? (int)aq_menuWindow.isKeyWindow : -1;
                aq_add(@"[菜单] 显示后 %.1f 秒 仍存活，已绘制 %d 帧 画面隐藏=%d 窗口隐藏=%d 主窗口=%d",
                       t, aq_drawCount, hid, winHid, key);
                // 原版偶尔会在画完几帧后把画面（甚至承载窗口）重新藏起来，藏起来后
                // 就不再有新帧。这里每秒检查一次，发现被藏就再显示出来。
                // 原版覆盖窗口按设计保持隐藏（它不绘制且会挡触摸），这里不再把它重新显示。
                // 只读看一眼绘制通道；显示后 2.5 秒再尝试补建一次渲染器（只在缺席时）。
                aq_log_draw_channel("菜单状态", NO);
                if (t >= 2.5) aq_try_backend_init();
                // 2.5 秒这次顺便把所有窗口翻一遍，看有没有原版自己留着没显示的容器。
                static BOOL didScanWins = NO;
                if (t >= 2.5 && !didScanWins) {
                    didScanWins = YES;
                    aq_scan_extra_windows();
                }
                aq_copy();
            });
        }
    }
    // 主线程心跳：给主队列派一个小任务，看它多久没被处理。
    // 主线程被卡死时，剪贴板也刷不进去，只能把现场写进沙盒文件等下次启动读出来。
    if (g_found) {
        dispatch_async(dispatch_get_main_queue(), ^{ g_mainBeats += 1; });
        if (g_mainBeats != g_mainSeen) {
            g_mainSeen = g_mainBeats;
            g_lastMainMove = aq_now();
        } else if (aq_menuBuilt && !g_hangLogged && aq_now() > 6.0 && aq_now() - g_lastMainMove > 1.5) {
            g_hangLogged = YES;
            @try {
                NSString *path = g_crash_path[0] ? [NSString stringWithUTF8String:g_crash_path] : nil;
                if (path) {
                    char pcInfo[96] = {0};
                    aq_snap_main_pc(pcInfo, sizeof(pcInfo));
                    NSString *s = [NSString stringWithFormat:
                                   @"\n=== 上次运行主线程卡死 ===\n最后一步时间 %.1fs，卡住超过 1.5 秒%s\n",
                                   g_lastMainMove, pcInfo];
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
                NSString *tail = prev.length > 500
                               ? [prev substringFromIndex:prev.length - 500] : prev;
                [g_text appendFormat:@"=== 上次运行最后记录 ===\n%@\n", tail];
            }
        }
    } @catch (NSException *e) {
    }
    aq_add(@"处理代码已加载");
    aq_install_crash_capture();
    // 主线程的 mach 端口只能在主线程上取，这里尽早存下来（后台做卡死取样时要用）。
    dispatch_async(dispatch_get_main_queue(), ^{
        g_mainMachThread = pthread_mach_thread_np(pthread_self());
    });

    g_q = dispatch_queue_create("aqaw.fix", DISPATCH_QUEUE_SERIAL);
    g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, g_q);
    if (!g_timer) return;
    dispatch_source_set_timer(g_timer,
                              dispatch_time(DISPATCH_TIME_NOW, 100ull * NSEC_PER_MSEC),
                              100ull * NSEC_PER_MSEC,
                              20ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(g_timer, ^{ aq_tick(); });
    dispatch_resume(g_timer);

    // 兜底：万一后台搜索没跑起来或没命中，45 秒时也把同一份完整报告打出来。
    // 正常路径下搜索一结束就会提前触发，届时这里自动跳过。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 45ull * NSEC_PER_SEC),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        aq_final_report();
    });
}
