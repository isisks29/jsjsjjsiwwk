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
static id aq_menuA = nil;   // 菜单的两个配套对象，自己长期持有，避免初始化函数返回后被释放
static id aq_menuC = nil;
static BOOL aq_menuBuilt = NO;
static BOOL aq_menuTried = NO;
static BOOL aq_menuAsked = NO;       // 用户点过悬浮球、要求显示面板
static BOOL aq_menuVisible = NO;
static BOOL aq_menuShown = NO;       // 菜单是否已经正式显示
static BOOL aq_menuWanted = YES;     // 用户希望菜单开着还是关着（点悬浮球切换）
static double aq_menuShowAt = 0;     // 计划显示的时间点（先避开游戏加载期）
static BOOL aq_ballDiag2 = NO;
static UIWindow *aq_lastSceneWin = nil;   // 最近一个由原版构造函数内部建出来的覆盖窗口
static uint8_t aq_panelCfg[0x200];   // 悬浮球和菜单视图共用同一份配置

// 绘制与菜单回调的观察点：只记录，随后照原样调用。
static void (*aq_origDrawMTK)(id, SEL, id) = NULL;
static void (*aq_origDidMove)(id, SEL) = NULL;
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
            BOOL mine = (w == aq_menuWindow) || (aq_ballWindow && w == aq_ballWindow);
            UIView *root = w.rootViewController ? w.rootViewController.view : nil;
            aq_add(@"[窗口] 层级=%.0f 类=%@ 隐藏=%d 是自建=%d 根=%@ 子视图=%lu",
                   lvl, NSStringFromClass([w class]), (int)w.isHidden, (int)mine,
                   w.rootViewController ? NSStringFromClass([w.rootViewController class]) : @"无",
                   (unsigned long)w.subviews.count);
            if (mine) continue;
            if (root) {
                aq_dump_view_tree(root, [NSString stringWithFormat:@"[窗%.0f]", lvl], 0);
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

static void aq_hook_view_hidden(id self, SEL _cmd, BOOL hidden) {
    // 面板画面的可见性由这份处理代码按用户意愿决定：实测原版每画一帧都会把
    // 画面重新藏起来（调用点固定在库内 0x913768）。用户要让菜单开着时，
    // 这里只放行「显示」、把「隐藏」拦下；只影响这个画面自己的隐藏位，
    // 不碰窗口、不碰游戏。
    if (hidden && self == aq_menuView) {
        aq_probe_state_frame();
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
    if (aq_origViewHidden) aq_origViewHidden(self, _cmd, hidden);
}

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

// 把配置前 32 字节原样打出来：原版每帧到底改哪几个字节，一看就知道。
static void aq_log_cfg(const char *tag, int frame) {
    uint8_t *p = aq_panelCfg;
    aq_add(@"[配置] %s 帧=%d %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X"
           @" %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
           tag, frame,
           p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
           p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
           p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23],
           p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31]);
}

// 配置的 0x20~0x7F 段：点悬浮球前后各打一次，看开关是否写在更靠后的位置。
static void aq_log_cfg_wide(const char *tag, int frame) {
    uint8_t *p = aq_panelCfg;
    for (int base = 0x20; base < 0x80; base += 16) {
        aq_add(@"[配置全量] %s 帧=%d +%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
               tag, frame, base,
               p[base + 0], p[base + 1], p[base + 2], p[base + 3],
               p[base + 4], p[base + 5], p[base + 6], p[base + 7],
               p[base + 8], p[base + 9], p[base + 10], p[base + 11],
               p[base + 12], p[base + 13], p[base + 14], p[base + 15]);
    }
}

// 只读查看菜单视图自己的字段：哪个字段在「关闭/打开」之间变化，就是原版真正
// 维护的开关。只打印名字和值，不改任何东西；读失败就跳过，不影响程序。
static void aq_dump_menu_ivars(const char *tag) {
    id mv = aq_menuView;
    if (!mv) return;
    unsigned int n = 0;
    Ivar *ivs = class_copyIvarList([mv class], &n);
    if (!ivs) { aq_add(@"[菜单] %s 字段: 读不到", tag); return; }
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
    aq_add(@"[菜单] %s 字段: %@", tag, m);
}

// 界面库把「这一帧要画什么」放在上下文里的一个数据块中。这个块的特征是
// 前面几个小整数依次是「列表数 / 索引数 / 顶点数」，随后是列表指针和显示尺寸。
// 这里只在上下文自身那一块内存里按这个特征找一遍：能找到有内容的，就说明画面
// 已经生成、只差提交；一个都找不到，就说明界面内容根本没构建出来。
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
    size_t limit = (size_t)malloc_size(ctx);
    if (limit < 0x200) limit = 0x3000;
    if (limit > 0x80000) limit = 0x80000;
    int hits = 0;
    for (size_t off = 0; off + 48 <= limit && hits < 8; off += 8) {
        const unsigned char *p = (const unsigned char *)ctx + off;
        int lists = *(const int *)(p + 4);
        int idx = *(const int *)(p + 8);
        int vtx = *(const int *)(p + 12);
        if (lists < 1 || lists > 512) continue;
        if (idx < 0 || idx > 20000000) continue;
        if (vtx < 0 || vtx > 20000000) continue;
        const void *cl = *(const void *const *)(p + 16);
        uintptr_t clp = (uintptr_t)cl;
        if (clp < 0x100000000ULL || clp > 0x1FF000000ULL) continue;
        float dx = *(const float *)(p + 32);
        float dy = *(const float *)(p + 36);
        aq_add(@"[画面数据] %s 上下文+0x%lx 列表=%d 索引=%d 顶点=%d 尺寸=%.1fx%.1f",
               tag, (unsigned long)off, lists, idx, vtx, dx, dy);
        hits++;
    }
    if (hits == 0) aq_add(@"[画面数据] %s 上下文里一块可提交的画面数据都没有", tag);
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
        aq_add(@"[绘制通道] 渲染器已在（%p），不用补建", backend);
        return;
    }
    if (!ctx) {
        aq_add(@"[绘制通道] 界面上下文还不存在，先不补建渲染器");
        return;
    }
    SEL s = NSSelectorFromString(@"device");
    if (![aq_menuView respondsToSelector:s]) return;
    __unsafe_unretained id dev = ((id (*)(id, SEL))objc_msgSend)(aq_menuView, s);
    if (!dev) {
        aq_add(@"[绘制通道] 视图还没有设备，先不补建渲染器");
        return;
    }
    BOOL ok = ((BOOL (*)(id))(g_slide + 0x83DEE8))(dev);
    backend = *(void **)(g_slide + 0x1640D08);
    aq_add(@"[绘制通道] 已补建渲染器 结果=%d 渲染器=%p 设备=%@",
           (int)ok, backend, NSStringFromClass([dev class]));
}

// 面板状态单例：原版把「能不能画」这类开关放在这个共享实例里。
// 这里只读一遍它的属性值，用来判断到底哪个开关还关着；一个字节都不改。
static void aq_dump_state_singleton(const char *tag) {
    Class S = NSClassFromString(@"_0xA7F3B2E9");
    if (!S) { aq_add(@"[状态] 面板状态类不在（%s）", tag); return; }
    SEL si = NSSelectorFromString(@"sharedInstance");
    if (![S respondsToSelector:si]) { aq_add(@"[状态] 没有共享入口（%s）", tag); return; }
    id obj = ((id (*)(id, SEL))objc_msgSend)(S, si);
    if (!obj) { aq_add(@"[状态] 共享实例为空（%s）", tag); return; }
    unsigned int n = 0;
    Method *ms = class_copyMethodList([obj class], &n);
    if (!ms) { aq_add(@"[状态] 读不到方法列表（%s）", tag); return; }
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
    aq_add(@"[状态] %s 面板状态: %@", tag, s);
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

// 界面库把「这一帧到底画了多少个顶点」记在上下文里的固定位置。这里只读，
// 用来判断补跑某一步之后画面内容到底有没有真的生成。
static int aq_vtx_count(void) {
    if (!g_slide) return -1;
    void *ctx = *(void **)(g_slide + 0x1644470);
    if (!ctx) return -1;
    // 画面数据本体在上下文 +0x3DF0：列表数@+4、索引数@+8、顶点数@+12、列表指针@+16。
    // 旧代码读 +0xB0，那是另一个结构，正是「帧在涨、顶点却永远 0」误判的根源。
    if (malloc_size(ctx) > 0x3E10) {
        const unsigned char *p = (const unsigned char *)ctx + 0x3DF0;
        int lists = *(const int *)(p + 4);
        int vtx = *(const int *)(p + 12);
        uintptr_t clp = (uintptr_t)*(const void *const *)(p + 16);
        if (lists >= 1 && lists <= 512 && vtx >= 0 && vtx <= 20000000 &&
            clp >= 0x100000000ULL && clp <= 0x1FF000000ULL)
            return vtx;
    }
    // 兜底：上下文还没稳定时按旧位置再读一次，读不到就如实返回 -1。
    const unsigned char *p = (const unsigned char *)ctx + 0xb0;
    int lists = *(const int *)(p + 4);
    int vtx = *(const int *)(p + 12);
    if (lists < 0 || lists > 4096) return -1;
    if (vtx < 0 || vtx > 20000000) return -1;
    return vtx;
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

static void aq_drive_frame(int frameNo) {
    if (!g_slide) return;
    void *ctx = *(void **)(g_slide + 0x1644470);
    if (!ctx) return;
    // 后台时整条构建链也不动：没有开帧还去建内容，等于把界面库往坏状态里推。
    if (!aq_is_foreground()) return;
    // 第一步：替原版开帧。之前是空的，所以后面建出来的内容没有归属。
    aq_open_frame_once(frameNo);
    aq_fixCount++;
    aq_fixFC = *(const int *)((const char *)ctx + 0x3da8);
    int vtxBefore = aq_vtx_count();
    id backend = aq_find_ivar_obj(aq_menuView, "0xB1D7F3A9");
    if (!backend) {
        if (frameNo <= 3) aq_add(@"[补齐] 第 %d 帧没找到绘制对象", frameNo);
    } else {
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
            if (frameNo <= 3 || frameNo % 300 == 0)
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
                if (frameNo <= 3 || frameNo % 300 == 0)
                    aq_add(@"[三步] 第 %d 帧 m%d 后顶点=%d", frameNo, k, aq_vtx_count());
            }
        }
    }
    int vtxBuilt = aq_vtx_count();
    // 第三步：构建完就立刻替原版生成画面数据。原版绘制若提前返回，这一步就没人做，
    // 内容会一直停在「建好了但没变成画面」的状态。
    aq_close_frame_once(frameNo);
    aq_fixVtx = aq_vtx_count();
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
    }
    // 先把「开始这一帧 + 构建界面内容」替原版补上，再让它自己走一遍绘制流程；
    // 这样它内部的「提交」就能把刚构建好的界面内容一起送出去。
    if (mine) aq_drive_frame(n);
    @try {
        // 原版绘制实现住在签名代码页里。那一页一旦被系统判定无效，再执行就会把整个
        // 进程带走（之前两次闪退都停在这页的 0x908204）。先确认页还带执行位；不带就
        // 只记录、不调用——宁可不画，也不让游戏跟着退出。
        int pageExec = aq_code_page_exec_state();
        if (mine && n == 1) aq_probe_code_page("首帧绘制前");
        if (pageExec == 0) {
            static int skipLogged = 0;
            if (mine && skipLogged < 3) {
                skipLogged++;
                aq_add(@"[绘制] 第 %d 帧跳过：绘制实现所在代码页已不可执行", n);
            }
        } else if (aq_origDrawMTK) {
            double tDraw = aq_now();
            aq_origDrawMTK(self, _cmd, view);
            if (mine && n <= 3)
                aq_add(@"[绘制] 原版绘制已返回 第 %d 帧 耗时=%.3f 秒", n, aq_now() - tDraw);
        }
    } @catch (NSException *e) {
        if (mine && !aq_drawExcLogged) {
            aq_drawExcLogged = YES;
            aq_add(@"[绘制] 抛异常: %@ / %@", e.name ?: @"?", e.reason ?: @"?");
        }
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

#define AQ_M_HOOK(NUM)                                                        \
    static void aq_hook_m##NUM(id self, SEL _cmd) {                           \
        aq_mCalls[NUM]++;                                                     \
        if (aq_mCalls[NUM] <= 5) {                                            \
            aq_add(@"[回调] m%d 被调用 t=%.2f", NUM, aq_now());               \
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
        // 这个类的初始化只保留了宽高，原点会被重置成 (0,0)；这里按右上角的位置再摆一次。
        ((UIView *)ball).frame = f;
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
        aq_add(@"[菜单] 已执行原版悬浮球点击处理（%s，第 %d 次）", why, aq_origClicks);
    } @catch (NSException *e) {
        aq_add(@"[菜单] 原版点击处理抛异常: %@", e.reason ?: @"?");
    }
    aq_data_diff_end("点击后");
    aq_log_cfg("点击后", aq_drawCount);
    aq_log_cfg_wide("点击后", aq_drawCount);
    aq_dump_menu_ivars("点击后");
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
    aq_menuWanted = YES;
    aq_menuVisible = YES;
    if (aq_origClicks == 0) aq_call_original_click("用户点悬浮球");
    if (aq_menuView) ((UIView *)aq_menuView).hidden = NO;
    aq_repaint_menu();
    aq_add(@"[菜单] 已显示（开关=%d）", (int)aq_panelCfg[0]);
    aq_copy();
}

static void aq_build_menu_main(void) {
    @try {
        aq_probe_code_page("建面板前");
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
        aq_menuVisible = YES;
        aq_menuWanted = YES;
        aq_menuShown = YES;
        aq_menuShowAt = aq_now();
        aq_panelCfg[0] = 1;
        w.hidden = NO;
        aq_add(@"[菜单] 已创建 结果=%p 尺寸=%.0fx%.0f 承载=%@，直接显示",
               menu, scr.size.width, scr.size.height,
               hostedByOriginal ? @"原版窗口" : @"自建窗口");
        aq_dump_view_tree(menu, @"[菜单]", 0);
        aq_dump_menu_ivars("建好后");
        aq_dump_state_singleton("建好后");
        aq_dump_windows(@"自建菜单后");
        aq_adopt_ball_into_menu_window();
        // 只在同一窗口里放一个小红块：如果屏幕上能看到它，说明这个窗口本身
        // 能正常显示，面板看不见就不是窗口的问题；看不到它则相反。
        @try {
            UIView *host = w.rootViewController.view ?: ((UIView *)menu).superview;
            UIView *marker = [[UIView alloc] initWithFrame:CGRectMake(6, 6, 96, 96)];
            marker.backgroundColor = [UIColor colorWithRed:1.0 green:0.0 blue:0.0 alpha:0.85];
            marker.userInteractionEnabled = NO;
            [host addSubview:marker];
            aq_add(@"[菜单] 已在同一窗口左上角放了 96x96 红色标记（只用来确认窗口能否显示）");
        } @catch (NSException *e) {
        }
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
                    aq_dump_view_tree(aq_menuWindow.rootViewController.view, @"[菜单窗]", 0);
            } @catch (NSException *e) {
                aq_add(@"[菜单] 3 秒窗口复查失败: %@", e.reason ?: @"?");
            }
        });
        // 5 秒后自动替用户「点一次球」，用原版自己的入口试着把面板打开。
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            aq_call_original_click("自动试开");
            aq_repaint_menu();
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
                if (aq_menuWindow && aq_menuWindow.hidden) {
                    aq_menuWindow.hidden = NO;
                    aq_add(@"[菜单] 承载窗口被藏起来了，已重新显示（层级 %.0f）",
                           aq_menuWindow.windowLevel);
                }
                if (mv && mv.isHidden && aq_menuWanted) {
                    mv.hidden = NO;
                    aq_add(@"[菜单] 画面又被藏起来了，已重新显示");
                }
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
                NSString *tail = prev.length > 2000
                               ? [prev substringFromIndex:prev.length - 2000] : prev;
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
}
