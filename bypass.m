
#define ACE_TRACE 1   // 必须保持 1

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <stdio.h>
#import <math.h>
#import <signal.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <Security/Security.h>
#import <pthread.h>

// ══════════════ 第 0 层：隐身（对靶场的 dyld/调试探测不可见）══════════════
typedef void (*ACEAddImageFn)(const struct mach_header *mh, intptr_t vmaddr_slide);

static const struct mach_header *ACE_self_header(void) {
    Dl_info info;
    if (dladdr((const void *)&ACE_self_header, &info))
        return (const struct mach_header *)info.dli_fbase;
    return NULL;
}
static int g_our_index = -1;
static int ACE_find_our_index(void) {
    if (g_our_index >= 0) return g_our_index;
    const struct mach_header *self = ACE_self_header();
    if (!self) return -1;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++)
        if (_dyld_get_image_header(i) == self) { g_our_index = (int)i; return g_our_index; }
    return -1;
}
static uint32_t ACE_image_count(void) {
    return (uint32_t)((int)_dyld_image_count() - (ACE_find_our_index() >= 0 ? 1 : 0));
}
static const char *ACE_image_name(uint32_t i) {
    int o = ACE_find_our_index();
    return _dyld_get_image_name((o >= 0 && i >= (uint32_t)o) ? i + 1 : i);
}
static const struct mach_header *ACE_image_header(uint32_t i) {
    int o = ACE_find_our_index();
    return _dyld_get_image_header((o >= 0 && i >= (uint32_t)o) ? i + 1 : i);
}
static ACEAddImageFn g_watch_cb = NULL;
static void ACE_watch_wrapper(const struct mach_header *mh, intptr_t slide) {
    if (!g_watch_cb) return;
    // v7.10: 自己的镜像绝不转发。旧版换成 image0 的头配我们的 slide 转发,
    // 靶场解密引擎(pm_poolmin_prepare)拿到错配组合算出野指针 → 启动随机 SIGSEGV
    if (mh && mh == ACE_self_header()) return;
    g_watch_cb(mh, slide);
}
static void ACE_register_add_image(ACEAddImageFn f) {
    g_watch_cb = f;
    _dyld_register_func_for_add_image(ACE_watch_wrapper);
}
static int g_hit_tt = 0, g_hit_tsep = 0, g_hit_exit = 0, g_hit_abort = 0;
static kern_return_t ACE_task_threads(mach_port_t t, thread_act_array_t *a, mach_msg_type_number_t *c) {
    g_hit_tt++;
    if (a) *a = NULL; if (c) *c = 0; return KERN_SUCCESS;
}
static kern_return_t ACE_task_set_exception_ports(mach_port_t t, exception_mask_t m,
        exception_handler_t h, exception_behavior_t b, thread_state_flavor_t f) {
    g_hit_tsep++;   // 计数: 验证隐身层真实生效(靶场异常端口接管被挡次数)
    return KERN_SUCCESS;
}

static void ACE_exit(int code) { g_hit_exit++; (void)code; for (;;) sleep(86400); }
static void ACE_abort(void) { g_hit_abort++; for (;;) sleep(86400); }
// ══════════════ 第 0.5 层：观测日志（存内存，悬浮按钮导出）══════════════
static NSMutableArray *g_logbuf = NULL;
static int g_trace_lines = 0;
static int g_ace_busy = 0;
static int g_ace_ready = 0;

static void ACETraceLine(NSString *line) {
    if (g_trace_lines > 20000) return; // 总量封顶
    g_trace_lines++;
    @autoreleasepool { NSLog(@"%@", line); }
    @synchronized ([NSMutableArray class]) {
        if (!g_logbuf) g_logbuf = [[NSMutableArray alloc] init];
        [g_logbuf addObject:line];
    }
}
#define ACETrace(fmt, ...) ACETraceLine([NSString stringWithFormat:(@"[ace] " fmt), ##__VA_ARGS__])
// v7.13 前置声明(nanosleep 探针提前引用; 定义在下方原位置)
static uintptr_t g_tgt_base, g_tgt_end;
static uintptr_t g_self_base;
static int g_ace_ready, g_ace_busy;
static int g_hit_nsl = 0;
static int ACE_nanosleep(const struct timespec *rqtp, struct timespec *rmtp) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    int from_tgt = (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end);
    int from_self = (g_self_base && ra >= g_self_base);
    if (from_tgt && !from_self && g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1; g_hit_nsl++;
        long sec = rqtp ? (long)rqtp->tv_sec : -1;
        long nsec = rqtp ? rqtp->tv_nsec : -1;
        ACETrace(@"[wd] nanosleep(%ld.%09ld) caller=TGT+0x%lx", sec, nsec,
                 (unsigned long)(ra - g_tgt_base));
        g_ace_busy = 0;
    }
    return nanosleep(rqtp, rmtp);   // interpose 不影响本镜像内部调用, 这里直达真身
}
static NSString *ACELogDump(void) {
    NSMutableArray *snap = nil;
    @synchronized ([NSMutableArray class]) { snap = [g_logbuf mutableCopy]; }
    if (!snap || ![snap count]) return @"(暂无日志)";
    NSString *head = [NSString stringWithFormat:@"=== ace 日志 · %lu 行 ===\n", (unsigned long)[snap count]];
    return [head stringByAppendingString:[snap componentsJoinedByString:@"\n"]];
}
#define ACE_G(...) do { if (g_ace_ready && !g_ace_busy) { g_ace_busy = 1; @try { ACETrace(__VA_ARGS__); } @catch (NSException *e) {} g_ace_busy = 0; } } while (0)
static NSString *ACETrimStr(id obj, NSUInteger n) {
    if (!obj) return @"(nil)";
    NSString *s = [obj description];
    if ([s length] > n) s = [s substringToIndex:n];
    return s;
}

#define ACE_INTERPOSE(rep, orig) \
    const struct { const void *r, *o; } _ace_ip_##orig \
    __attribute__((used, section("__DATA,__interpose"))) = { (const void *)(rep), (const void *)(orig) };

ACE_INTERPOSE(ACE_register_add_image,   _dyld_register_func_for_add_image)
ACE_INTERPOSE(ACE_image_count,          _dyld_image_count)
ACE_INTERPOSE(ACE_image_name,           _dyld_get_image_name)
ACE_INTERPOSE(ACE_image_header,         _dyld_get_image_header)
ACE_INTERPOSE(ACE_task_threads,         task_threads)
ACE_INTERPOSE(ACE_task_set_exception_ports, task_set_exception_ports)
ACE_INTERPOSE(ACE_exit,                 exit)
ACE_INTERPOSE(ACE_abort,                abort)
ACE_INTERPOSE(ACE_nanosleep,            nanosleep)

// ══════════════ 第 0.6 层：验卡结果改写（作业主机制）══════════════
typedef struct {
    uint32_t cmd, cmdsize;
} ACELoadCmdHdr;
typedef struct {
    uint32_t cmd, cmdsize;
    char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
} ACESegCmd64;
typedef struct {
    char sectname[16], segname[16];
    uint64_t addr, size;
    uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3;
} ACESect64;
typedef struct { uint32_t n_strx; uint8_t n_type; uint8_t n_sect; uint16_t n_desc; uint64_t n_value; } ACENlist64;

static uintptr_t g_tgt_base = 0, g_tgt_end = 0;
static void *g_saved_slot_val = NULL;
static int g_rw_dialog = 0, g_rw_boot = 0;
// ═══ v7.4 新增①: EndTime 补喂 ═══
// 实证: 靶场有时间跳变/过期检测, 自毁走【裸 svc exit_group(9)+brk】(0xc2e2c 等),
// libc exit/abort interpose 拦不住。无服务器配置时 ctx+0x78(EndTime double)=0
// → "授权成功(到期1970)" 弹出瞬间被判过期 → 秒杀。
// 修复: 结果改写时把过期/空的 EndTime 补成 2100-01-01(只动 < now+1天 的值, 真卡不碰)。
static void ACE_prime_endtime(void) {
    @try {
        if (!g_tgt_base) return;
        uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff698);   // 全局 ctx 指针(实证)
        if (ctx < 0x100000000ULL) return;                        // 未建/异常则跳过
        double *endp = (double *)(ctx + 0x78);                   // 成功弹窗到期时间就读它(实证)
        double now = (double)time(NULL);
        if (*endp < now + 86400.0) {
            ACETrace(@"[prime] EndTime %.0f → 4102444800 (2100-01-01, 避开时间检测裸svc自毁)", *endp);
            *endp = 4102444800.0;
        }
    } @catch (NSException *e) {}
}

// ═══ v7.4 新增②: 自带崩溃现场捕捉器（解决"系统里找不到崩溃日志"）═══
// 靶场接管过 mach 异常端口且自毁走裸 svc, 系统崩溃报告基本无望。
// 自己装 BSD 信号处理器: 崩溃瞬间把 信号/PC/靶场内偏移/自身内偏移/出错地址
// 用 write(2)(async-signal-safe) 写进 Documents/ace_crash.txt, 下次启动读进悬浮日志。
static int g_crashfd = -1;
static uintptr_t g_self_base = 0;
static void ace_hex16(char *d, uint64_t v) {   // 16位十六进制, 信号安全
    const char *hd = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) { d[i] = hd[v & 0xf]; v >>= 4; }
}
static void ACE_crash_handler(int sig, siginfo_t *info, void *uctx) {
    if (g_crashfd >= 0) {
        ucontext_t *uc = (ucontext_t *)uctx;
        uintptr_t pc = 0;
#if defined(__arm64__) || defined(__aarch64__)
        if (uc && uc->uc_mcontext) pc = (uintptr_t)uc->uc_mcontext->__ss.__pc;
#endif
        uintptr_t fa = (uintptr_t)info->si_addr;
        char buf[224]; int n = 0;
        const char *p1 = "SIG="; memcpy(buf+n, p1, 4); n+=4;
        buf[n++] = (char)('0' + (sig/10)%10); buf[n++] = (char)('0' + sig%10);
        const char *p2 = " PC="; memcpy(buf+n, p2, 4); n+=4;
        ace_hex16(buf+n, pc); n+=16;
        const char *p3 = " TGT+="; memcpy(buf+n, p3, 6); n+=6;
        ace_hex16(buf+n, (g_tgt_base && pc>=g_tgt_base && pc<g_tgt_end) ? pc-g_tgt_base : 0); n+=16;
        const char *p4 = " SELF+="; memcpy(buf+n, p4, 7); n+=7;
        ace_hex16(buf+n, (g_self_base && pc>=g_self_base) ? pc-g_self_base : 0); n+=16;
        const char *p5 = " FAULT="; memcpy(buf+n, p5, 7); n+=7;
        ace_hex16(buf+n, fa); n+=16;
        buf[n++] = '\n';
        write(g_crashfd, buf, (size_t)n);
        fsync(g_crashfd);
    }
    signal(sig, SIG_DFL);   // 恢复默认处置, 不改变崩溃行为本身
}
static NSString *ACE_crash_path(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_crash.txt"];
}
static UIViewController *ACE_topVC(void);   // 前置声明(定义在悬浮按钮段)
static void ACE_report_last_crash(void) {
    @try {
        NSData *d = [NSData dataWithContentsOfFile:ACE_crash_path()];
        if (d && [d length]) {
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (!s) s = @"(解析失败)";
            ACETrace(@"上次崩溃现场: %@", s);
            [UIPasteboard generalPasteboard].string =
                [NSString stringWithFormat:@"[ace崩溃现场]\n%@", s];
            dispatch_after(dispatch_time(0, 300000000), dispatch_get_main_queue(), ^{
                @try {
                    NSString *body = [s length] > 500 ? [s substringToIndex:500] : s;
                    UIAlertController *a = [UIAlertController
                        alertControllerWithTitle:@"上次崩溃现场(已复制到剪贴板)"
                        message:body preferredStyle:UIAlertControllerStyleAlert];
                    [a addAction:[UIAlertAction actionWithTitle:@"知道了"
                        style:UIAlertActionStyleDefault handler:nil]];
                    UIViewController *host = ACE_topVC();
                    if (host) [host presentViewController:a animated:YES completion:nil];
                } @catch (NSException *e3) {}
            });
        } else {
            ACETrace(@"上次崩溃文件为空: 若上次确实闪退, 说明是【裸svc exit_group】类不可捕获自毁");
        }
        NSData *ld3 = [NSData dataWithContentsOfFile:
            [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_log.txt"]];
        if (ld3 && [ld3 length]) {
            NSString *ls = [[NSString alloc] initWithData:ld3 encoding:NSUTF8StringEncoding];
            if (ls) {
                NSUInteger L = [ls length];
                NSString *tail = (L > 2600) ? [ls substringFromIndex:L - 2600] : ls;
                ACETrace(@"===== 上次运行最后日志(心跳落盘, 末尾=死前瞬间) =====\n%@", tail);
                [UIPasteboard generalPasteboard].string =
                    [NSString stringWithFormat:@"[ace死前日志尾]\n%@", tail];
            }
        }
        NSData *td2 = [NSData dataWithContentsOfFile:
            [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_trace.txt"]];
        if (td2 && [td2 length]) {
            NSString *ts = [[NSString alloc] initWithData:td2 encoding:NSUTF8StringEncoding];
            if (ts) {
                ACETrace(@"上次死前线程指纹(靶场内偏移):\n%@", ts);
                [UIPasteboard generalPasteboard].string =
                    [NSString stringWithFormat:@"[ace死前指纹]\n%@", ts];
            }
        }
    } @catch (NSException *e) {}
}
static void ACE_install_crash_catcher(void) {
    @try {
        g_self_base = (uintptr_t)ACE_self_header();
        struct stat fsb;
        int oflags = O_CREAT | O_WRONLY | ((stat(ACE_crash_path().fileSystemRepresentation, &fsb) == 0
                                            && fsb.st_size < 4096) ? O_APPEND : O_TRUNC);
        g_crashfd = open(ACE_crash_path().fileSystemRepresentation, oflags, 0644);
        static stack_t ss;                 // 备用信号栈(栈溢出时也能记)
        static char altbuf[128 * 1024];
        ss.ss_sp = altbuf; ss.ss_size = sizeof(altbuf); ss.ss_flags = 0;
        sigaltstack(&ss, NULL);
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = ACE_crash_handler;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS,  &sa, NULL);
        sigaction(SIGILL,  &sa, NULL);
        sigaction(SIGTRAP, &sa, NULL);   // brk #1 = SIGTRAP, 靶场自毁点全覆盖
        sigaction(SIGABRT, &sa, NULL);
        ACETrace(@"崩溃捕捉器已装 fd=%d (SIGSEGV/BUS/ILL/TRAP/ABRT)", g_crashfd);
    } @catch (NSException *e) { ACETrace(@"崩溃捕捉器安装失败: %@", e); }
}
// ═══ v7.8: Mach 异常层捕捉(BSD 信号的前一层) ═══
// 实证: 靶场 13 处自毁 = svc exit_group(9); brk #1 成对。svc 不可拦截,
// 但 brk 先变成 EXC_BREAKPOINT mach 异常 → 记录 PC 后跳过 brk 继续运行。
#ifndef EXC_BREAKPOINT
#define EXC_BAD_ACCESS 1
#define EXC_BAD_INSTRUCTION 2
#define EXC_BREAKPOINT 6
#define EXC_MASK_BAD_ACCESS (1u << 1)
#define EXC_MASK_BAD_INSTRUCTION (1u << 2)
#define EXC_MASK_BREAKPOINT (1u << 6)
#define EXCEPTION_DEFAULT 1
#endif
#ifndef MACH_RCV_MSG
#define MACH_RCV_MSG 2
#define MACH_RCV_TIMEOUT 0x10
#define MACH_SEND_MSG 1
#define MACH_MSG_TYPE_MOVE_SEND_ONCE 18
#define MACH_MSG_TYPE_MAKE_SEND 20
#define MACH_MSGH_BITS(r, l) ((r) | ((l) << 8))
#endif
#define ACE_ARM64_STATE 6     /* ARM_THREAD_STATE64 */
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
    unsigned int pad[96];
} ACEExcReq;
typedef struct {
    mach_msg_header_t head;
    NDR_record_t NDR;
    kern_return_t retCode;
} ACEExcReply;
static mach_port_t g_exc_port = 0;
static int g_exc_skip = 0;
static void *ACE_exc_server(void *arg) {
    (void)arg;
    for (;;) {
        ACEExcReq req;
        memset(&req, 0, sizeof(req));
        kern_return_t kr = mach_msg(&req.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                0, sizeof(req), g_exc_port, 1000, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) continue;
        if (req.head.msgh_id != 2401 /*exception_raise*/) continue;
        unsigned long long st[34];
        memset(st, 0, sizeof(st));
        mach_msg_type_number_t cnt = 68;
        kern_return_t gs = thread_get_state(req.thread.name, ACE_ARM64_STATE,
                                            (thread_state_t)st, &cnt);
        unsigned long long pc = (gs == 0 && cnt >= 66) ? st[32] : 0;
        if (g_crashfd >= 0) {
            char b[320]; int n = 0;
            const char *p = "EXC="; memcpy(b + n, p, 4); n += 4;
            b[n++] = (char)('0' + (req.exception / 10) % 10);
            b[n++] = (char)('0' + req.exception % 10);
            p = " CODE0="; memcpy(b + n, p, 7); n += 7;
            ace_hex16(b + n, (unsigned long long)req.code[0]); n += 16;
            p = " THREAD="; memcpy(b + n, p, 8); n += 8;
            ace_hex16(b + n, req.thread.name); n += 16;
            p = " PC="; memcpy(b + n, p, 4); n += 4; ace_hex16(b + n, pc); n += 16;
            p = " TGT+="; memcpy(b + n, p, 6); n += 6;
            ace_hex16(b + n, (g_tgt_base && pc >= g_tgt_base && pc < g_tgt_end)
                               ? pc - g_tgt_base : 0); n += 16;
            unsigned long long lr = (gs == 0 && cnt >= 66) ? st[30] : 0;
            p = " LR_TGT+="; memcpy(b + n, p, 10); n += 10;
            ace_hex16(b + n, (g_tgt_base && lr >= g_tgt_base && lr < g_tgt_end)
                               ? lr - g_tgt_base : 0); n += 16;
            b[n++] = '\n';
            write(g_crashfd, b, (size_t)n); fsync(g_crashfd);
        }
        ACEExcReply rep;
        memset(&rep, 0, sizeof(rep));
        rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        rep.head.msgh_remote_port = req.head.msgh_local_port;
        rep.head.msgh_local_port = MACH_PORT_NULL;
        rep.head.msgh_id = 2501;
        rep.NDR = NDR_record;
        if (req.exception == EXC_BREAKPOINT && pc && g_exc_skip < 64) {
            st[32] = pc + 4;   // 跳过 brk, 拆掉自毁
            cnt = 68;
            g_exc_skip++;
            thread_set_state(req.thread.name, ACE_ARM64_STATE, (thread_state_t)st, cnt);
            rep.retCode = KERN_SUCCESS;
        } else {
            rep.retCode = KERN_FAILURE;   // 交回常规崩溃流程(信号层还有捕捉器兜底)
        }
        mach_msg(&rep.head, MACH_SEND_MSG, sizeof(rep), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    }
    return NULL;
}
typedef kern_return_t (*ACE_tsep_fn)(mach_port_t, exception_mask_t, exception_handler_t,
                                     exception_behavior_t, thread_state_flavor_t);

static void ACE_install_exc_server(void) {
    // task_set_exception_ports 被我们自己的 interpose 拦着, 必须 dlsym(RTLD_NEXT) 拿真身注册
    ACE_tsep_fn real_tsep = (ACE_tsep_fn)dlsym(RTLD_NEXT, "task_set_exception_ports");
    if (!real_tsep) { ACETrace(@"真实 task_set_exception_ports 未找到"); return; }
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port);
    if (kr != KERN_SUCCESS) { ACETrace(@"异常端口分配失败 kr=%d", kr); return; }
    mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND);
    kr = real_tsep(mach_task_self(),
            EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT,
            g_exc_port, EXCEPTION_DEFAULT, ACE_ARM64_STATE);
    if (kr != KERN_SUCCESS) { ACETrace(@"异常端口注册失败 kr=%d", kr); return; }
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &at, ACE_exc_server, NULL);
    pthread_attr_destroy(&at);
    ACETrace(@"Mach异常捕捉层已装 port=%u (brk自毁点将被跳过)", (unsigned)g_exc_port);
}
// v7.9 飞行记录器环形缓冲(心跳线程要用, 先前置声明)
static char g_ring[8][240];
static volatile int g_ring_i = 0, g_ring_n = 0;
// 静默死亡/主线程卡死时悬浮按钮点不到, 心跳文件保留死前最后一秒完整日志。
static void *ACE_heartbeat(void *arg) {
    (void)arg;
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_log.txt"];
    for (;;) {
        sleep(1);
        @autoreleasepool {
            NSString *dump = ACELogDump();
            if (dump) [dump writeToFile:p atomically:NO encoding:NSUTF8StringEncoding error:NULL];
            NSMutableString *tr = [NSMutableString string];
            int start = (g_ring_i - g_ring_n + 8) & 7;
            for (int k = 0; k < g_ring_n; k++) {
                [tr appendString:[NSString stringWithUTF8String:g_ring[(start + k) & 7]]];
                [tr appendString:@"\n"];
            }
            NSString *tp = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_trace.txt"];
            [tr writeToFile:tp atomically:NO encoding:NSUTF8StringEncoding error:NULL];
        }
    }
    return NULL;
}
static void ACE_install_heartbeat(void) {
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &at, ACE_heartbeat, NULL);
    pthread_attr_destroy(&at);
}
// ═══ v7.9: 飞行记录器——每150ms采样全线程PC, 只记靶场范围内偏移 ═══
// 静默死亡(裸svc exit_group/SIGKILL)无异常无信号可捕; 死前最后一拍采样
// = 凶手检测函数的指纹。环形8拍, 心跳线程每秒落盘 Documents/ace_trace.txt。
typedef kern_return_t (*ACE_tt_fn)(mach_port_t, thread_act_array_t *, mach_msg_type_number_t *);
static void *ACE_flight_recorder(void *arg) {
    (void)arg;
    ACE_tt_fn real_tt = (ACE_tt_fn)dlsym(RTLD_NEXT, "task_threads");   // 绕过自家 interpose
    if (!real_tt) return NULL;
    for (;;) {
        usleep(150000);
        if (!g_tgt_base) continue;
        thread_act_array_t list = NULL;
        mach_msg_type_number_t n = 0;
        if (real_tt(mach_task_self(), &list, &n) != KERN_SUCCESS || !list) continue;
        char line[240]; int p = 0;
        memcpy(line, "PC:", 3); p = 3;
        for (unsigned i = 0; i < n && p < 200; i++) {
            unsigned long long stt[34];
            memset(stt, 0, sizeof(stt));
            mach_msg_type_number_t c = 68;
            if (thread_get_state(list[i], ACE_ARM64_STATE, (thread_state_t)stt, &c) == 0 && c >= 66) {
                unsigned long long pc = stt[32];
                if (pc >= g_tgt_base && pc < g_tgt_end) {
                    static const char *hd = "0123456789abcdef";
                    unsigned long long off = pc - g_tgt_base;
                    line[p++] = ' ';
                    for (int k = 28; k >= 0; k -= 4) line[p++] = hd[(off >> k) & 0xf];
                }
            }
        }
        line[p] = 0;
        vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(mach_port_t));
        strcpy(g_ring[g_ring_i], line);
        g_ring_i = (g_ring_i + 1) & 7;
        if (g_ring_n < 8) g_ring_n++;
    }
    return NULL;
}

// ═══ v7.9: EndTime 持续补喂——每50ms把 ctx+0x78 顶回 2100 ═══
// 实证(v7.8日志): prime 写入后"到期时间"仍空白 → 成功路径里有代码事后清零;
// 清零后过期检测读到 0 → 判过期 → 裸svc自毁(与"授权成功弹窗瞬间闪退"吻合)。
// 只写堆上数据(非.text), 安全面与 v7.4 prime 相同。
static void *ACE_endtime_keeper(void *arg) {
    (void)arg;
    for (;;) {
        usleep(50000);
        @try {
            if (!g_tgt_base) continue;
            uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff698);
            if (ctx < 0x100000000ULL) continue;
            volatile double *endp = (volatile double *)(ctx + 0x78);
            double now = (double)time(NULL);
            if (*endp < now + 86400.0) *endp = 4102444800.0;
        } @catch (NSException *e) {}
    }
    return NULL;
}
static void *ACE_ctx_monitor(void *arg);   // v7.13 前置声明(定义在下方)
static void *ACE_bp_installer(void *arg);  // v7.14 前置声明(定义在下方)
static void ACE_install_v79_threads(void) {
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &at, ACE_flight_recorder, NULL);
    pthread_create(&th, &at, ACE_endtime_keeper, NULL);
    pthread_create(&th, &at, ACE_ctx_monitor, NULL);
        pthread_create(&th, &at, ACE_bp_installer, NULL);
    pthread_attr_destroy(&at);
    ACETrace(@"v7.9 飞行记录器+EndTime守护已启动");
}
// ═══ v7.14: 硬件断点哨兵——16 个裸 svc 处决点全部下 CPU 硬件断点 ═══
// 原理: ARM debug 寄存器(DBGBCR/DBGBVR)经 thread_set_state 设置, 不写靶场一个字节。
// 命中 → EXC_BREAKPOINT → 异常层记录 PC+LR(凶手与调用者) 并跳过 svc+brk(枪打不响)。
// 靶场的断点扫描器(0x545f8)靠 task_threads 枚举线程, 已被隐身层致盲, 看不到这些断点。
typedef struct { unsigned long long bvr[16], bcr[16], wvr[16], wcr[16]; } ACEDbgState64;
#define ACE_ARM_DEBUG64 15
static const unsigned long long g_kill_sites[16] = {
    0x9f668ULL, 0xa6220ULL, 0xa62b8ULL, 0xa630cULL, 0xa69d0ULL, 0xa6ae8ULL,
    0xae820ULL, 0xc2e34ULL, 0xefe40ULL, 0xf1744ULL, 0xf1768ULL, 0xf1774ULL,
    0xf958cULL, 0xf8308ULL, 0xf831cULL, 0xf83d0ULL };
static int g_bp_logged = 0;
static ACE_tt_fn ACE_real_task_threads(void) {
    ACE_tt_fn f = NULL;
    void *h = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOW);
    if (h) f = (ACE_tt_fn)dlsym(h, "task_threads");
    if (!f || f == (ACE_tt_fn)&ACE_task_threads)
        f = (ACE_tt_fn)dlsym(RTLD_NEXT, "task_threads");
    if (f == (ACE_tt_fn)&ACE_task_threads) return NULL;
    return f;
}
static void *ACE_bp_installer(void *arg) {
    (void)arg;
    ACE_tt_fn real_tt = ACE_real_task_threads();
    if (!real_tt) { ACETrace(@"[bp] 拿不到真实task_threads, 哨兵无法安装"); return NULL; }
    for (;;) {
        usleep(100000);
        if (!g_tgt_base) continue;
        thread_act_array_t list = NULL;
        mach_msg_type_number_t n = 0;
        if (real_tt(mach_task_self(), &list, &n) != KERN_SUCCESS || !list) continue;
        int ok = 0, fail = 0;
        for (unsigned i = 0; i < n; i++) {
            ACEDbgState64 ds;
            memset(&ds, 0, sizeof(ds));
            for (int k = 0; k < 16; k++) {
                ds.bvr[k] = (unsigned long long)(g_tgt_base + g_kill_sites[k]);
                ds.bcr[k] = 0x7ULL;   // E=1, PMC=EL0/EL1, 非链接地址匹配
            }
            mach_msg_type_number_t c = 128;
            kern_return_t kr = thread_set_state(list[i], ACE_ARM_DEBUG64,
                                                (thread_state_t)&ds, &c);
            if (kr == KERN_SUCCESS) ok++; else fail++;
        }
        if (!g_bp_logged && (ok || fail)) {
            g_bp_logged = 1;
            ACETrace(@"[bp] 硬件断点哨兵: %u 线程, 成功%d 失败%d %s", (unsigned)n, ok, fail,
                     fail && !ok ? "(iOS拒绝设置debug状态, 此路不通)" : "");
        }
        vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(mach_port_t));
    }
    return NULL;
}
// ═══ v7.13: ctx 关键字段监视器——20ms 采样, 只记录变化 ═══
// 看门狗 canary 混合了 ctx[0]/+0x74/+0x78/+0x8e/+0x92; 谁在成功路径上改它们,
// 这里直接打出变化序列(值+采样序号), 与弹窗/死亡时刻对齐即可锁定杀人字段。
static void *ACE_ctx_monitor(void *arg) {
    (void)arg;
    static const int offs[] = { 0x00, 0x74, 0x78, 0x88, 0x8c, 0x8e, 0x92, 0x96, 0x1196, 0x119a };
    const int NF = (int)(sizeof(offs) / sizeof(offs[0]));
    unsigned long long last[10];
    for (int i = 0; i < NF; i++) last[i] = 0xDEADBEEFULL;
    unsigned long seq = 0;
    for (;;) {
        usleep(20000);
        @try {
            if (!g_tgt_base) continue;
            uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff698);
            if (ctx < 0x100000000ULL) continue;
            seq++;
            for (int i = 0; i < NF; i++) {
                unsigned long long v;
                if (offs[i] == 0x78) v = *(unsigned long long *)(ctx + 0x78);
                else if (offs[i] == 0x119a) v = *(unsigned long long *)(ctx + 0x119a);
                else v = (unsigned long long)(*(unsigned int *)(ctx + offs[i]));
                if (v != last[i]) {
                    if (g_ace_ready && !g_ace_busy) {
                        g_ace_busy = 1;
                        ACETrace(@"[ctx#%lu] +0x%x: %016llx → %016llx",
                                 seq, offs[i], last[i], v);
                        g_ace_busy = 0;
                    }
                    last[i] = v;
                }
            }
        } @catch (NSException *e) {}
    }
    return NULL;
}
// ═══ v7.12: 遥测类 _0x7D3B5E28 全量钩 ═══
// 实证: 13 处 svc exit_group 自毁点里 6 处位于该类方法体内
// (q4→0x9f668, q5→0xa6220/0xa62b8/0xa630c, q17→0xa69c8, q18:→0xa6ae8, q6:/q7:整体=处决函数)。
// 该类带 NSTimer 属性(q8/q12) → 定时器驱动检查, 不走 dispatch(面包屑盲区, 与实测吻合)。
// 策略: q 系方法记录 调用点偏移+遗言参数; q6:/q7:(纯处决) 直接吞掉不调原实现。
#define ACE_TEL_MAX 16
static SEL g_tel_sel[ACE_TEL_MAX];
static IMP g_tel_imp[ACE_TEL_MAX];
static int g_tel_neuter[ACE_TEL_MAX];
static int g_tel_n = 0;
static int ACE_tel_idx(SEL s) {
    for (int i = 0; i < g_tel_n; i++) if (g_tel_sel[i] == s) return i;
    return -1;
}
static unsigned long ACE_tel_caller(void) {
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    return (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end)
           ? (unsigned long)(ra - g_tgt_base) : 0UL;
}
static void ACE_tel_v(id self, SEL _cmd) {
    int i = ACE_tel_idx(_cmd);
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"[tel] %@ caller=TGT+0x%lx", NSStringFromSelector(_cmd), ACE_tel_caller());
        g_ace_busy = 0;
    }
    if (i >= 0 && g_tel_imp[i]) ((void (*)(id, SEL))g_tel_imp[i])(self, _cmd);
}
static void ACE_tel_o(id self, SEL _cmd, id a) {
    int i = ACE_tel_idx(_cmd);
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"[tel] %@ 遗言=[%@] caller=TGT+0x%lx", NSStringFromSelector(_cmd),
                 ACETrimStr(a, 160), ACE_tel_caller());
        g_ace_busy = 0;
    }
    if (i >= 0 && g_tel_neuter[i]) return;                 // 纯处决方法: 吞掉
    if (i >= 0 && g_tel_imp[i]) ((void (*)(id, SEL, id))g_tel_imp[i])(self, _cmd, a);
}
static unsigned long long ACE_tel_q(id self, SEL _cmd, id a) {
    int i = ACE_tel_idx(_cmd);
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"[tel] %@ 遗言=[%@] caller=TGT+0x%lx", NSStringFromSelector(_cmd),
                 ACETrimStr(a, 160), ACE_tel_caller());
        g_ace_busy = 0;
    }
    if (i >= 0 && g_tel_neuter[i]) return 0;               // 纯处决方法: 吞掉
    if (i >= 0 && g_tel_imp[i])
        return ((unsigned long long (*)(id, SEL, id))g_tel_imp[i])(self, _cmd, a);
    return 0;
}
static void ACE_tel_reg(Class cls, const char *selname, IMP tramp, int neuter) {
    if (g_tel_n >= ACE_TEL_MAX) return;
    SEL s = NSSelectorFromString([NSString stringWithUTF8String:selname]);
    Method m = class_getInstanceMethod(cls, s);
    if (!m) { ACETrace(@"[tel] 方法不存在: %s", selname); return; }
    IMP old = method_setImplementation(m, tramp);
    g_tel_sel[g_tel_n] = s;
    g_tel_imp[g_tel_n] = old;
    g_tel_neuter[g_tel_n] = neuter;
    g_tel_n++;
}
static void ACE_install_tel_hooks(void) {
    @try {
        Class tel = NSClassFromString(@"_0x7D3B5E28");
        if (!tel) { ACETrace(@"[tel] 类不存在(版本不符?)"); return; }
        ACE_tel_reg(tel, "q4",  (IMP)ACE_tel_v, 0);
        ACE_tel_reg(tel, "q16", (IMP)ACE_tel_v, 0);
        ACE_tel_reg(tel, "q5",  (IMP)ACE_tel_v, 0);
        ACE_tel_reg(tel, "q17", (IMP)ACE_tel_v, 0);
        ACE_tel_reg(tel, "q19", (IMP)ACE_tel_v, 0);
        ACE_tel_reg(tel, "q18:", (IMP)ACE_tel_o, 0);
        ACE_tel_reg(tel, "q20:", (IMP)ACE_tel_o, 0);
        ACE_tel_reg(tel, "q21:", (IMP)ACE_tel_o, 0);
        ACE_tel_reg(tel, "q22:", (IMP)ACE_tel_o, 0);
        ACE_tel_reg(tel, "q6:", (IMP)ACE_tel_o, 1);   // 纯处决 → 吞
        ACE_tel_reg(tel, "q7:", (IMP)ACE_tel_q, 1);   // 纯处决 → 吞
        ACETrace(@"[tel] 遥测类钩子已挂 %d 个方法 (q6:/q7: 已拆除)", g_tel_n);
    } @catch (NSException *e) { ACETrace(@"[tel] 挂设异常: %@", e); }
}

// ═══ v7.7: 定向净化——只删卡密账户 signaturetoken.v2 ═══
// 实证: v7.5 全量净化把 identitytoken.v4(设备标识)也删了 → UDID 注册死循环;
// identitytoken.v4 由 ACE_pw_get 注入假值兜底; 卡密账户才是毒化启动复核的元凶。
#define ACE_VIRGIN_PURGE 1
static void ACE_boot_purge(void) {
#if ACE_VIRGIN_PURGE
    @try {
        NSMutableDictionary *del = [NSMutableDictionary dictionary];
        [del setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
        [del setObject:@"com.apple.LSDocumentRegistry" forKey:(__bridge id)kSecAttrService];
        [del setObject:@"com.apple.signaturetoken.v2" forKey:(__bridge id)kSecAttrAccount];
        OSStatus st = SecItemDelete((__bridge CFDictionaryRef)del);
        NSString *flag = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_purged.flag"];
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:flag]) {
            NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
            [[NSUserDefaults standardUserDefaults] removePersistentDomainForName:bid];
            [fm createFileAtPath:flag contents:[@"1" dataUsingEncoding:NSUTF8StringEncoding] attributes:nil];
            ACETrace(@"启动净化: 卡密账户已删(st=%d) + defaults 一次性清理", (int)st);
        } else {
            ACETrace(@"启动净化: 卡密账户已删(st=%d), UDID/defaults 保留", (int)st);
        }
    } @catch (NSException *e) { ACETrace(@"启动净化异常: %@", e); }
#endif
}


static int ACE_addr_mapped(uintptr_t base, const uint64_t *segs, unsigned nseg,
                           uintptr_t addr, size_t len) {
    for (unsigned i = 0; i < nseg; i++) {
        uintptr_t s = base + (uintptr_t)segs[i * 2];
        uintptr_t e = s + (uintptr_t)segs[i * 2 + 1];
        if (addr >= s && addr + len <= e) return 1;
    }
    return 0;
}
static int ACE_sig_ok(uintptr_t base) {
    const struct mach_header_64 *h64 = (const struct mach_header_64 *)base;
    if (h64->ncmds == 0 || h64->ncmds > 256) return 0;
    uint64_t textsize = 0;
    uint64_t segs[32]; unsigned nseg = 0;   // (vmaddr, vmsize) 对，fileoff==0 的映射段
    ACELoadCmdHdr *c = (ACELoadCmdHdr *)(base + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < h64->ncmds; i++) {
        if (c->cmdsize < 8 || c->cmdsize > 0x100000) return 0;   // 命令流损坏防御
        if (c->cmd == LC_SEGMENT_64) {
            const ACESegCmd64 *s64 = (const ACESegCmd64 *)c;
            if (strncmp(s64->segname, "__PAGEZERO", 16) != 0 && s64->fileoff == 0 &&
                s64->vmsize > 0 && nseg < 16) {
                segs[nseg * 2] = s64->vmaddr; segs[nseg * 2 + 1] = s64->vmsize; nseg++;
            }
            if (s64->vmaddr == 0 && strncmp(s64->segname, "__PAGEZERO", 16) != 0 &&
                s64->vmsize > textsize && s64->vmsize < 0x10000000ULL)
                textsize = s64->vmsize;
        }
        c = (ACELoadCmdHdr *)((uintptr_t)c + c->cmdsize);
    }
    if (textsize < 0x100000) return 0;   // 首选基址非 0 或太小 → 不是候选
    if (!ACE_addr_mapped(base, segs, nseg, base + 0xef0fc, 4)) return 0;
    if (!ACE_addr_mapped(base, segs, nseg, base + 0xdcf68, 4)) return 0;
    const uint32_t *p1 = (const uint32_t *)(base + 0xef0fc);   // ldr w8,[x0,#0x38]
    const uint32_t *p2 = (const uint32_t *)(base + 0xdcf68);   // ldr w8,[x0,#0x30]
    return *p1 == 0xB9403808u && *p2 == 0xB9403008u;
}
static const struct mach_header *ACE_find_target_header(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h) continue;
        if (*(const uint32_t *)h != 0xFEEDFACFu) continue;   // 只看 64 位 Mach-O
        if (ACE_sig_ok((uintptr_t)h)) return h;
    }
    return NULL;
}
static uintptr_t ace_off2va(uintptr_t base, const uint64_t (*smap)[4], unsigned n, uint32_t off) {
    for (unsigned i = 0; i < n; i++) {
        if (off >= smap[i][2] && off < smap[i][2] + smap[i][3])
            return base + (uintptr_t)smap[i][0] + (off - (uint32_t)smap[i][2]);
    }
    return 0;
}
static void **ACE_find_ptr_slot(const struct mach_header *hdr, const char *want) {
    uintptr_t base = (uintptr_t)hdr;
    const ACESegCmd64 *seg = (const ACESegCmd64 *)(base + sizeof(struct mach_header_64));
    const struct symtab_command *st = NULL;
    const struct dysymtab_command *dy = NULL;
    uint64_t smap[16][4]; unsigned nsmap = 0;   // vmaddr, vmsize, fileoff, filesize
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        ACELoadCmdHdr *c = (ACELoadCmdHdr *)seg;
        if (c->cmd == LC_SYMTAB) st = (const struct symtab_command *)c;
        else if (c->cmd == LC_DYSYMTAB) dy = (const struct dysymtab_command *)c;
        else if (c->cmd == LC_SEGMENT_64) {
            const ACESegCmd64 *s64 = (const ACESegCmd64 *)c;
            if (s64->filesize > 0 && nsmap < 16) {
                smap[nsmap][0] = s64->vmaddr;  smap[nsmap][1] = s64->vmsize;
                smap[nsmap][2] = s64->fileoff; smap[nsmap][3] = s64->filesize;
                nsmap++;
            }
        }
        seg = (const ACESegCmd64 *)((uintptr_t)c + c->cmdsize);
    }
    if (!st || !dy || !nsmap) return NULL;
    const uint32_t *isyms = (const uint32_t *)ace_off2va(base, smap, nsmap, dy->indirectsymoff);
    const ACENlist64 *nl  = (const ACENlist64 *)ace_off2va(base, smap, nsmap, st->symoff);
    const char *strtab    = (const char *)ace_off2va(base, smap, nsmap, st->stroff);
    if (!isyms || !nl || !strtab) return NULL;
    seg = (const ACESegCmd64 *)(base + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        ACELoadCmdHdr *c = (ACELoadCmdHdr *)seg;
        if (c->cmd == LC_SEGMENT_64) {
            const ACESegCmd64 *s64 = (const ACESegCmd64 *)c;
            const ACESect64 *sec = (const ACESect64 *)((uintptr_t)c + sizeof(ACESegCmd64));
            for (uint32_t k = 0; k < s64->nsects; k++) {
                uint32_t ty = sec[k].flags & 0xff;
                if ((ty == 0x6 || ty == 0x7) && sec[k].size >= 8) {
                    size_t nslots = (size_t)(sec[k].size / 8);
                    for (size_t j = 0; j < nslots; j++) {
                        uint32_t si = isyms[sec[k].reserved1 + j];
                        if (si & 0xC0000000u) continue;   // INDIRECT_SYMBOL_LOCAL/ABS
                        if (si >= st->nsyms) continue;    // 越界防御
                        if (strcmp(strtab + nl[si].n_strx, want) == 0)
                            return (void **)(base + sec[k].addr + j * 8);
                    }
                }
            }
        }
        seg = (const ACESegCmd64 *)((uintptr_t)c + c->cmdsize);
    }
    return NULL;
}
static void ACE_dispatch_async_hook(dispatch_queue_t q, dispatch_block_t blk) {
    @try {
        if (blk && g_tgt_base) {
            void **hdrp = (void **)(__bridge void *)blk;
            uintptr_t inv = (uintptr_t)hdrp[2];           // block 布局: invoke 在 +16
            if (inv >= g_tgt_base && inv < g_tgt_end) {
                uintptr_t off = inv - g_tgt_base;
                ACETrace(@"[disp] +0x%lx", (unsigned long)off);   // v7.11 面包屑: 死前最后几行=凶手
                if (off == 0xef0c8ULL) {                // 弹窗验卡结果: capture+0x38 → 0
                    volatile int32_t *slot = (volatile int32_t *)((uintptr_t)(__bridge void *)blk + 0x38);
                    if (*slot != 0) {
                        ACETrace(@"[hook] 弹窗验卡结果 %d → 0（强制成功路径）", *slot);
                        *slot = 0; g_rw_dialog++;
                    }
                    ACE_prime_endtime();
                } else if (off == 0xdcf68ULL) {            // 启动复核结果: capture+0x30 → 非0
                    volatile int32_t *slot = (volatile int32_t *)((uintptr_t)(__bridge void *)blk + 0x30);
                    if (*slot == 0) {
                        ACETrace(@"[hook] 启动复核结果 0 → 1（强制成功路径）", *slot);
                        *slot = 1; g_rw_boot++;
                    }
                    ACE_prime_endtime();
                }
            }
        }
    } @catch (NSException *e) {}
    dispatch_async(q, blk);
}
static void ACE_install_result_hook(void) {
    const struct mach_header *hdr = ACE_find_target_header();
    if (!hdr) { ACETrace(@"结果hook: 未找到靶场镜像(按指令签名扫描)"); return; }
    uintptr_t base = (uintptr_t)hdr;
    uint64_t textsize = 0x3e8000;   // 本版本实证值，下面再动态取一次
    {
        ACELoadCmdHdr *c = (ACELoadCmdHdr *)(base + sizeof(struct mach_header_64));
        for (uint32_t i = 0; i < ((const struct mach_header_64 *)hdr)->ncmds; i++) {
            if (c->cmd == LC_SEGMENT_64) {
                const ACESegCmd64 *s64 = (const ACESegCmd64 *)c;
                if (s64->vmaddr == 0 && s64->vmsize > 0 && s64->vmsize < 0x10000000ULL &&
                    strncmp(s64->segname, "__PAGEZERO", 16) != 0) {
                    textsize = s64->vmsize; break;
                }
            }
            c = (ACELoadCmdHdr *)((uintptr_t)c + c->cmdsize);
        }
    }
    void **slot = ACE_find_ptr_slot(hdr, "_dispatch_async");
    if (!slot) { ACETrace(@"结果hook: 未找到 _dispatch_async 指针槽"); return; }
    g_tgt_base = base;
    g_tgt_end = base + (uintptr_t)textsize;
    g_saved_slot_val = *slot;
    *slot = (void *)ACE_dispatch_async_hook;
    ACETrace(@"结果hook 已安装: 靶场基址=%p __TEXT=0x%llx 槽=%p 原值=%p → %p",
             (void *)base, (unsigned long long)textsize, slot, g_saved_slot_val,
             (void *)ACE_dispatch_async_hook);
}
// ══════════════ 屏幕悬浮按钮（日志导出）═══════════════
@interface ACELogWindow : UIWindow
@end
@interface ACEFloatButton : UIButton
@end
static UIViewController *g_rootVC = nil;
static ACELogWindow *g_logWin = nil;

static UIViewController *ACE_topVC(void);

@implementation ACELogWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (!v || v == self) return nil;
    if (g_rootVC && v == g_rootVC.view) return nil;
    return v;
}
@end

@implementation ACEFloatButton { CGPoint _start; CGPoint _origin; CGFloat _maxDev; }
- (void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event {
    UITouch *t = [touches anyObject]; if (!t) return;
    _start = [t locationInView:self.superview];
    _origin = self.center;
    _maxDev = 0;
}
- (void)touchesMoved:(NSSet *)touches withEvent:(UIEvent *)event {
    UITouch *t = [touches anyObject]; if (!t) return;
    CGPoint p = [t locationInView:self.superview];
    self.center = CGPointMake(_origin.x + (p.x - _start.x), _origin.y + (p.y - _start.y));
    CGFloat dev = fabs(p.x - _start.x) + fabs(p.y - _start.y);
    if (dev > _maxDev) _maxDev = dev;
}
- (void)touchesEnded:(NSSet *)touches withEvent:(UIEvent *)event {
    if (_maxDev < 10.0) {
        NSString *s = ACELogDump();
        @try {
            [UIPasteboard generalPasteboard].string = s;
            [self setTitle:@"已复制" forState:UIControlStateNormal];
            NSUInteger n = s.length;
            NSString *preview = [s substringToIndex:(n < 160 ? n : 160)];
            UIAlertController *a = [UIAlertController alertControllerWithTitle:@"日志已复制到剪贴板"
                message:[NSString stringWithFormat:@"%@…\n\n去备忘录/聊天框粘贴发出去即可", preview]
                preferredStyle:UIAlertControllerStyleAlert];
            [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
            UIViewController *host = ACE_topVC();
            if (host) [host presentViewController:a animated:YES completion:nil];
        } @catch (NSException *e) {}
    }
}
@end

static UIViewController *ACE_topVC(void) {
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        NSArray *wins = [app windows];
        UIWindow *w = nil;
        for (UIWindow *cand in wins) { if (cand != g_logWin && cand.isKeyWindow) w = cand; }
        if (!w) for (UIWindow *cand in wins) { if (cand != g_logWin) w = cand; }
        UIViewController *vc = w.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        return vc;
    } @catch (NSException *e) { return nil; }
}

static int g_btn_retry = 0;
static void ACE_setup_button(void) {
    @autoreleasepool {
        @try {
            if (g_logWin || g_btn_retry > 80) return; // 80 次×0.5s≈40s 内等场景就绪
            UIWindowScene *scene = nil;
            for (UIScene *sc in [[UIApplication sharedApplication] connectedScenes]) {
                if ([sc isKindOfClass:[UIWindowScene class]]) {
                    if (!scene) scene = (UIWindowScene *)sc;
                    if ([sc activationState] == UISceneActivationStateForegroundActive) {
                        scene = (UIWindowScene *)sc; break;
                    }
                }
            }
            if (!scene) {
                g_btn_retry++;
                dispatch_after(dispatch_time(0, 500000000), dispatch_get_main_queue(), ^{ ACE_setup_button(); });
                return;
            }
            g_rootVC = [[UIViewController alloc] init];
            g_rootVC.view.backgroundColor = [UIColor clearColor];
            g_logWin = [[ACELogWindow alloc] initWithWindowScene:scene];
            g_logWin.rootViewController = g_rootVC;
            g_logWin.windowLevel = 999999;
            g_logWin.backgroundColor = [UIColor clearColor];
            g_logWin.hidden = NO;
            ACEFloatButton *btn = [[ACEFloatButton alloc] initWithFrame:CGRectMake(0, 0, 84, 44)];
            btn.center = CGPointMake(120, 130);
            [btn setTitle:@"ACE·日志" forState:UIControlStateNormal];
            [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            btn.titleLabel.font = [UIFont systemFontOfSize:13];
            btn.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.72];
            btn.layer.cornerRadius = 14;
            btn.clipsToBounds = YES;
            [g_rootVC.view addSubview:btn];
            ACETrace(@"interpose命中: tsep=%d taskThreads=%d exit=%d abort=%d (tsep>0=隐身层实锤生效)",
                     g_hit_tsep, g_hit_tt, g_hit_exit, g_hit_abort);
            ACETrace(@"悬浮按钮已显示：点一下=复制全部日志，按住可拖动");
        } @catch (NSException *e) { ACETrace(@"按钮创建失败: %@", e); }
    }
}

// ══════════════ 第 1 层：只读观测探针（钥匙串 + 弹窗，成功证据链）══════════════
@interface ACELicensePatch : NSObject
@end

@implementation ACELicensePatch

static IMP g_pwGet_imp = NULL;
// v7.7: 假 UDID 注入。实证: identitytoken.v4 的全部读取点只判 length!=0(无校验),
// 钥匙串查空时返回固定 40 位十六进制串即可过门槛, Safari 注册流程整个跳过。
static id ACE_pw_get(id cls, SEL _cmd, id svc, id acct) {
    id r = ((id (*)(id, SEL, id, id))g_pwGet_imp)(cls, _cmd, svc, acct);
    @try {
        if (!r && [acct isKindOfClass:[NSString class]] &&
            [(NSString *)acct isEqualToString:@"com.apple.identitytoken.v4"]) {
            r = @"9f3c2b1a4d5e6f708192a3b4c5d6e7f8091a2b3c";
            if (g_ace_ready && !g_ace_busy) {
                g_ace_busy = 1;
                ACETrace(@"[udid] 钥匙串为空 → 注入固定设备标识, 跳过 Safari 注册");
                g_ace_busy = 0;
            }
        }
    } @catch (NSException *e2) {}
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"Keychain GET svc=%@ acct=%@ -> %@", svc, acct, r ?: @"(nil)");
        g_ace_busy = 0;
    }
    return r;
}
static IMP g_pwSet_imp = NULL;
static BOOL ACE_pw_set(id cls, SEL _cmd, id pw, id svc, id acct) {
    BOOL r = ((BOOL (*)(id, SEL, id, id, id))g_pwSet_imp)(cls, _cmd, pw, svc, acct);
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"Keychain SET svc=%@ acct=%@ pw=%@ ok=%d", svc, acct, ACETrimStr(pw, 64), r);
        g_ace_busy = 0;
    }
    return r;
}
static IMP g_alert_imp = NULL;
static id ACE_alert_init(id cls, SEL _cmd, id title, id msg, NSInteger style) {
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"UIAlert title=[%@] msg=[%@]", ACETrimStr(title, 96), ACETrimStr(msg, 160));
        g_ace_busy = 0;
    }
    return ((id (*)(id, SEL, id, id, NSInteger))g_alert_imp)(cls, _cmd, title, msg, style);
}
static IMP g_addAct_imp = NULL;
static void ACE_addAct(id self, SEL _cmd, id action) {
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        @try {
            id (*getT)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            ACE_G(@"Alert按钮: %@", ACETrimStr(getT(action, NSSelectorFromString(@"title")), 64));
        } @catch (NSException *e) {}
        g_ace_busy = 0;
    }
    ((void (*)(id, SEL, id))g_addAct_imp)(self, _cmd, action);
}

+ (void)load {
    g_ace_ready = 1;   // 此刻 Foundation 必定已就绪（加载顺序保证）
    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            g_ace_busy = 1;
            ACETrace(@"=== v7.12 启动 ===");
                        @try { ACE_report_last_crash(); } @catch (NSException *e) {}
            @try { ACE_install_crash_catcher(); } @catch (NSException *e) { ACETrace(@"崩溃捕捉器异常: %@", e); }
            @try { ACE_install_exc_server(); } @catch (NSException *e) { ACETrace(@"异常捕捉层异常: %@", e); }
            @try { ACE_install_heartbeat(); } @catch (NSException *e) { ACETrace(@"心跳异常: %@", e); }
            @try { ACE_install_v79_threads(); } @catch (NSException *e) { ACETrace(@"v7.9线程异常: %@", e); }
            @try { ACE_boot_purge(); } @catch (NSException *e) { ACETrace(@"启动净化异常: %@", e); }
            @try { ACE_install_result_hook(); } @catch (NSException *e) { ACETrace(@"结果hook异常: %@", e); }
            @try {
                Class kc = NSClassFromString(@"_0xD5A13E79");   // 靶场内 SAMKeychain 封装类
                if (kc) {
                    Method m1 = class_getClassMethod(kc, NSSelectorFromString(@"passwordForService:account:"));
                    if (m1) g_pwGet_imp = method_setImplementation(m1, (IMP)ACE_pw_get);
                    Method m2 = class_getClassMethod(kc, NSSelectorFromString(@"setPassword:forService:account:"));
                    if (m2) g_pwSet_imp = method_setImplementation(m2, (IMP)ACE_pw_set);
                    ACETrace(@"SAMKeychain 探针已挂 (get=%p set=%p)", (void*)g_pwGet_imp, (void*)g_pwSet_imp);
                }
                Class alert = NSClassFromString(@"UIAlertController");
                if (alert) {
                    Method m4 = class_getClassMethod(alert, NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:"));
                    if (m4) g_alert_imp = method_setImplementation(m4, (IMP)ACE_alert_init);
                    Method m5 = class_getInstanceMethod(alert, NSSelectorFromString(@"addAction:"));
                    if (m5) g_addAct_imp = method_setImplementation(m5, (IMP)ACE_addAct);
                    ACETrace(@"Alert 探针已挂");
                }
            } @catch (NSException *e) { ACETrace(@"探针挂设异常: %@", e); }
            @try { ACE_install_tel_hooks(); } @catch (NSException *e) { ACETrace(@"[tel] 安装异常: %@", e); }
            g_ace_busy = 0;
            dispatch_after(dispatch_time(0, 1000000000), dispatch_get_main_queue(), ^{ ACE_setup_button(); });
        }
    });
}

@end
