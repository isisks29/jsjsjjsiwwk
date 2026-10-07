// bypass.m (v8.09)
#define ACE_TRACE 1   // 必须保持 1

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach/mach.h>
#import <mach/mach_time.h>   // v7.23+
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <stdio.h>
#import <math.h>
#import <time.h>
#import <stdarg.h>
#import <signal.h>
#import <fcntl.h>
#import <pthread.h>
#import <sys/stat.h>
#import <Security/Security.h>
#import <sys/socket.h>   // v7.20
#import <netinet/in.h>
#import <arpa/inet.h>
#import <errno.h>
#import <sys/mman.h>   // v7.68
extern void sys_icache_invalidate(void *start, size_t len);

static volatile int g_http_arm = 0;   // v8.08: 验卡改写后才武装HTTPS轨迹(声明前置)
static dispatch_queue_t g_http_logq = NULL;

// ═══ 第 0 层 ═══
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
// ═══ v7.88 ═══
static int g_tramp_index = -2;
static uint32_t g_tramp_scan_cnt = 0xffffffffu;
static int ACE_find_tramp_index(void) {
    if (g_tramp_index >= 0) return g_tramp_index;
    uint32_t n = _dyld_image_count();
    if (g_tramp_index == -1 && n == g_tramp_scan_cnt) return -1;   // 数量未变不重扫
    g_tramp_scan_cnt = n;
    g_tramp_index = -1;
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "libobjc-trampolines")) { g_tramp_index = (int)i; break; }
    }
    return g_tramp_index;
}
static uint32_t g_mapCache[1536];
static uint32_t g_mapN = 0;
static uint32_t g_mapCnt = 0xffffffffu;
static int g_mapO = -99, g_mapT = -99;
static void ACE_ensure_map(void) {
    uint32_t n = _dyld_image_count();
    int o = ACE_find_our_index();
    int t = ACE_find_tramp_index();
    if (n == g_mapCnt && o == g_mapO && t == g_mapT && g_mapN) return;
    g_mapCnt = n; g_mapO = o; g_mapT = t; g_mapN = 0;
    for (uint32_t r = 0; r < n && g_mapN < 1536; r++) {
        if ((int)r == o || (int)r == t) continue;
        g_mapCache[g_mapN++] = r;
    }
}
static uint32_t ACE_map_real(uint32_t i) {
    ACE_ensure_map();
    return (i < g_mapN) ? g_mapCache[i] : i;
}
static uint32_t ACE_image_count(void) {
    ACE_ensure_map();
    return g_mapN;
}
static const char *ACE_image_name(uint32_t i) {
    const char *nm = _dyld_get_image_name(ACE_map_real(i));
// v7.37
    if (nm && strstr(nm, "libsystem_pthread")) return "libsystem_pthr_ead.dylib";
    return nm;
}
static const struct mach_header *ACE_image_header(uint32_t i) {
    return _dyld_get_image_header(ACE_map_real(i));
}
static ACEAddImageFn g_watch_cb = NULL;
static void ACE_watch_wrapper(const struct mach_header *mh, intptr_t slide) {
    if (!g_watch_cb) return;
// v7.10
    if (mh && mh == ACE_self_header()) return;
// v7.88
    {
        int t88 = ACE_find_tramp_index();
        if (mh && t88 >= 0 && mh == _dyld_get_image_header((uint32_t)t88)) return;
    }
    g_watch_cb(mh, slide);
}
static void ACE_register_add_image(ACEAddImageFn f) {
    g_watch_cb = f;
    _dyld_register_func_for_add_image(ACE_watch_wrapper);
}
static int g_hit_tt = 0, g_hit_tsep = 0, g_hit_exit = 0, g_hit_abort = 0;
// ═══ v7.94 前向声明 ═══
static void ACETrace(NSString *fmt, ...);
static uintptr_t g_tgt_base, g_tgt_end;
typedef kern_return_t (*ACE_tt_fn)(mach_port_t, thread_act_array_t *, mach_msg_type_number_t *);
static ACE_tt_fn ACE_real_task_threads(void);
static kern_return_t ACE_task_threads(mach_port_t t, thread_act_array_t *a, mach_msg_type_number_t *c) {
    g_hit_tt++;
// ═══ v7.94 ═══
    uintptr_t ra94 = (uintptr_t)__builtin_return_address(0);
    if (g_tgt_base && ra94 >= g_tgt_base + 0x53df8ULL && ra94 < g_tgt_base + 0x5428cULL) {
        static int v94Log = 0;
        ACE_tt_fn f94 = ACE_real_task_threads();
        if (f94) {
            if (v94Log < 3) { v94Log++;
                ACETrace(@"[v94] task_threads 对 sub_545f8 放行真值(靶场线程态机制恢复供血)");
            }
            return f94(t, a, c);
        }
    }
    if (a) *a = NULL; if (c) *c = 0; return KERN_SUCCESS;
}
static kern_return_t ACE_task_set_exception_ports(mach_port_t t, exception_mask_t m,
        exception_handler_t h, exception_behavior_t b, thread_state_flavor_t f) {
    g_hit_tsep++;   // v7.8
    return KERN_SUCCESS;
}
static void ACE_exit(int code) { g_hit_exit++; (void)code; for (;;) sleep(86400); }
static void ACE_abort(void) { g_hit_abort++; for (;;) sleep(86400); }

// ═══ 第 0.5 层 ═══
static NSMutableArray *g_logbuf = NULL;
static int g_trace_lines = 0;
static int g_ace_busy = 0;
static int g_ace_ready = 0;
static int g_livefd = -1;   // v7.29

static void ACETraceLine(NSString *line) {
    if (g_trace_lines > 20000) return;   // v7.11
    g_trace_lines++;
    @autoreleasepool { NSLog(@"%@", line); }
    @synchronized ([NSMutableArray class]) {
        if (!g_logbuf) g_logbuf = [[NSMutableArray alloc] init];
        [g_logbuf addObject:line];
    }
// v7.29
    if (g_livefd >= 0 && line) {
        const char *u = [line UTF8String];
        if (u) {
            ssize_t w1 = write(g_livefd, u, strlen(u));
            ssize_t w2 = write(g_livefd, "\n", 1);
            (void)w1; (void)w2;
        }
    }
}
// v7.17b
static void ACETrace(NSString *fmt, ...) {
    if (g_trace_lines > 20000) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    ACETraceLine([NSString stringWithFormat:@"[ace] %@", body]);
}
static uintptr_t g_tgt_base, g_tgt_end;
static uintptr_t g_self_base;
static int g_ace_ready, g_ace_busy;
// ═══ v7.41 ═══
static int g_hit__exit = 0;
static void ACE__exit(int code) {
    g_hit__exit++;
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end)
        ACETrace(@"[_exit!!] code=%d caller=TGT+0x%lx (挂起拦截)",
                 code, (unsigned long)(ra - g_tgt_base));
    else
        ACETrace(@"[_exit!!] code=%d caller=%p (挂起拦截)", code, (void *)ra);
    for (;;) sleep(86400);
}
// ═══ v7.18 ═══
// v7.17
static void ACE_ensure_tgt_base(void);   // v7.19
static int ACE_pthread_create(pthread_t *t, const pthread_attr_t *a,
                              void *(*fn)(void *), void *arg) {
    if (fn) ACE_ensure_tgt_base();   // v7.19
    if (g_tgt_base && fn) {
        uintptr_t e = (uintptr_t)fn;
        if (e >= g_tgt_base && e < g_tgt_end) {
            uintptr_t off = e - g_tgt_base;
            if (off == 0xf0d24ULL || off == 0xf2d38ULL) {
                if (g_ace_ready && !g_ace_busy) {
                    g_ace_busy = 1;
                    ACETrace(@"[pc] 拦截靶场安保线程孵化 entry=+0x%lx (看门狗/校验线程)",
                             (unsigned long)off);
                    g_ace_busy = 0;
                }
                if (t) *t = (pthread_t)0;
                return 0;   // 假装创建成功
            }
            if (g_ace_ready && !g_ace_busy) {
                g_ace_busy = 1;
                ACETrace(@"[pc] 靶场线程孵化 entry=+0x%lx (放行)", (unsigned long)off);
                g_ace_busy = 0;
            }
        }
    }
    return pthread_create(t, a, fn, arg);
}
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
    return nanosleep(rqtp, rmtp);
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
ACE_INTERPOSE(ACE__exit,                _exit)   // v7.41
// v7.22

// ═══ 第 0.6 层 ═══
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

// ═══ v7.4 新增① ═══
static void ACE_web_tick(void);   // v7.24
static void ACE_prime_endtime(void) {
    @try {
        if (!g_tgt_base) return;
        uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff658);   // 全局 ctx 指针(实证)
        if (ctx < 0x100000000ULL) return;   // 未建/异常则跳过
// v7.21
        volatile long long *endp = (volatile long long *)(ctx + 0x78);
        long long nowll = (long long)time(NULL);
        long long target = nowll + 3650LL * 86400LL;
        if (*endp < nowll + 86400LL) {
            ACETrace(@"[prime] EndTime(int64) %lld → %lld (now+3650天, scvtf整数语义)", *endp, target);
            *endp = target;
        }
        ACE_web_tick();   // v7.24
    } @catch (NSException *e) {}
}

// ═══ v7.4 新增② ═══
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
    signal(sig, SIG_DFL);
}
static NSString *ACE_crash_path(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_crash.txt"];
}
// v7.5
static UIViewController *ACE_topVC(void);   // 前置声明(定义在悬浮按钮段)
static void ACE_report_last_crash(void) {
    @try {
// v7.29
        NSString *logp = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_log.txt"];
        NSData *ld3 = [NSData dataWithContentsOfFile:logp];
        g_livefd = open(logp.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC | O_APPEND, 0644);
        return;   // v7.95
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
// v7.29
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
        NSData *bd4 = [NSData dataWithContentsOfFile:
            [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_burst.txt"]];
        if (bd4 && [bd4 length]) {
// v7.34
            const char *bb = (const char *)[bd4 bytes];
            NSUInteger BL = [bd4 length];
            NSMutableString *dg = [NSMutableString stringWithCapacity:4096];
            char lastPc[64][17], lastLr[64][17], runSw[64][3];
            int runN[64];
            memset(lastPc, 0, sizeof(lastPc)); memset(lastLr, 0, sizeof(lastLr));
            memset(runSw, 0, sizeof(runSw)); memset(runN, 0, sizeof(runN));
            char curSw[3] = "??";
            long entries = 0;
            #define ACE_HX(c) (((c)>='0'&&(c)<='9')?((c)-'0'):((((c)|32)>='a')?(((c)|32)-'a'+10):0))
            #define ACE_T_FLUSH(ix) do { if (runN[ix] > 0 && entries < 600) { \
                    [dg appendFormat:@"S%.2s t%02x P%s L%s x%d\n", runSw[ix], (ix), lastPc[ix], lastLr[ix], runN[ix]]; \
                    entries++; } runN[ix] = 0; } while (0)
            NSUInteger bi = 0;
            while (bi < BL) {
                const char *nl = (const char *)memchr(bb + bi, '\n', BL - bi);
                NSUInteger len = nl ? (NSUInteger)(nl - (bb + bi)) : (BL - bi);
                if (len == 3 && bb[bi] == 'S') {
                    curSw[0] = bb[bi+1]; curSw[1] = bb[bi+2];
                } else if (len == 37 && bb[bi] == 'T') {
                    int idx = ACE_HX(bb[bi+1]) * 16 + ACE_HX(bb[bi+2]);
                    if (idx >= 0 && idx < 64) {
                        char pc[17], lr2[17];
                        memcpy(pc, bb + bi + 4, 16); pc[16] = 0;
                        memcpy(lr2, bb + bi + 21, 16); lr2[16] = 0;
                        if (runN[idx] > 0 && memcmp(lastPc[idx], pc, 16) == 0) {
                            runN[idx]++;
                        } else {
                            ACE_T_FLUSH(idx);
                            memcpy(lastPc[idx], pc, 17); memcpy(lastLr[idx], lr2, 17);
                            runSw[idx][0] = curSw[0]; runSw[idx][1] = curSw[1];
                            runN[idx] = 1;
                        }
                    }
                }
                if (!nl) break;
                bi += len + 1;
            }
            for (int fx = 0; fx < 64; fx++) ACE_T_FLUSH(fx);
            #undef ACE_T_FLUSH
            #undef ACE_HX
            ACETrace(@"===== 上次burst靶场活动全记录(%ld段, t行已滤) =====\n%@", entries, dg);
            [UIPasteboard generalPasteboard].string =
                [NSString stringWithFormat:@"[aceTline]\n%@", dg];
        }
        NSData *td2 = [NSData dataWithContentsOfFile:
            [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_trace.txt"]];
        if (td2 && [td2 length]) {
            NSString *ts = [[NSString alloc] initWithData:td2 encoding:NSUTF8StringEncoding];
            if (ts) {
                ACETrace(@"上次死前线程指纹(靶场内偏移):\n%@", ts);
                [UIPasteboard generalPasteboard].string =
                    [NSString stringWithFormat:@"[ace死前指纹]\n%@\n[崩溃文件]\n%@", ts,
                        d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : @"(空)"];
            }
        }
    } @catch (NSException *e) {}
}
static void ACE_install_crash_catcher(void) {
    @try {
        g_self_base = (uintptr_t)ACE_self_header();
// v7.5
        struct stat fsb;
        int oflags = O_CREAT | O_WRONLY | ((stat(ACE_crash_path().fileSystemRepresentation, &fsb) == 0
                                            && fsb.st_size < 4096) ? O_APPEND : O_TRUNC);
        g_crashfd = open(ACE_crash_path().fileSystemRepresentation, oflags, 0644);
        static stack_t ss;   // 备用信号栈(栈溢出时也能记)
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
        sigaction(SIGTRAP, &sa, NULL);
        sigaction(SIGABRT, &sa, NULL);
        ACETrace(@"崩溃捕捉器已装 fd=%d (SIGSEGV/BUS/ILL/TRAP/ABRT)", g_crashfd);
    } @catch (NSException *e) { ACETrace(@"崩溃捕捉器安装失败: %@", e); }
}

// ═══ v7.8 新增 ═══
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
#define ACE_ARM64_STATE 6
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
// ═══ v7.68 地址陷阱 ═══
static volatile int g_addrTrapArmed = 0;
static volatile long g_addrTrapCnt = 0;
static volatile long g_addrTrapRounds = 0;   // v7.69
static unsigned long long g_trapPCs[3];
static unsigned long long g_trapRegs[3][34];
// ═══ v7.71 信号层陷阱救援 ═══
static struct sigaction g_oldBus, g_oldSegv;
static volatile int g_sigTrapReady = 0;
static volatile long g_jumpCnt = 0;   // v7.72
// ═══ v7.73 显示链诊断全局 ═══
static id g_mtkView = nil;   // 复刻 MTKView(强引用)
static void *g_mtlLayer = NULL;
static volatile long g_curDCnt = 0;
static volatile long g_curDNil = 0;
static volatile long g_presCnt = 0;
static id (*g_orig_curD)(id, SEL) = NULL;
static void (*g_orig_pres)(id, SEL, id) = NULL;
typedef struct { double r, g, b, a; } ACEClearColor;
static void ACE_diag_display(int run);
static void ACE_dump_wins80(int phase, long n);   // v7.81
static void ACE_scan_windows82(long tag);   // v7.82
static void ACE_code_check84(long n);   // v7.84
// ═══ v7.74 m1 ═══
static void (*g_orig_m1)(id, SEL) = NULL;
static void (*g_orig_n0)(id, SEL) = NULL;
static void (*g_orig_m2)(id, SEL) = NULL;
static void (*g_orig_m3)(id, SEL) = NULL;
static volatile long g_m1Cnt = 0, g_n0Cnt = 0, g_m2Cnt = 0, g_m3Cnt = 0;
static void *g_getDrawData = NULL;
static void *g_cfgPtr = NULL;
static volatile long g_probeDraws = 0;   // v7.78
static void ACE_trap_signal_handler(int sig, siginfo_t *si, void *uc) {
    uintptr_t fa = (uintptr_t)(si ? si->si_addr : NULL);
    uintptr_t pgBase = g_tgt_base ? (g_tgt_base + 0x3fc000ULL) : 0;
    if (pgBase && fa >= pgBase && fa < pgBase + 16384ULL) {
        mprotect((void *)pgBase, 16384, PROT_READ | PROT_WRITE);
#if defined(__APPLE__)
        if (uc) {
            ucontext_t *uct = (ucontext_t *)uc;
            uint64_t pc = (uint64_t)uct->uc_mcontext->__ss.__pc;
            if (g_addrTrapArmed && g_tgt_base
                    && pc >= g_tgt_base + 0x8bcc0ULL && pc < g_tgt_base + 0x8cd78ULL) {
                long n = g_addrTrapCnt;
                if (n < 3) {
                    g_trapPCs[n] = pc;
                    for (int i = 0; i < 29; i++)
                        g_trapRegs[n][i] = (unsigned long long)uct->uc_mcontext->__ss.__x[i];
                    g_trapRegs[n][29] = (unsigned long long)uct->uc_mcontext->__ss.__fp;
                    g_trapRegs[n][30] = (unsigned long long)uct->uc_mcontext->__ss.__lr;
                    g_trapRegs[n][31] = (unsigned long long)uct->uc_mcontext->__ss.__sp;
                    g_trapRegs[n][32] = pc;
                }
                g_addrTrapCnt = n + 1;
// ═══ v7.72 绕门手术 ═══
                if (pc == g_tgt_base + 0x8bd10ULL) {
                    uct->uc_mcontext->__ss.__pc = g_tgt_base + 0x8c018ULL;
                    g_jumpCnt++;
                }
            }
        }
#endif
        return;   // 重执行故障指令(页已恢复RW)
    }
    struct sigaction *oldp = (sig == SIGBUS) ? &g_oldBus : &g_oldSegv;
    if (oldp->sa_sigaction || oldp->sa_handler) sigaction(sig, oldp, NULL);
    else signal(sig, SIG_DFL);
    raise(sig);
}
static void ACE_arm_signal_trap(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = ACE_trap_signal_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (!g_sigTrapReady) {
        sigaction(SIGBUS, &sa, &g_oldBus);
        sigaction(SIGSEGV, &sa, &g_oldSegv);
        g_sigTrapReady = 1;
    } else {
        sigaction(SIGBUS, &sa, NULL);   // 重抢(防被再覆盖)
        sigaction(SIGSEGV, &sa, NULL);
    }
}
static void *ACE_exc_server(void *arg) {
    (void)arg;
    for (;;) {
        ACEExcReq req;
        memset(&req, 0, sizeof(req));
        kern_return_t kr = mach_msg(&req.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                0, sizeof(req), g_exc_port, 1000, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) continue;
        if (req.head.msgh_id != 2401 ) continue;
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
        if (req.exception == EXC_BAD_ACCESS) {
// v7.69
            uintptr_t faddr = (uintptr_t)req.code[1];
            uintptr_t pgBase = g_tgt_base ? (g_tgt_base + 0x3fc000ULL) : 0;
            if (pgBase && faddr >= pgBase && faddr < pgBase + 16384ULL) {
                mprotect((void *)pgBase, 16384, PROT_READ | PROT_WRITE);
                if (g_addrTrapArmed && g_tgt_base
                        && pc >= g_tgt_base + 0x8bcc0ULL && pc < g_tgt_base + 0x8cd78ULL) {
                    long n = g_addrTrapCnt;
                    if (n < 3) {
                        g_trapPCs[n] = pc;
                        int lim = (int)(cnt / 2); if (lim > 34) lim = 34;
                        for (int i = 0; i < lim; i++) g_trapRegs[n][i] = st[i];
                    }
                    g_addrTrapCnt = n + 1;
                }
                rep.retCode = KERN_SUCCESS;   // 重执行故障指令(页已恢复RW)
            } else {
                rep.retCode = KERN_FAILURE;
            }
        } else if (req.exception == EXC_BREAKPOINT && pc && g_exc_skip < 64) {
            st[32] = pc + 4;   // 跳过 brk, 拆掉自毁
            cnt = 68;
            g_exc_skip++;
            thread_set_state(req.thread.name, ACE_ARM64_STATE, (thread_state_t)st, cnt);
            rep.retCode = KERN_SUCCESS;
        } else {
            rep.retCode = KERN_FAILURE;
        }
        mach_msg(&rep.head, MACH_SEND_MSG, sizeof(rep), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    }
    return NULL;
}
typedef kern_return_t (*ACE_tsep_fn)(mach_port_t, exception_mask_t, exception_handler_t,
                                     exception_behavior_t, thread_state_flavor_t);
static ACE_tsep_fn g_real_tsep = 0;   // v7.70
static void ACE_install_exc_server(void) {
    ACE_tsep_fn real_tsep = (ACE_tsep_fn)dlsym(RTLD_NEXT, "task_set_exception_ports");
    if (!real_tsep) { ACETrace(@"真实 task_set_exception_ports 未找到"); return; }
    g_real_tsep = real_tsep;
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

// v7.9
static char g_ring[8][240];
static volatile int g_ring_i = 0, g_ring_n = 0;
static volatile long long g_burst_until = 0;   // v7.17
static volatile int g_imgMapSaved87 = 0;   // v7.87
static volatile uintptr_t g_cacheBase92 = 0;   // v7.92
// v7.92c
typedef const void *(*ACE_gscr_t)(size_t *);
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void *)-2)
#endif
static ACE_gscr_t ACE_gscr92(void) {
    static ACE_gscr_t f = 0;
    static int done92 = 0;
    if (!done92) {
        done92 = 1;
        f = (ACE_gscr_t)dlsym(RTLD_DEFAULT, "dyld_get_shared_cache_range");
    }
    return f;
}
// ═══ v7.8 新增 ═══
static void *ACE_heartbeat(void *arg) {
    (void)arg;
    for (;;) {
        sleep(1);
        @autoreleasepool {
// v7.29
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

// ═══ v7.9 ═══
typedef kern_return_t (*ACE_tt_fn)(mach_port_t, thread_act_array_t *, mach_msg_type_number_t *);
static ACE_tt_fn ACE_real_task_threads(void);   // v7.15
// ═══ v7.32 ═══
static const unsigned g_sus_off[] = {
    0x9e558, 0xa5110, 0xa51a8, 0xa51fc, 0xa58c0, 0xa59d8, 0xad710, 0xc1d24,
    0xee3b0, 0xefddc, 0xefe0c, 0xf7f74, 0xd071c, 0xd0740, 0xf6c34, 0xf6ce4,
    0x31764, 0xe588c, 0xe58dc, 0xf0cc0, 0xee3bc, 0xefde8, 0xefe18, 0xf7f80,
    0xefe20, 0x9cd54, 0x9ccdc, 0xadc98, 0xf0d24, 0xf2d38,
    0x9e730, 0xad6f8, 0xc54a0, 0xd1630, 0xdc438
};
#define ACE_SUS_N 35
static mach_port_t g_main_th = MACH_PORT_NULL;   // v7.31
static unsigned char g_sus_seen[96][ACE_SUS_N];
// v7.33
// v7.35
static unsigned char g_zone_frozen[96];
static int ace_freeze_zone(unsigned long long off) {
// v7.35
// v7.34
    if (off >= 0xadc98ULL && off < 0xc67f0ULL) return 0;
    if (off >= 0xf0d24ULL && off < 0xf0f58ULL) return 2;
    if (off >= 0xf2d38ULL && off < 0xf30e8ULL) return 3;
    if (off >= 0xf6ba0ULL && off < 0xf6d00ULL) return 4;
// ═══ v7.87 扩容 ═══
    if (off >= 0xed550ULL && off < 0xf7870ULL) return 5;
    if (off >= 0xa50f0ULL && off < 0xa59f0ULL) return 6;
    if (off >= 0xe57ccULL && off < 0xe59ccULL) return 7;
    if (off >= 0x9e4f0ULL && off < 0x9e5f0ULL) return 8;
    if (off >= 0xf7ef4ULL && off < 0xf7f94ULL) return 10;
    if (off >= 0xad6f0ULL && off < 0xad720ULL) return 11;   // z11: ad710纯die桩
    if (off >= 0xd0704ULL && off < 0xd0754ULL) return 12;
    if (off >= 0x31750ULL && off < 0x31780ULL) return 13;   // z13: 31764动态svc
    return -1;
}
static void *ACE_flight_recorder(void *arg) {
    (void)arg;
    return NULL;   // v7.95
    mach_port_t self_th = mach_thread_self();   // v7.33
    ACE_tt_fn real_tt = ACE_real_task_threads();   // v7.15
    if (!real_tt) { ACETrace(@"[rec] 真实task_threads解析失败, 线程采样不可用"); return NULL; }
    ACETrace(@"[rec] 采样启动 real_tt=%p", (void *)real_tt);
    int burstfd = -1, was_burst = 0;
    long long burst_bytes = 0;   // v7.27
    for (;;) {
        long long nowt = (long long)time(NULL);
        int burst = (g_burst_until != 0 && nowt <= g_burst_until);
        if (burst && !was_burst) {
            if (burstfd >= 0) close(burstfd);
            NSString *bp2 = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_burst.txt"];
            burstfd = open(bp2.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            burst_bytes = 0;
            ACETrace(@"[burst] 高精度采样启动 fd=%d", burstfd);
        } else if (!burst && was_burst) {
            if (burstfd >= 0) { close(burstfd); burstfd = -1; }
            ACETrace(@"[burst] 采样窗口结束");
        }
        was_burst = burst;
// ═══ v7.87 高警戒采样 ═══
        int alert87 = 0;
        if (!burst && g_tgt_base) {
            alert87 = (*(volatile uint8_t *)(g_tgt_base + 0x3fc308ULL) & 1);
            if (alert87 && !g_imgMapSaved87) {
                g_imgMapSaved87 = 1;
                NSMutableString *mp87 = [NSMutableString string];
                uint32_t ic87 = _dyld_image_count();
                for (uint32_t i87 = 0; i87 < ic87; i87++)
                    [mp87 appendFormat:@"IMG %s %p\n", _dyld_get_image_name(i87),
                     (void *)_dyld_get_image_header(i87)];
                ACETrace(@"===== v87 image映射(burst t行绝对地址换算用) =====\n%@", mp87);
            }
        }
        usleep(burst ? 300 : (alert87 ? 2000 : 50000));   // v7.25
        if (!g_tgt_base) continue;
        thread_act_array_t list = NULL;
        mach_msg_type_number_t n = 0;
        if (real_tt(mach_task_self(), &list, &n) != KERN_SUCCESS || !list) continue;
        char line[240]; int p = 0;
        memcpy(line, "PC:", 3); p = 3;
        static const char *hd = "0123456789abcdef";
        char blk[4096]; int bq = 0;   // v7.27
        unsigned sweep = 0;
        for (unsigned i = 0; i < n && p < 200; i++) {
            unsigned long long stt[34];
            memset(stt, 0, sizeof(stt));
            mach_msg_type_number_t c = 68;
            if (thread_get_state(list[i], ACE_ARM64_STATE, (thread_state_t)stt, &c) == 0 && c >= 66) {
                unsigned long long pc = stt[32];
                unsigned long long lr = stt[30];
                int inT = (pc >= g_tgt_base && pc < g_tgt_end);
                int lrInT = (lr >= g_tgt_base && lr < g_tgt_end);
                if (inT) {
                    unsigned long long off = pc - g_tgt_base;
                    line[p++] = ' ';
                    for (int k = 28; k >= 0; k -= 4) line[p++] = hd[(off >> k) & 0xf];
// v7.33
                    if (i < 96) {
                        for (unsigned s = 0; s < ACE_SUS_N; s++) {
                            unsigned long long so = g_sus_off[s];
                            if (off >= so && off < so + 0x60ULL && !g_sus_seen[i][s]
                                && g_ace_ready && !g_ace_busy) {
                                g_sus_seen[i][s] = 1;
                                int canFreeze = (s < 24) && list[i] != g_main_th
                                                && list[i] != self_th;
                                kern_return_t fkr = 0;
                                if (canFreeze) fkr = thread_suspend(list[i]);
                                g_ace_busy = 1;
                                if (canFreeze)
                                    ACETrace(@"[freeze-kill] t%02u 冻结于自毁点%u @+0x%llx kr=%d (lr+0x%llx)",
                                             i, s, off, fkr, lrInT ? (lr - g_tgt_base) : 0ULL);
                                else
                                    ACETrace(@"[watch] t%02u 路过岗哨%u @+0x%llx (lr+0x%llx)", i, s, off,
                                             lrInT ? (lr - g_tgt_base) : 0ULL);
                                g_ace_busy = 0;
                            }
                        }
                    }
// v7.33
// v7.35
                    if (i < 96 && !g_zone_frozen[i] && list[i] != g_main_th
                        && list[i] != self_th) {
                        int z = ace_freeze_zone(off);
                        if (z < 0 && off >= 0x14e000ULL && off < 0x14f000ULL && lrInT) {
                            unsigned long long lro = lr - g_tgt_base;
                            if (lro >= 0xadc98ULL && lro < 0xc67f0ULL) z = 9;
                        }
                        if (z >= 0) {
                            g_zone_frozen[i] = 1;
                            kern_return_t zkr = thread_suspend(list[i]);
                            if (g_ace_ready && !g_ace_busy) {
                                g_ace_busy = 1;
                                ACETrace(@"[zone-freeze] t%02u 区域%d 冻结 @+0x%llx kr=%d (lr+0x%llx)",
                                         i, z, off, zkr, lrInT ? (lr - g_tgt_base) : 0ULL);
                                g_ace_busy = 0;
                            }
                        }
                    }
                }
// v7.27
                if (burstfd >= 0 && bq < 3900) {
                    blk[bq++] = inT ? 'T' : 't';
                    blk[bq++] = hd[(i >> 4) & 0xf];
                    blk[bq++] = hd[i & 0xf];
                    blk[bq++] = 'P'; ace_hex16(blk + bq, inT ? pc - g_tgt_base : pc); bq += 16;
                    blk[bq++] = 'L'; ace_hex16(blk + bq, lrInT ? lr - g_tgt_base : lr); bq += 16;
                    blk[bq++] = '\n';
                    sweep = i + 1;
                }
            }
        }
        if (burstfd >= 0 && bq > 0 && burst_bytes < 24 * 1024 * 1024) {
            char sm[12]; int sq = 0;
            sm[sq++] = 'S'; sm[sq++] = hd[(sweep >> 4) & 0xf]; sm[sq++] = hd[sweep & 0xf]; sm[sq++] = '\n';
            write(burstfd, sm, (size_t)sq);
            int w1 = (int)write(burstfd, blk, (size_t)bq);
            burst_bytes += sq + (w1 > 0 ? w1 : 0);   // v7.27
        }
        line[p] = 0;
        vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(mach_port_t));
        int hadTarget = (p > 3);
        strcpy(g_ring[g_ring_i], line);
        g_ring_i = (g_ring_i + 1) & 7;
        if (g_ring_n < 8) g_ring_n++;
// v7.16
        if (hadTarget) {
            static NSString *tp = nil;
            static dispatch_once_t onceTok;
            dispatch_once(&onceTok, ^{
                tp = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_trace.txt"];
            });
            NSMutableString *tr = [NSMutableString string];
            int st2 = (g_ring_i - g_ring_n + 8) & 7;
            for (int k = 0; k < g_ring_n; k++) {
                [tr appendString:[NSString stringWithUTF8String:g_ring[(st2 + k) & 7]]];
                [tr appendString:@"\n"];
            }
            [tr writeToFile:tp atomically:NO encoding:NSUTF8StringEncoding error:NULL];
            static int logged_once = 0;
            if (!logged_once) {
                logged_once = 1;
                if (g_ace_ready && !g_ace_busy) {
                    g_ace_busy = 1;
                    ACETrace(@"[rec] 首拍命中靶场PC, 指纹落盘已激活: %@", @"");
                    g_ace_busy = 0;
                }
            }
        }
    }
    return NULL;
}

// ═══ v7.9 ═══
// v7.8
// v7.4
static void *ACE_endtime_keeper(void *arg) {
    (void)arg;
    for (;;) {
        usleep(50000);
        @try {
            if (!g_tgt_base) continue;
            uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff658);
            if (ctx < 0x100000000ULL) continue;
// v7.21
            volatile long long *endp = (volatile long long *)(ctx + 0x78);
            long long nowll = (long long)time(NULL);
            if (*endp < nowll + 86400LL) *endp = nowll + 3650LL * 86400LL;
        } @catch (NSException *e) {}
    }
    return NULL;
}
// ═══ v7.23 ═══
// v7.28
// v7.21
static void *ACE_clock_keeper(void *arg) {
    (void)arg;
    static int prearmed = 0;
    for (;;) {
        usleep(50000);
        @autoreleasepool { @try {
            if (!g_tgt_base) continue;
            volatile double  *wbase = (volatile double *)(g_tgt_base + 0x3f6560);
            const volatile uint32_t *tb   = (const volatile uint32_t *)(g_tgt_base + 0x3f6570);
            const volatile uint64_t *mbase= (const volatile uint64_t *)(g_tgt_base + 0x3f6588);
            volatile double  *epoch = (volatile double *)(g_tgt_base + 0x3f6590);
            volatile double  *ovr   = (volatile double *)(g_tgt_base + 0x3f65a0);
// ═══ v7.30 ═══
            if (!prearmed) {
                prearmed = 1;
                volatile uint64_t *tokD8 = (volatile uint64_t *)(g_tgt_base + 0x3f6598);
                volatile uint64_t *tokB8 = (volatile uint64_t *)(g_tgt_base + 0x3f6578);
                if (*tokD8 != ~(uint64_t)0) {
                    if (tb[0] == 0 || tb[1] == 0) {
                        mach_timebase_info_data_t ti; mach_timebase_info(&ti);
                        ((volatile uint32_t *)(g_tgt_base + 0x3f6570))[0] = ti.numer;
                        ((volatile uint32_t *)(g_tgt_base + 0x3f6570))[1] = ti.denom;
                        *(volatile uint32_t *)(g_tgt_base + 0x3f65b8) = 1;   // block B 同款 flag
                    }
                    uint32_t pn = tb[0], pd = tb[1];
                    uint64_t pabs = mach_absolute_time();
                    uint64_t pms = pd ? ((pabs * (uint64_t)pn) / (uint64_t)pd) / 1000000ULL : 0ULL;
                    *(volatile uint64_t *)(g_tgt_base + 0x3f6588) = pms;   // mbase=单调毫秒now
                    *(volatile double *)(g_tgt_base + 0x3f6590) =
                        [[NSDate date] timeIntervalSince1970];
                    *tokB8 = ~(uint64_t)0;
                    *tokD8 = ~(uint64_t)0;
                }
            }
            if (*ovr != 0.0) *ovr = 0.0;   // v7.28
            double K = 1000.0;   // v8.01
            uint64_t abst = mach_absolute_time();
            uint32_t num = tb[0], den = tb[1];
            uint64_t mono_ms = den ? ((abst * (uint64_t)num) / (uint64_t)den) / 1000000ULL : 0ULL;
            double delta = (double)(mono_ms - *mbase);
            double computed = (K != 0.0 && isfinite(K)) ? (delta / K) : delta;
            computed += *epoch;
            double wall = [[NSDate date] timeIntervalSince1970];
            double diff = wall - computed;
            if (!(diff < 5.0 && diff > -5.0)) {   // NaN/超差都纠正
                double ne = *epoch + diff;
                *epoch = isfinite(ne) ? ne : wall;   // 毒值兜底
            }
            double wb = *wbase;
            if (!(wb > 0.0) || wall - wb > 15.0 || wall - wb < -30.0) *wbase = wall;
        } @catch (NSException *e) {} }
    }
    return NULL;
}
// ═══ v7.24 ═══
static uint32_t ACE_mix32(uint32_t x) {
    x ^= x >> 15; x *= 0x1f3d6a71u; x ^= x >> 11; x *= 0x8e4b1395u; x ^= x >> 17;
    return x;
}
static volatile int g_freeze_web = 0;   // v7.47
// v7.56
static BOOL g_nativeBuilt = NO;   // 复刻面板已建成
static volatile int g_panelWant = 0;   // v7.93
static void ACE_apply_panel_hidden(int want);   // v7.95
static int g_rebuildCnt = 0;
static void ACE_web_tick(void) {
    @try {
        if (!g_tgt_base) return;
// v7.47
        if (g_freeze_web) return;
// v7.37
        *(volatile uint64_t *)(g_tgt_base + 0x3f6568ULL) = 0;
// ═══ v7.87 ═══
        *(volatile uint32_t *)(g_tgt_base + 0x3f68a4ULL) = 0;
        volatile uint32_t *tb = (volatile uint32_t *)(g_tgt_base + 0x3f6b00);
        uint32_t num = tb[0], den = tb[1];
        if (num == 0 || den == 0) {
            mach_timebase_info_data_t ti; mach_timebase_info(&ti);
            num = ti.numer; den = ti.denom;
            tb[0] = num; tb[1] = den;
        }
        uint64_t ns = (uint64_t)mach_absolute_time();
        if (den) ns = ns * num / den;
// v7.26
        uint64_t S = ns / 1000000ULL;   // 单调毫秒 = 校验方的种子单位
        uint32_t Slo = (uint32_t)S, Shi = (uint32_t)(S >> 32);
        *(volatile uint64_t *)(g_tgt_base + 0x3ff660) = S ^ 0xb75e8052babd72a6ULL;
// v7.50
// v7.46
        uint32_t a8 = ACE_mix32((Slo ^ Shi) ^ 0xd18ddb25u);
        *(volatile uint32_t *)(g_tgt_base + 0x3ff668) = a8;
        uint32_t t2 = a8 ^ 0x1767cedcu;
        t2 ^= t2 >> 15; t2 *= 0x1f3d6a71u; t2 ^= t2 >> 11; t2 *= 0x8e4b1395u;
// v7.61
// v7.59
        uint32_t ac = Slo ^ (t2 >> 17) ^ t2;
        *(volatile uint32_t *)(g_tgt_base + 0x3ff66c) = ac;
        uint32_t t3 = ac ^ 0x5d41c293u;   // 链3: 折进 Shi
        t3 ^= t3 >> 15; t3 *= 0x1f3d6a71u; t3 ^= t3 >> 11; t3 *= 0x8e4b1395u;
        uint32_t b0 = Shi ^ (t3 >> 17) ^ t3;
        *(volatile uint32_t *)(g_tgt_base + 0x3ff670) = b0;
// v7.45
        *(volatile uint64_t *)(g_tgt_base + 0x3ff640) = S ^ 0xb75e8052babd72a6ULL;
        uint32_t a88 = ACE_mix32(((uint32_t)S ^ 0xd18ddb25u) ^ Shi);
        *(volatile uint32_t *)(g_tgt_base + 0x3ff648) = a88;
        uint32_t g2 = a88 ^ 0x1767cedcu;
        g2 ^= g2 >> 15; g2 *= 0x1f3d6a71u; g2 ^= g2 >> 11; g2 *= 0x8e4b1395u;   // pmix
        uint32_t ac8c = Slo ^ (g2 >> 17) ^ g2;
        *(volatile uint32_t *)(g_tgt_base + 0x3ff64c) = ac8c;
        uint32_t h2 = ac8c ^ 0x5d41c293u;
        h2 ^= h2 >> 15; h2 *= 0x1f3d6a71u; h2 ^= h2 >> 11; h2 *= 0x8e4b1395u;   // pmix
        uint32_t b090 = Shi ^ (h2 >> 17) ^ h2;
        *(volatile uint32_t *)(g_tgt_base + 0x3ff650) = b090;
        uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff658);
        if (ctx < 0x100000000ULL) return;
        volatile long long *endp = (volatile long long *)(ctx + 0x78);
        long long nowll = (long long)time(NULL);
        if (*endp < nowll + 86400LL) *endp = nowll + 3650LL * 86400LL;   // v7.21
        volatile uint32_t *p8e = (volatile uint32_t *)(ctx + 0x8e);
        volatile uint32_t *p92 = (volatile uint32_t *)(ctx + 0x92);
        if (*p8e == 0) *p8e = 0x61636561u;   // 武装标志: 任意非零
        if (*p92 == 0) *p92 = 0x61636562u;
        uint64_t C = *(volatile uint64_t *)(ctx + 0x119a);
        if (C == 0) { C = 0xc6a45bd1a793e995ULL; *(volatile uint64_t *)(ctx + 0x119a) = C; }
        uint64_t E = (uint64_t)*endp;
        uint64_t A = E ^ C ^ 0xa5c3e1f7b6d2489aULL;   // 反解 eq7
        *(volatile uint64_t *)(ctx + 0x11a2) = A;
        uint32_t V8e = *p8e, V92 = *p92;
// ═══ v7.36 真凶修复 ═══
        uint32_t C0 = 0xffffffffu;
        uint32_t s10 = V8e ^ (uint32_t)(C >> 7)  ^ 0x4a9b5206u;   // 反解 eq8
        uint32_t s18 = V92 ^ (uint32_t)(C >> 13) ^ 0x8c1a73e5u;   // 反解 eq9
        uint32_t s20 = C0  ^ (uint32_t)(C >> 19) ^ 0x5f8a16e3u;   // 反解 eq10
        *(volatile uint32_t *)(ctx + 0x11aa) = s10;
        *(volatile uint32_t *)(ctx + 0x11b2) = s18;
        *(volatile uint32_t *)(ctx + 0x11ba) = s20;
        uint32_t m = (uint32_t)(A >> 32) ^ (uint32_t)A;   // eq11 混合校验和
        m *= 0x45d9f3b7u; m ^= s10; m *= 0x8e4b1395u; m ^= s18;
        m *= 0x1f3d6a71u; m ^= s20; m ^= m >> 16;
        *(volatile uint32_t *)(ctx + 0x11c2) = m;
    } @catch (NSException *e) {}
}
static void *ACE_web_keeper(void *arg) {
    (void)arg;
// v7.38
    uint64_t lastC = 0;
    int n20 = 0;
    for (;;) {
        usleep(1000);
        while (g_addrTrapArmed) usleep(200);   // v7.70
        @try {
// ═══ v7.89 ═══
// v7.87
// v7.88
            if (g_tgt_base) {
                volatile uint8_t *p402 = (volatile uint8_t *)(g_tgt_base + 0x3ff3c2ULL);
                volatile uint8_t *p403 = (volatile uint8_t *)(g_tgt_base + 0x3ff3c3ULL);
                volatile uint8_t *p404 = (volatile uint8_t *)(g_tgt_base + 0x3ff3c4ULL);
                volatile uint8_t *p405 = (volatile uint8_t *)(g_tgt_base + 0x3ff3c5ULL);
                volatile uint8_t *p439 = (volatile uint8_t *)(g_tgt_base + 0x3ff3f9ULL);
                volatile uintptr_t *p408 = (volatile uintptr_t *)(g_tgt_base + 0x3ff3c8ULL);
                if (*p402 || *p403 || *p404 || *p405 || *p439) {
                    static long v89Log = 0;
                    if (v89Log < 30) {
                        v89Log++;
                        ACETrace(@"[v89] ★功能开关非零→钉0: 广角(402)=%u 加速(404)=%u 403=%u 405=%u 锁球(439)=%u (开关开=野调用, 已拆)",
                                 (unsigned)*p402, (unsigned)*p404, (unsigned)*p403,
                                 (unsigned)*p405, (unsigned)*p439);
                    }
                    *p402 = 0; *p403 = 0; *p404 = 0; *p405 = 0; *p439 = 0;
                }
// ═══ v7.92 ═══
// v7.89
                if (!g_cacheBase92) {
                    ACE_gscr_t f92 = ACE_gscr92();
                    size_t clen92 = 0;
                    const void *cr92 = f92 ? f92(&clen92) : 0;
                    if (cr92 && clen92) {
                        g_cacheBase92 = (uintptr_t)cr92;
                    } else {
                        uintptr_t lo92 = ~(uintptr_t)0;
                        uint32_t n92 = _dyld_image_count();
                        for (uint32_t i92 = 0; i92 < n92; i92++) {
                            const char *nm92 = _dyld_get_image_name(i92);
                            if (nm92 && strncmp(nm92, "/usr/lib/", 9) == 0) {
                                uintptr_t h92 = (uintptr_t)_dyld_get_image_header(i92);
                                if (h92 && h92 < lo92) lo92 = h92;
                            }
                        }
                        if (lo92 != ~(uintptr_t)0) g_cacheBase92 = lo92 & ~(uintptr_t)0x0ffffffULL;
                        ACETrace(@"[v92] dlsym共享缓存符号失败, 兜底显示基址 %p", (void *)g_cacheBase92);
                    }
                }
                if (g_cacheBase92 && *p408 != g_cacheBase92) {
                    static long v92Log = 0;
                    if (v92Log < 5) {
                        v92Log++;
                        ACETrace(@"[v92] ★基地址复原: [3ff408] %p → %p (共享缓存真基址, 面板显示与真机一致)",
                                 (void *)*p408, (void *)g_cacheBase92);
                    }
                    *p408 = g_cacheBase92;
                }
            }
// ═══ v7.91 ═══
            if (g_tgt_base) {
                volatile uintptr_t *ptok = (volatile uintptr_t *)(g_tgt_base + 0x3ff678ULL);
                if (*ptok == 0) {
                    static long v91Arms = 0;
                    void *blk91 = calloc(1, 0x1d28);
                    if (blk91) {
                        *ptok = (uintptr_t)blk91;
                        if (v91Arms < 40) {
                            v91Arms++;
                            ACETrace(@"[v91] ★命脉令牌伪造武装 [3ff6b8]=%p (第%ld次, calloc 0x1d28 全零=真发牌人同构)",
                                     blk91, v91Arms);
                        }
                    }
                }
            }
// ═══ v7.92 ═══
// 任何脱同步状态自愈。
            {
                static int v92Tick = 0;
// v7.93
                if (g_rw_dialog > 0 && ++v92Tick >= 500) {
                    v92Tick = 0;
                    ACE_apply_panel_hidden(g_panelWant);
                }
            }
            if (g_tgt_base) {
                uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff658);
                if (ctx >= 0x100000000ULL) {
                    uint64_t Cnow = *(volatile uint64_t *)(ctx + 0x119a);
                    if (Cnow != lastC) {
                        if (lastC != 0)
                            ACETrace(@"[creseed] C: %llx → %llx (谁在重播种?)", lastC, Cnow);
                        lastC = Cnow;
                        ACE_web_tick();
                        n20 = 0;
                        continue;
                    }
                }
            }
            if (++n20 >= 20) {
                n20 = 0;
                ACE_web_tick();
// v7.56
                if (g_nativeBuilt && g_tgt_base) {
                    volatile uint8_t *sw = (volatile uint8_t *)(g_tgt_base + 0x3ff7a4ULL);
// v7.90
// v7.89
// 误清则由这里顶回 — 两全。
                    if ((int)*sw != g_panelWant) *sw = (uint8_t)g_panelWant;
// v7.60
                    volatile uint32_t *tb = (volatile uint32_t *)(g_tgt_base + 0x3f28c0ULL);
                    if (tb[1] != 3u || tb[2] != 1u) { tb[0] = 125u; tb[1] = 3u; tb[2] = 1u; }
                }
// v7.56
                if (g_nativeBuilt && g_tgt_base) {
                    static int swCnt = 0, swLog = 0;
                    if (++swCnt >= 25) {
                        swCnt = 0;
                        uint64_t Sr = *(volatile uint64_t *)(g_tgt_base + 0x3ff660ULL) ^ 0xb75e8052babd72a6ULL;
                        uint32_t a8r = *(volatile uint32_t *)(g_tgt_base + 0x3ff668ULL);
                        uint32_t e2r = ACE_mix32((((uint32_t)Sr) ^ ((uint32_t)(Sr >> 32))) ^ 0xd18ddb25u);
                        if (a8r != e2r && swLog < 10) {
                            swLog++;
                            ACETrace(@"[Schain] ★撕裂/外部写者! S=%llu a8=%x 期望=%x (渲染链在滚动S链?)",
                                     (unsigned long long)Sr, a8r, e2r);
                        }
                    }
                }
            }
        } @catch (NSException *e) {}
    }
    return NULL;
}
// ═══ v7.31 ═══
// v7.30
static int g_freeze_n = 0;
static void *ACE_freezer(void *arg) {
    (void)arg;
    ACE_tt_fn real_tt = ACE_real_task_threads();
    if (!real_tt) return NULL;
    mach_port_t self95 = mach_thread_self();   // v7.95
    for (;;) {
        usleep(3000);
        @try {
            if (!g_tgt_base) continue;
            thread_act_array_t list = NULL;
            mach_msg_type_number_t n = 0;
            if (real_tt(mach_task_self(), &list, &n) != KERN_SUCCESS || !list) continue;
            for (unsigned i = 0; i < n; i++) {
                if (list[i] == g_main_th || list[i] == self95) continue;
                unsigned long long stt[34];
                memset(stt, 0, sizeof(stt));
                mach_msg_type_number_t c = 68;
                if (thread_get_state(list[i], ACE_ARM64_STATE, (thread_state_t)stt, &c) == 0 && c >= 66) {
                    uintptr_t pc = (uintptr_t)stt[32];
                    int z95 = -1;   // v7.95
                    if (pc >= g_tgt_base && pc < g_tgt_end) {
                        unsigned long long off95 = pc - g_tgt_base;
                        z95 = ace_freeze_zone(off95);
                        if (z95 < 0 && off95 >= 0x14e000ULL && off95 < 0x14f000ULL) {
                            unsigned long long lr95 = stt[30];
                            if (lr95 >= g_tgt_base && lr95 < g_tgt_end) {
                                unsigned long long lro95 = lr95 - g_tgt_base;
                                if (lro95 >= 0xadc98ULL && lro95 < 0xc67f0ULL) z95 = 9;
                            }
                        }
                    }
                    if (z95 >= 0) {
                        kern_return_t kr = thread_suspend(list[i]);
                        g_freeze_n++;
                        if (g_ace_ready && !g_ace_busy) {
                            g_ace_busy = 1;
                            ACETrace(@"[freeze#%d] 冻结复核线程#%u PC=+0x%lx kr=%d (永久挂起)",
                                     g_freeze_n, i, (unsigned long)(pc - g_tgt_base), kr);
                            g_ace_busy = 0;
                        }
                    }
                }
            }
            vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(mach_port_t));
        } @catch (NSException *e) {}
    }
    return NULL;
}
static void *ACE_ctx_monitor(void *arg);   // v7.13
static void *ACE_bp_installer(void *arg);   // v7.14
// ═══ v7.87 轻量槽监控 ═══
static void *ACE_slot_watch87(void *arg) {
    (void)arg;
    return NULL;   // v7.95
    uint8_t lastB1 = 0xff; uintptr_t last408 = ~(uintptr_t)0;
    uint32_t lastE4 = 0xffffffff; int lastPf = -1;
    uintptr_t lastTk = ~(uintptr_t)0;   // v7.90
    for (;;) {
        usleep(300000);
        if (!g_tgt_base) continue;
        uint8_t b1 = *(volatile uint8_t *)(g_tgt_base + 0x3ee7b1ULL);
        uintptr_t o8 = *(volatile uintptr_t *)(g_tgt_base + 0x3ff3c8ULL);
        uint32_t e4 = *(volatile uint32_t *)(g_tgt_base + 0x3f68a4ULL);
        int pf = (int)(*(volatile uint8_t *)(g_tgt_base + 0x3fc308ULL) & 1);
        uintptr_t tk = *(volatile uintptr_t *)(g_tgt_base + 0x3ff678ULL);   // v7.90
        if (b1 != lastB1 || o8 != last408 || e4 != lastE4 || pf != lastPf || tk != lastTk) {
            ACETrace(@"[v87] 槽变化: [3ee7b1主体] %u→%u [3ff408检测] %p→%p [3f68e4失败计数] %u→%u 面板flag %d→%d ★[3ff6b8命脉令牌] %p→%p",
                     (unsigned)lastB1, (unsigned)b1, (void *)last408, (void *)o8,
                     lastE4, e4, lastPf, pf, (void *)lastTk, (void *)tk);
            lastB1 = b1; last408 = o8; lastE4 = e4; lastPf = pf; lastTk = tk;
        }
    }
    return NULL;
}
static void ACE_install_v79_threads(void) {
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &at, ACE_flight_recorder, NULL);
// v7.24
    pthread_create(&th, &at, ACE_web_keeper, NULL);   // v7.24
    pthread_create(&th, &at, ACE_clock_keeper, NULL);   // v7.23
    pthread_create(&th, &at, ACE_freezer, NULL);   // v7.31
    pthread_create(&th, &at, ACE_ctx_monitor, NULL);
    pthread_create(&th, &at, ACE_slot_watch87, NULL);   // v7.87
// v7.22
    pthread_attr_destroy(&at);
    ACETrace(@"v7.9 飞行记录器+EndTime守护已启动");
}

// ═══ v7.14 ═══
// v7.94
typedef struct { unsigned long long bvr[16], bcr[16], wvr[16], wcr[16]; } ACEDbgState64;
#define ACE_ARM_DEBUG64 15
static const unsigned long long g_kill_sites[16] = {
    0x9e558ULL, 0xa5110ULL, 0xa51a8ULL, 0xa51fcULL, 0xa58c0ULL, 0xa59d8ULL,
    0xad710ULL, 0xc1d24ULL, 0xee3bcULL, 0xefde8ULL, 0xefe0cULL, 0xefe18ULL,
    0xf7f80ULL, 0xf6c34ULL, 0xf6c48ULL, 0xf6ce4ULL };
static int g_bp_logged = 0;
// v7.15
static ACE_tt_fn ACE_real_task_threads(void) {
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm || !strstr(nm, "libsystem_kernel")) continue;
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!mh) continue;
        const struct symtab_command *st = NULL;
        uintptr_t p = (uintptr_t)mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const ACESegCmd64 *lc = (const ACESegCmd64 *)p;
            if (lc->cmd == 0x2 ) { st = (const struct symtab_command *)p; break; }
            p += lc->cmdsize;
        }
        if (!st) continue;
        uintptr_t le_va = 0; uint64_t le_off = 0, le_sz = 0;
        p = (uintptr_t)mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const ACESegCmd64 *sg = (const ACESegCmd64 *)p;
            if (sg->cmd == 0x19  && !strcmp(sg->segname, "__LINKEDIT")) {
                le_va = (uintptr_t)(sg->vmaddr + slide);
                le_off = sg->fileoff; le_sz = sg->filesize;
                break;
            }
            p += sg->cmdsize;
        }
        if (!le_va) continue;
        const uint8_t *le = (const uint8_t *)le_va;
        const ACENlist64 *syms = (const ACENlist64 *)(le + (st->symoff - le_off));
        const char *strs = (const char *)(le + (st->stroff - le_off));
        for (uint32_t k = 0; k < st->nsyms; k++) {
            uint32_t so = syms[k].n_strx;
            if (so == 0 || so >= st->strsize) continue;
            const char *snm = strs + so;
            if (snm[0] == '_') snm++;
            if (!strcmp(snm, "task_threads") && syms[k].n_value) {
                ACE_tt_fn f = (ACE_tt_fn)(uintptr_t)(syms[k].n_value + slide);
                if (f != (ACE_tt_fn)&ACE_task_threads) {
                    ACETrace(@"[bp] 真实task_threads=%p (libsystem_kernel 符号表解析)", (void *)f);
                    return f;
                }
            }
        }
    }
    ACETrace(@"[bp] 镜像符号表解析失败, 哨兵无法安装");
    return NULL;
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
                ds.bcr[k] = 0x7ULL;
            }
            mach_msg_type_number_t c = 128;
            kern_return_t kr = thread_set_state(list[i], ACE_ARM_DEBUG64,
                                                (thread_state_t)&ds, c);
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

// ═══ v7.13 ═══
static void *ACE_ctx_monitor(void *arg) {
    (void)arg;
    return NULL;   // v7.95
    static const int offs[] = { 0x00, 0x74, 0x78, 0x88, 0x8c, 0x8e, 0x92, 0x96, 0x1196, 0x119a };
    const int NF = (int)(sizeof(offs) / sizeof(offs[0]));
    unsigned long long last[10];
    for (int i = 0; i < NF; i++) last[i] = 0xDEADBEEFULL;
    unsigned long seq = 0;
    for (;;) {
        usleep(20000);
        while (g_addrTrapArmed) usleep(200);   // v7.70
        @try {
            if (!g_tgt_base) continue;
            uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff658);
            if (ctx < 0x100000000ULL) continue;
            seq++;
            for (int i = 0; i < NF; i++) {
                unsigned long long v;
                if (offs[i] == 0x78) v = *(unsigned long long *)(ctx + 0x78);   // double 按位取
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

// ═══ v7.12 ═══
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
// ═══ v7.39 ═══
static uint32_t ACE_pmix32(uint32_t x) {
    x ^= x >> 15; x *= 0x1f3d6a71u; x ^= x >> 11; x *= 0x8e4b1395u;
    return x;
}
static void ACE_eq_snapshot(const char *tag) {
    @try {
        if (!g_tgt_base) return;
        uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff658);
        if (ctx < 0x100000000ULL) { ACETrace(@"[eq@%s] ctx未就绪", tag); return; }
        uint64_t S = *(volatile uint64_t *)(g_tgt_base + 0x3ff660) ^ 0xb75e8052babd72a6ULL;
        uint32_t a8 = *(volatile uint32_t *)(g_tgt_base + 0x3ff668);
        uint32_t ac = *(volatile uint32_t *)(g_tgt_base + 0x3ff66c);
        uint32_t b0 = *(volatile uint32_t *)(g_tgt_base + 0x3ff670);
        uint32_t Slo = (uint32_t)S, Shi = (uint32_t)(S >> 32);
        uint32_t e2 = ACE_mix32((Slo ^ Shi) ^ 0xd18ddb25u);   // v7.50
        uint32_t G  = ACE_pmix32(a8 ^ 0x1767cedcu);
        uint32_t e3 = (Slo ^ (G >> 17)) ^ G;   // v7.61
        uint32_t H  = ACE_pmix32(ac ^ 0x5d41c293u);
        uint32_t e4 = (Shi ^ (H >> 17)) ^ H;
        mach_timebase_info_data_t ti; mach_timebase_info(&ti);
        uint64_t ms = ti.denom ? ((uint64_t)mach_absolute_time() * ti.numer / ti.denom) / 1000000ULL : 0;
        long long age = (long long)ms - (long long)S;
        uint64_t C = *(volatile uint64_t *)(ctx + 0x119a);
        uint64_t A = *(volatile uint64_t *)(ctx + 0x11a2);
        uint64_t E = (uint64_t)(*(volatile long long *)(ctx + 0x78));
        uint32_t p8e = *(volatile uint32_t *)(ctx + 0x8e);
        uint32_t p92 = *(volatile uint32_t *)(ctx + 0x92);
        uint32_t c0  = *(volatile uint32_t *)ctx;
        uint32_t s10 = *(volatile uint32_t *)(ctx + 0x11aa);
        uint32_t s18 = *(volatile uint32_t *)(ctx + 0x11b2);
        uint32_t s20 = *(volatile uint32_t *)(ctx + 0x11ba);
        uint32_t chk = *(volatile uint32_t *)(ctx + 0x11c2);
        uint32_t e10 = (uint32_t)(C >> 7)  ^ s10 ^ 0x4a9b5206u;
        uint32_t e11 = (uint32_t)(C >> 13) ^ s18 ^ 0x8c1a73e5u;
        uint32_t e12 = (uint32_t)(C >> 19) ^ s20 ^ 0x5f8a16e3u;
        uint32_t m = (uint32_t)(A >> 32) ^ (uint32_t)A;
        m *= 0x45d9f3b7u; m ^= s10; m *= 0x8e4b1395u; m ^= s18;
        m *= 0x1f3d6a71u; m ^= s20; m ^= m >> 16;
        int f1 = (a8 == 0), f2 = (a8 != e2), f3 = (ac != e3), f4 = (b0 != e4);
        int f5 = (age < 0 || age > 45000);
        int f6 = (p8e == 0), f7 = (p92 == 0), f8 = (C == 0);
        int f9 = (E != (C ^ A ^ 0xa5c3e1f7b6d2489aULL));
        int f10 = (p8e != e10), f11 = (p92 != e11), f12 = (c0 != e12), f13 = (chk != m);
        ACETrace(@"[eq@%s] 1-4:%d%d%d%d 5:%d(age%lld) 6-8:%d%d%d 9:%d 10:%d 11:%d 12:%d 13:%d (1=FAIL)",
                 tag, f1, f2, f3, f4, f5, age, f6, f7, f8, f9, f10, f11, f12, f13);
        if (f9 | f10 | f11 | f12 | f13) {
            ACETrace(@"[eq@%s|vals] C=%llx E=%llx A=%llx c0=%x p8e=%x p92=%x s10=%x s18=%x s20=%x chk=%x calc=%x",
                     tag, C, E, A, c0, p8e, p92, s10, s18, s20, chk, m);
        }
        if (f2 | f3 | f4 | f5) {
            ACETrace(@"[eq@%s|S] S=%llu a8=%x/%x ac=%x/%x b0=%x/%x", tag, S, a8, e2, ac, e3, b0, e4);
        }
    } @catch (NSException *e) {}
}
static void ACE_tel_v(id self, SEL _cmd) {
    int i = ACE_tel_idx(_cmd);
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"[tel] %@ caller=TGT+0x%lx", NSStringFromSelector(_cmd), ACE_tel_caller());
        g_ace_busy = 0;
    }
// v7.39
    if (_cmd == NSSelectorFromString(@"q4")) ACE_eq_snapshot("q4");
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
    if (i >= 0 && g_tel_neuter[i]) return;   // 纯处决方法: 吞掉
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
    if (i >= 0 && g_tel_neuter[i]) return 0;   // 纯处决方法: 吞掉
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

// ═══ v7.7 ═══
// v7.5
// v7.7
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
    uint64_t segs[32]; unsigned nseg = 0;
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
    if (textsize < 0x100000) return 0;
    if (!ACE_addr_mapped(base, segs, nseg, base + 0xed44c, 4)) return 0;
    if (!ACE_addr_mapped(base, segs, nseg, base + 0xdc418, 4)) return 0;
    const uint32_t *p1 = (const uint32_t *)(base + 0xed44c);
    const uint32_t *p2 = (const uint32_t *)(base + 0xdc418);
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
// v7.19
static int g_ensure_tried = 0;
static void ACE_ensure_tgt_base(void) {
    if (g_tgt_base) return;
    if (g_ensure_tried > 200) return;
    g_ensure_tried++;
    const struct mach_header *hdr = ACE_find_target_header();
    if (!hdr) return;
    uintptr_t base = (uintptr_t)hdr;
    uint64_t textsize = 0x3e8000;
    ACELoadCmdHdr *c = (ACELoadCmdHdr *)(base + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < ((const struct mach_header_64 *)hdr)->ncmds; i++) {
        if (c->cmd == LC_SEGMENT_64) {
            const ACESegCmd64 *s64 = (const ACESegCmd64 *)c;
            if (s64->vmaddr == 0 && s64->vmsize > 0 && s64->vmsize < 0x10000000ULL &&
                strncmp(s64->segname, "__PAGEZERO", 16) != 0) { textsize = s64->vmsize; break; }
        }
        c = (ACELoadCmdHdr *)((uintptr_t)c + c->cmdsize);
    }
    g_tgt_base = base;
    g_tgt_end = base + (uintptr_t)textsize;
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"[pc] 靶场基址提前解析=%p (构造器期拦截已就绪)", (void *)base);
        g_ace_busy = 0;
    }
}
// v7.3
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
    uint64_t smap[16][4]; unsigned nsmap = 0;
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
                        if (si & 0xC0000000u) continue;
                        if (si >= st->nsyms) continue;   // 越界防御
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
// ═══ v7.87 ═══
static void ACE_probe_prologues(void);   // v8.05 前向声明
static void ACE_scan_rx_pools(void);   // v8.05 前向声明
static void ACE_dispatch_after_hook(unsigned long when, dispatch_queue_t q, void (^blk)(void)) {
    @try {
        if (blk && g_tgt_base) {
            void **hdrp = (void **)(__bridge void *)blk;
            uintptr_t inv = (uintptr_t)hdrp[2];
            if (inv >= g_tgt_base && inv < g_tgt_end) {
                uintptr_t off = inv - g_tgt_base;
                ACETrace(@"[dispA] +0x%lx", (unsigned long)off);
                if ((off >= 0xed550ULL && off < 0xf7870ULL) ||
                    (off >= 0xadc98ULL && off < 0xc67f0ULL)) {
                    ACETrace(@"[dispA] ★吞掉安保block +0x%lx (不派发)", (unsigned long)off);
                    return;
                }
            }
        }
    } @catch (NSException *e) {}
    dispatch_after(when, q, blk);
}
static void ACE_dispatch_async_hook(dispatch_queue_t q, dispatch_block_t blk) {
    @try {
        if (blk && g_tgt_base) {
            void **hdrp = (void **)(__bridge void *)blk;
            uintptr_t inv = (uintptr_t)hdrp[2];
            if (inv >= g_tgt_base && inv < g_tgt_end) {
                uintptr_t off = inv - g_tgt_base;
// v7.40
                uintptr_t ra0 = (uintptr_t)__builtin_return_address(0);
                unsigned long coff = (g_tgt_base && ra0 >= g_tgt_base && ra0 < g_tgt_end)
                                     ? (unsigned long)(ra0 - g_tgt_base) : 0UL;
                ACETrace(@"[disp] +0x%lx caller=+0x%lx", (unsigned long)off, coff);   // v7.11
                if (off == 0xed418ULL) {
                    volatile int32_t *slot = (volatile int32_t *)((uintptr_t)(__bridge void *)blk + 0x38);
                    if (*slot != 0) {
                        ACETrace(@"[hook] 弹窗验卡结果 %d → 0（强制成功路径）", *slot);
                        *slot = 0; g_rw_dialog++;
                        g_http_arm = 1;   // v8.08: 验卡后武装HTTPS轨迹
                    }
                    g_burst_until = (long long)time(NULL) + 30;   // v7.90
                    ACE_prime_endtime();
                    dispatch_after(dispatch_time(0, 500000000LL), dispatch_get_main_queue(), ^{
                        ACETrace(@"[measure] 验卡改写时刻加测"); ACE_probe_prologues(); ACE_scan_rx_pools(); });
                } else if (off == 0xdc418ULL) {
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
// ═══ v7.32 ═══
// ═══ v7.41 ═══
// v7.32
// v7.32
__attribute__((unused)) static int ACE_write_code(uintptr_t at, const uint32_t *words, unsigned n) {
    mach_msg_type_number_t len = n * 4;
    kern_return_t kr = vm_write(mach_task_self(), (vm_address_t)at,
                                (vm_offset_t)(uintptr_t)words, len);
    if (kr == KERN_SUCCESS) return 0;
    vm_address_t page = (vm_address_t)at & ~(vm_address_t)0x3FFF;
    kern_return_t kp = vm_protect(mach_task_self(), page, 0x4000, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kp != KERN_SUCCESS) return (int)kr;
    volatile uint32_t *p = (volatile uint32_t *)at;
    for (unsigned i = 0; i < n; i++) p[i] = words[i];
    vm_protect(mach_task_self(), page, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    return 0;
}
__attribute__((unused)) static int ACE_disarm_kills(void) {
// v8.00
// v8.00
    static const unsigned int koff[] = {
        0x31c14U, 0x9f668U, 0xa6220U, 0xa62b8U, 0xa630cU, 0xa69d0U,
        0xa6ae8U, 0xc2e34U, 0xd1818U, 0xd183cU, 0xe61c0U, 0xe6224U,
        0xefe34U, 0xefe40U, 0xf1738U, 0xf1744U, 0xf1768U, 0xf1774U,
        0xf2668U, 0xf8308U, 0xf83d0U, 0xf9580U, 0xf958cU,
    };
    static const unsigned int kpatch[] = {
        0x17ffffd6U, 0x17ffff02U, 0x17fff0d4U, 0x17fff0aeU,
        0x17fff099U, 0x17ffffedU, 0x17ffffceU, 0x17ffcda5U,
        0x17fffff0U, 0x17ffffe7U, 0x17ffffdfU, 0x17ffffc6U,
        0x17fffff0U, 0x17ffffedU, 0x17fffff0U, 0x17ffffedU,
        0x17ffffe4U, 0x17ffffe1U, 0x17ffffe5U, 0x17fffebbU,
        0x17fffe89U, 0x17fffa1dU, 0x17fffa1aU,
    };
    const uint32_t SVC = 0xd4001001U;   // svc #0x80
    int ok = 0, fail = 0, mism = 0, kr0 = 0, hkr = 0;
    for (unsigned i = 0; i < sizeof(koff) / sizeof(koff[0]); i++) {
        uintptr_t at = g_tgt_base + koff[i];
        volatile uint32_t *p = (volatile uint32_t *)at;
        if (*p != SVC) { mism++; continue; }   // 非svc=偏移漂移, 绝不动
        uint32_t w = kpatch[i];
        int r = ACE_write_code(at, &w, 1);
        if (r && !hkr) { kr0 = r; hkr = 1; }
        if (*p != w) { fail++; continue; }   // 回读校验
        sys_icache_invalidate((void *)at, 4);
        ok++;
    }
    {
        uintptr_t at = g_tgt_base + 0xae820U;
        volatile uint32_t *p = (volatile uint32_t *)at;
        if (*p == SVC) {
            uint32_t syn[2] = { 0xa8c17bfdU, 0xd65f03c0U };
            int r = ACE_write_code(at, syn, 2);
            if (r && !hkr) { kr0 = r; hkr = 1; }
            if (p[0] == syn[0] && p[1] == syn[1]) {
                sys_icache_invalidate((void *)at, 8); ok++;
            } else fail++;
        } else mism++;
    }
    ACETrace(@"[disarm] svc自毁点缴械: 成功=%d 失败=%d 偏移不符=%d kr0=%d%s",
             ok, fail, mism, kr0,
             (ok == 0 && kr0) ? " (vm_write+vm_protect全拒=代码签名禁改页, 需转静态重打包)" : "");
    return ok;
}
// ═══ v7.37 ═══
typedef int (*ACE_pc_fn)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static ACE_pc_fn g_real_pc = NULL;
static int ACE_pc_gate(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *), void *arg) {
// v7.39
    if (g_tgt_base && fn) {
        uintptr_t e = (uintptr_t)fn;
        if (e >= g_tgt_base && e < g_tgt_end) {
            unsigned long off = (unsigned long)(e - g_tgt_base);
            if (off == 0xadc98UL || off == 0xf0d24UL || off == 0xf2d38UL) {
                if (t) *t = (pthread_t)0;
                ACETrace(@"[gate] BLOCK entry=+0x%lx %s", off,
                         off == 0xadc98UL ? "reval" : (off == 0xf0d24UL ? "watchdog" : "verifier"));
                return 0;
            }
            ACETrace(@"[gate] pass entry=+0x%lx", off);
        } else {
            ACETrace(@"[gate] pass external fn=%p", fn);
        }
    }
    return g_real_pc(t, a, fn, arg);
}
// ═══ v7.40 ═══
static void (*g_orig_post2)(id, SEL, NSString *, id) = NULL;
static void ACE_post2(id self, SEL _cmd, NSString *name, id obj) {
    @try {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        if (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end
            && g_ace_ready && !g_ace_busy) {
            g_ace_busy = 1;
            ACETrace(@"[notif] post [%@] caller=TGT+0x%lx", name,
                     (unsigned long)(ra - g_tgt_base));
            g_ace_busy = 0;
        }
    } @catch (NSException *e) {}
    if (g_orig_post2) g_orig_post2(self, _cmd, name, obj);
}
// v7.41
static id (*g_orig_dc)(id, SEL) = NULL;
static id ACE_dc(id self, SEL _cmd) {
    @try {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        if (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end
            && g_ace_ready && !g_ace_busy) {
            g_ace_busy = 1;
            ACETrace(@"[nc] defaultCenter caller=TGT+0x%lx",
                     (unsigned long)(ra - g_tgt_base));
            g_ace_busy = 0;
        }
    } @catch (NSException *e) {}
    return g_orig_dc ? g_orig_dc(self, _cmd) : nil;
}
// ═══ v7.44 ═══
// v7.43
#define ACE_OBS_MAX 8
static NSString *g_obs_names[ACE_OBS_MAX];
static int g_obs_n = 0;
static void ACE_obs_capture(NSString *name, const char *api, uintptr_t ra) {
    if (!name || ![name isKindOfClass:[NSString class]]) return;
    @synchronized ([NSMutableArray class]) {
        for (int i = 0; i < g_obs_n; i++)
            if ([g_obs_names[i] isEqualToString:name]) return;   // 去重
        if (g_obs_n < ACE_OBS_MAX) g_obs_names[g_obs_n++] = [name copy];
    }
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"[obs] %s 注册观察者 name=[%@] caller=TGT+0x%lx", api, name,
                 (unsigned long)(ra - g_tgt_base));
        g_ace_busy = 0;
    }
}
static id (*g_orig_addObs4)(id, SEL, NSString *, id, id, void *) = NULL;
static id ACE_addObs4(id self, SEL _cmd, NSString *name, id obj, id queue, void *blk) {
    @try {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        if (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end)
            ACE_obs_capture(name, "addObserverForName", ra);
    } @catch (NSException *e) {}
    return g_orig_addObs4 ? g_orig_addObs4(self, _cmd, name, obj, queue, blk) : nil;
}
static void (*g_orig_addObsSel)(id, SEL, id, SEL, NSString *, id) = NULL;
static void ACE_addObsSel(id self, SEL _cmd, id observer, SEL sel, NSString *name, id obj) {
    @try {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        if (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end)
            ACE_obs_capture(name, "addObserverSel", ra);
    } @catch (NSException *e) {}
    if (g_orig_addObsSel) g_orig_addObsSel(self, _cmd, observer, sel, name, obj);
}
static void ACE_post_sec_notif(int attempt) {
    @try {
        NSString *names[ACE_OBS_MAX]; int n;
        @synchronized ([NSMutableArray class]) {
            n = g_obs_n;
            for (int i = 0; i < n; i++) names[i] = g_obs_names[i];
        }
        if (n == 0) { ACETrace(@"[notif-post] 尝试%d: 尚未捕获观察者通知名", attempt); return; }
        NSNotificationCenter *c = [NSNotificationCenter defaultCenter];
        for (int i = 0; i < n; i++) {
// v7.58
            if ([names[i] containsString:@"ResignActive"] || [names[i] containsString:@"Background"] ||
                [names[i] containsString:@"Foreground"]) {
                ACETrace(@"[notif-post] 尝试%d: 跳过生命周期通知[%@]", attempt, names[i]);
                continue;
            }
            ACETrace(@"[notif-post] 尝试%d: 代发[%@] (激活UI创建链, 观察者幂等)", attempt, names[i]);
            [c postNotificationName:names[i] object:nil];
        }
    } @catch (NSException *e) { ACETrace(@"[notif-post] 异常: %@", e); }
}
// ═══ v7.50 ═══
// v7.49
// v7.50
static void ACE_gates_dump(const char *tag) {
    @try {
        if (!g_tgt_base) return;
        uintptr_t B = g_tgt_base;
        int g1 = ((*(volatile uint8_t *)(B + 0x3fc308ULL)) & 1) == 0;   // 门1 幂等旗须0
        uint64_t S   = *(volatile uint64_t *)(B + 0x3ff660ULL) ^ 0xb75e8052babd72a6ULL;
        uint32_t Slo = (uint32_t)S, Shi = (uint32_t)(S >> 32);
        uint32_t a8  = *(volatile uint32_t *)(B + 0x3ff668ULL);
        uint32_t ac  = *(volatile uint32_t *)(B + 0x3ff66cULL);
        uint32_t b0  = *(volatile uint32_t *)(B + 0x3ff670ULL);
        int g2 = (a8 != 0);   // 门2 a8≠0
        uint32_t e2 = ACE_mix32((Slo ^ Shi) ^ 0xd18ddb25u);   // 门3 eq②真式
        int g3 = (a8 == e2);
        uint32_t G = ACE_pmix32(a8 ^ 0x1767cedcu);   // 门4 eq③
        int g4 = (ac == ((Slo ^ (G >> 17)) ^ G));   // v7.61
        uint32_t H = ACE_pmix32(ac ^ 0x5d41c293u);   // 门5 eq④
        int g5 = (b0 == ((Shi ^ (H >> 17)) ^ H));
        uint32_t tbInit = *(volatile uint32_t *)(B + 0x3fc314ULL);
        uint32_t tn = *(volatile uint32_t *)(B + 0x3fc30cULL);
        uint32_t td = *(volatile uint32_t *)(B + 0x3fc310ULL);
        if (!tbInit || !td) { mach_timebase_info_data_t ti; mach_timebase_info(&ti); tn = ti.numer; td = ti.denom; }
        uint64_t ms = td ? (((uint64_t)mach_absolute_time() * tn) / td) / 1000000ULL : 0;
        int g6 = (ms >= S);   // 门6 b.lo
        int g7 = ((ms - S) <= 45000ULL);   // 门7 b.hi
        uintptr_t ctx = *(volatile uintptr_t *)(B + 0x3ff658ULL);
        int g8 = (ctx >= 0x100000000ULL);   // 门8 ctx守卫
        int g9 = 0, g10 = 0, g11 = 0, g12 = 0, g13 = 0, g14 = 0, g15 = 0, g16 = 0;
        uint32_t c0 = 0, s20 = 0, chk = 0;
        uint64_t C = 0;
        if (g8) {
            uint32_t p8e = *(volatile uint32_t *)(ctx + 0x8e);
            uint32_t p92 = *(volatile uint32_t *)(ctx + 0x92);
            C   = *(volatile uint64_t *)(ctx + 0x119a);
            uint64_t A = *(volatile uint64_t *)(ctx + 0x11a2);
            uint64_t E = *(volatile uint64_t *)(ctx + 0x78);
            c0  = *(volatile uint32_t *)ctx;
            uint32_t s10 = *(volatile uint32_t *)(ctx + 0x11aa);
            uint32_t s18 = *(volatile uint32_t *)(ctx + 0x11b2);
            s20 = *(volatile uint32_t *)(ctx + 0x11ba);
            chk = *(volatile uint32_t *)(ctx + 0x11c2);
            g9  = (p8e != 0);   // 门9  0x120338
            g10 = (p92 != 0);   // 门10 0x120340
            g11 = (C != 0);   // 门11 0x120350
            g12 = (E == (C ^ A ^ 0xa5c3e1f7b6d2489aULL));   // 门12 eq⑨
            g13 = (p8e == ((uint32_t)(C >> 7)  ^ s10 ^ 0x4a9b5206u));   // 门13 eq⑩
            g14 = (p92 == ((uint32_t)(C >> 13) ^ s18 ^ 0x8c1a73e5u));   // 门14 eq⑪
            g15 = (c0  == ((uint32_t)(C >> 19) ^ s20 ^ 0x5f8a16e3u));   // 门15 eq⑫
            uint32_t m = (uint32_t)(A >> 32) ^ (uint32_t)A;   // 门16 eq⑬
            m *= 0x45d9f3b7u; m ^= s10; m *= 0x8e4b1395u; m ^= s18;
            m *= 0x1f3d6a71u; m ^= s20; m ^= m >> 16;
            g16 = (chk == m);
        }
        ACETrace(@"[gates@%s] %d%d%d%d%d%d%d|%d%d%d%d%d%d%d%d%d (1=过)",
                 tag, g1, g2, g3, g4, g5, g6, g7, g8, g9, g10, g11, g12, g13, g14, g15, g16);
        ACETrace(@"[gates@%s|raw] S=%llu Shi=%u age=%lld tb=%u/%u init=%u c0=%x",
                 tag, (unsigned long long)S, Shi, (long long)(ms - S), tn, td, tbInit, c0);
        if (!g3)  ACETrace(@"[gates@%s|G3] a8=%x 真式=%x 旧式(无Shi)=%x", tag, a8, e2, ACE_mix32(Slo ^ 0xd18ddb25u));
        if (!g5)  ACETrace(@"[gates@%s|G5] b0=%x 真式=%x", tag, b0, (Shi ^ (H >> 17)) ^ H);
        if (!g15) ACETrace(@"[gates@%s|G15] c0=%x 期望=%x (C>>19=%x s20=%x)", tag, c0,
                           (uint32_t)(C >> 19) ^ s20 ^ 0x5f8a16e3u, (uint32_t)(C >> 19), s20);
        if (!g16) ACETrace(@"[gates@%s|G16] chk=%x", tag, chk);
    } @catch (NSException *e) {}
}
// ═══ v7.50 ═══
static void ACE_build_panel_direct(int attempt) {
    @try {
        if (!g_tgt_base) return;
        volatile uint8_t *flag = (volatile uint8_t *)(g_tgt_base + 0x3fc308ULL);
        if (*flag & 1) {
            if (attempt == 1) ACETrace(@"[panel] 幂等标志已置位=面板早已构建, 盲点左上角即可");
            return;
        }
        uintptr_t blk = g_tgt_base + 0x3e9358ULL;
        void (*inv)(id) = (void (*)(id))*(uintptr_t *)(blk + 0x10);
        if (!inv) { ACETrace(@"[panel] 尝试%d: invoke指针为空", attempt); return; }
// v7.50
// v7.43
        uintptr_t ctx = *(volatile uintptr_t *)(g_tgt_base + 0x3ff658ULL);
        int waited = 0;
        while (ctx >= 0x100000000ULL && (*(volatile uint32_t *)ctx) != 0xffffffffu && waited < 100) {
            usleep(5000); waited++;
        }
        if (waited) ACETrace(@"[panel] 尝试%d: 等ctx[0]回-1 花了%dms", attempt, waited * 5);
// v7.50
        ACE_web_tick();
        g_freeze_web = 1;
        usleep(3000);
        ACE_gates_dump("pre");
        uint8_t tb0 = *(volatile uint8_t *)(g_tgt_base + 0x3fc314ULL);
        mach_timebase_info_data_t ti; mach_timebase_info(&ti);
// v7.52
        if (attempt <= 1) {
            volatile uint32_t *code = (volatile uint32_t *)(g_tgt_base + 0x11ed3cULL);
            ACETrace(@"[code] 运行时+0x11ed3c起6字: %08x %08x %08x %08x %08x %08x",
                     code[0], code[1], code[2], code[3], code[4], code[5]);
            ACETrace(@"[code] 文件期望:            14000001 d10543ff a90f6ffc a91067fa a9115ff8 a91257f6");
            volatile uint64_t *blkw = (volatile uint64_t *)(g_tgt_base + 0x3e9358ULL);
            ACETrace(@"[blk] isa=%llx flags=%llx invoke=%llx desc=%llx (文件flags=50000000 desc=3e9338)",
                     (unsigned long long)blkw[0], (unsigned long long)blkw[1],
                     (unsigned long long)blkw[2], (unsigned long long)blkw[3]);
        }
        uintptr_t sp0, sp1;
        __asm__ volatile("mov %0, sp" : "=r"(sp0));
        volatile uint64_t *pz = (volatile uint64_t *)(sp0 - 0x248ULL);
        for (int i = 0; i < 96; i++) pz[i] = 0xDEADBEEFCAFEBABEULL;
        uint64_t t0, t1;
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t0));
        if (attempt == 2) {
            void (*direct)(id) = (void (*)(id))(g_tgt_base + 0x11ed40ULL);
            direct(nil);
        } else {
            inv(nil);
        }
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t1));
        __asm__ volatile("mov %0, sp" : "=r"(sp1));
        int dirty = 0, didx[16]; uint64_t dval[16];
        for (int i = 0; i < 96 && dirty < 16; i++)
            if (pz[i] != 0xDEADBEEFCAFEBABEULL) { didx[dirty] = i - 73; dval[dirty] = pz[i]; dirty++; }
        g_freeze_web = 0;
        uint8_t tb1 = *(volatile uint8_t *)(g_tgt_base + 0x3fc314ULL);
        unsigned long ns = (unsigned long)((t1 - t0) * (uint64_t)ti.numer / (uint64_t)ti.denom);
        ACE_gates_dump("post");
        ACETrace(@"[panel] 尝试%d(%s): flag=%d tb=%d→%d 耗时=%lu.%03lums invoke=%p",
                 attempt, attempt == 2 ? "直调对照" : "invoke", (int)(*flag & 1), tb0, tb1,
                 ns / 1000000UL, (ns % 1000000UL) / 1000UL, (void *)inv);
        ACETrace(@"[stack] 尝试%d: 脏槽=%d sp漂移=%lld字节", attempt, dirty,
                 (long long)(sp1 - sp0));
        if (attempt <= 1)
            for (int i = 0; i < dirty && i < 12; i++)
                ACETrace(@"[stack|d] sp0%+d字 = %llx", didx[i] * 8, (unsigned long long)dval[i]);
        if (*flag & 1)
            ACETrace(@"[panel] ★尝试%d: 面板构建完成! 盲点左上角出面板", attempt);
    } @catch (NSException *e) { ACETrace(@"[panel] 异常: %@", e); }
}
// ═══ v7.54 ═══
static void ACE_visBallTap(void) {
    @try {
        if (!g_tgt_base) return;
// v7.56
        g_panelWant = g_panelWant ? 0 : 1;
        volatile uint8_t *sw = (volatile uint8_t *)(g_tgt_base + 0x3ff7a4ULL);
        *sw = (uint8_t)g_panelWant;
        ACETrace(@"[visball] 点击: 面板%@ (开关byte0=%d)", g_panelWant ? @"显示" : @"隐藏", g_panelWant);
// v7.73
        if (g_panelWant)
            dispatch_after(dispatch_time(0, 400000000LL), dispatch_get_main_queue(), ^{ ACE_diag_display(9); });
    } @catch (NSException *e) { ACETrace(@"[visball] 异常: %@", e); }
}
// ═══ v7.53 ═══
@interface ACEFbHelper : NSObject
- (void)fbToggle:(id)sender;
- (void)fbHide:(id)sender;
@end
static UIView *g_fbPanel = nil;
static UILabel *g_fbExpire = nil;
static void ACE_fb_refresh(void) {
    @try {
        if (!g_fbExpire) return;
        long long exp = 0;
        if (g_tgt_base) {
            uintptr_t ctx = *(volatile uintptr_t *)(g_tgt_base + 0x3ff658ULL);
            if (ctx >= 0x100000000ULL) exp = *(volatile long long *)(ctx + 0x78);
        }
        if (exp > 1000000000LL) {
            NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
            fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss";
            NSString *ds = [fmt stringFromDate:[NSDate dateWithTimeIntervalSince1970:(double)exp]];
            g_fbExpire.text = [NSString stringWithFormat:@"到期时间: %@", ds];
        } else {
            g_fbExpire.text = @"激活状态: 未激活";
        }
    } @catch (NSException *e) {}
}
@implementation ACEFbHelper
- (void)fbToggle:(id)sender {
    if (!g_fbPanel) return;
    g_fbPanel.hidden = !g_fbPanel.hidden;
    if (!g_fbPanel.hidden) {
        ACE_fb_refresh();
        [g_fbPanel.superview bringSubviewToFront:g_fbPanel];
    }
    ACETrace(@"[fbpanel] 点击热区 → 面板%@", g_fbPanel.hidden ? @"隐藏" : @"显示");
}
- (void)fbHide:(id)sender { g_fbPanel.hidden = YES; }
- (void)fbNativeToggle:(id)sender { ACE_visBallTap(); }   // v7.54
@end
static void ACE_install_fallback_panel(void) {
    return;   // v7.95
    static ACEFbHelper *helper = nil;
    if (helper) return;   // 幂等
    @try {
        if (g_tgt_base) {
            volatile uint8_t *flag = (volatile uint8_t *)(g_tgt_base + 0x3fc308ULL);
            if (*flag & 1) { ACETrace(@"[fbpanel] 原生面板已构建(flag=1), 无需自绘兜底"); return; }
        }
        UIApplication *app = [UIApplication sharedApplication];
        UIWindow *kw = app.keyWindow;
        if (!kw) for (UIWindow *w in app.windows) if (!w.hidden && w.alpha > 0.01) { kw = w; break; }
        if (!kw) {
            ACETrace(@"[fbpanel] 暂无可用窗口, 2s后重试");
            dispatch_after(dispatch_time(0, 2000000000LL), dispatch_get_main_queue(), ^{ ACE_install_fallback_panel(); });
            return;
        }
        helper = [[ACEFbHelper alloc] init];
        UIButton *hot = [[UIButton alloc] initWithFrame:CGRectMake(12, 54, 44, 44)];
        hot.backgroundColor = [UIColor clearColor];
        [hot addTarget:helper action:@selector(fbToggle:) forControlEvents:UIControlEventTouchUpInside];
        [kw addSubview:hot];
        g_fbPanel = [[UIView alloc] initWithFrame:CGRectMake(12, 104, 264, 148)];
        g_fbPanel.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.92];
        g_fbPanel.layer.cornerRadius = 12;
        g_fbPanel.hidden = YES;
        UILabel *ttl = [[UILabel alloc] initWithFrame:CGRectMake(14, 10, 236, 22)];
        ttl.text = @"激活状态: 已激活";
        ttl.textColor = [UIColor whiteColor];
        ttl.font = [UIFont boldSystemFontOfSize:16];
        [g_fbPanel addSubview:ttl];
        g_fbExpire = [[UILabel alloc] initWithFrame:CGRectMake(14, 38, 236, 20)];
        g_fbExpire.text = @"到期时间: 读取中...";
        g_fbExpire.textColor = [UIColor colorWithWhite:0.75 alpha:1.0];
        g_fbExpire.font = [UIFont systemFontOfSize:13];
        [g_fbPanel addSubview:g_fbExpire];
        UILabel *notice = [[UILabel alloc] initWithFrame:CGRectMake(14, 62, 236, 20)];
        notice.text = @"公告: 无";
        notice.textColor = [UIColor colorWithWhite:0.75 alpha:1.0];
        notice.font = [UIFont systemFontOfSize:13];
        [g_fbPanel addSubview:notice];
        UIButton *hideBtn = [[UIButton alloc] initWithFrame:CGRectMake(14, 94, 236, 38)];
        hideBtn.backgroundColor = [UIColor colorWithWhite:0.22 alpha:1.0];
        hideBtn.layer.cornerRadius = 8;
        [hideBtn setTitle:@"隐藏面板" forState:UIControlStateNormal];
        [hideBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        hideBtn.titleLabel.font = [UIFont systemFontOfSize:15];
        [hideBtn addTarget:helper action:@selector(fbHide:) forControlEvents:UIControlEventTouchUpInside];
        [g_fbPanel addSubview:hideBtn];
        [kw addSubview:g_fbPanel];
        [kw bringSubviewToFront:g_fbPanel];
        ACE_fb_refresh();
        ACETrace(@"[fbpanel] ★自绘面板已装: 点左上角(12,54 44×44透明热区)出3项面板");
    } @catch (NSException *e) { ACETrace(@"[fbpanel] 异常: %@", e); }
}
// ═══ v7.54 ═══
static UIButton *g_visBall = nil;
static UIWindow *g_visWin92 = nil;   // v7.92
// ═══ v7.92 ═══
@interface ACEPassWindow : UIWindow
@end
@implementation ACEPassWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:p withEvent:e];
    return (v == self) ? nil : v;
}
@end
// ═══ v7.95 ═══
static UIView *g_menuView95 = nil;
static CGPoint g_menuLast95;
static CGPoint g_menuStart95;
static int g_menuMoved95 = 0;
static void ACE_menu_toggle(void) {
    @try {
        g_panelWant = g_panelWant ? 0 : 1;
        if (g_tgt_base) *(volatile uint8_t *)(g_tgt_base + 0x3ff7a4ULL) = (uint8_t)g_panelWant;
        if (g_cfgPtr) *(volatile uint8_t *)g_cfgPtr = (uint8_t)g_panelWant;
        ACE_apply_panel_hidden(g_panelWant);
        ACETrace(@"[menu] 点按 → 意愿=%d (byte0/cfgPtr 直写+视图同步, keeper 1ms 跟随)", g_panelWant);
    } @catch (NSException *e) { ACETrace(@"[menu] 切换异常: %@", e); }
}
static void ACE_apply_panel_hidden(int want) {
    @try {
        if (g_rw_dialog < 1) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                UIApplication *app95 = [UIApplication sharedApplication];
                UIWindow *kw95 = app95.keyWindow;
                if (!kw95) for (UIWindow *w95 in app95.windows)
                    if (!w95.hidden && w95.alpha > 0.01) { kw95 = w95; break; }
                if (!kw95) return;
                UIView *stack95[512]; int top95 = 0;
                stack95[top95++] = kw95;
                while (top95 > 0) {
                    UIView *v95 = stack95[--top95];
                    NSString *cn95 = NSStringFromClass([v95 class]);
                    if ([cn95 containsString:@"1E6B7A93"]) {
                        BOOL h95 = (want == 0);
                        if (v95.hidden != h95) {
                            v95.hidden = h95;
                            ACETrace(@"[v92] 面板视图hidden同步=%d (意愿=%d)", (int)h95, want);
                        }
                    }
                    for (UIView *s95 in v95.subviews)
                        if (top95 < 512) stack95[top95++] = s95;
                }
            } @catch (NSException *e) {}
        });
    } @catch (NSException *e) {}
}
@interface ACEMenuView : UIView
@end
@implementation ACEMenuView
- (instancetype)initWithFrame:(CGRect)f {
    if ((self = [super initWithFrame:f])) {
        self.backgroundColor = [UIColor colorWithWhite:0.15 alpha:0.65];
        self.layer.cornerRadius = f.size.width / 2;
        UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, f.size.width, f.size.height)];
        lb.text = @"菜单";
        lb.textColor = [UIColor whiteColor];
        lb.font = [UIFont boldSystemFontOfSize:13];
        lb.userInteractionEnabled = NO;
        [self addSubview:lb];
    }
    return self;
}
- (void)touchesBegan:(NSSet *)t withEvent:(UIEvent *)e {
    (void)e;
    UITouch *to = [t anyObject];
    UIView *sv = self.superview; if (!sv) return;
    g_menuStart95 = [to locationInView:sv];
    g_menuLast95 = g_menuStart95;
    g_menuMoved95 = 0;
}
- (void)touchesMoved:(NSSet *)t withEvent:(UIEvent *)e {
    (void)e;
    UITouch *to = [t anyObject];
    UIView *sv = self.superview; if (!sv) return;
    CGPoint p = [to locationInView:sv];
    if (!g_menuMoved95) {
        CGFloat dx = p.x - g_menuStart95.x, dy = p.y - g_menuStart95.y;
        if (dx * dx + dy * dy > 64) g_menuMoved95 = 1;   // >8pt 判拖拽
    }
    if (g_menuMoved95) {
        CGPoint c = self.center;
        c.x += p.x - g_menuLast95.x;
        c.y += p.y - g_menuLast95.y;
        CGFloat hw = self.bounds.size.width / 2, hh = self.bounds.size.height / 2;
        if (c.x < hw) c.x = hw;
        if (c.y < hh) c.y = hh;
        if (c.x > sv.bounds.size.width - hw) c.x = sv.bounds.size.width - hw;
        if (c.y > sv.bounds.size.height - hh) c.y = sv.bounds.size.height - hh;
        self.center = c;
        g_menuLast95 = p;
    }
}
- (void)touchesEnded:(NSSet *)t withEvent:(UIEvent *)e {
    (void)t; (void)e;
    if (!g_menuMoved95) ACE_menu_toggle();   // 点一下=必切换一次
    g_menuMoved95 = 0;
}
- (void)touchesCancelled:(NSSet *)t withEvent:(UIEvent *)e {
    (void)t; (void)e;
    g_menuMoved95 = 0;
}
@end
static void ACE_install_visible_ball(void) {
    static int installed95 = 0;
    if (installed95) return;   // 幂等
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        UIWindow *kw = app.keyWindow;
        if (!kw) for (UIWindow *w in app.windows) if (!w.hidden && w.alpha > 0.01) { kw = w; break; }
        if (!kw) {
            dispatch_after(dispatch_time(0, 2000000000LL), dispatch_get_main_queue(), ^{ ACE_install_visible_ball(); });
            return;
        }
        installed95 = 1;
// v7.91
        g_visWin92 = [[ACEPassWindow alloc] initWithFrame:kw.bounds];
        g_visWin92.windowLevel = 2100;
        g_visWin92.backgroundColor = [UIColor clearColor];
        g_visWin92.hidden = NO;
        g_menuView95 = [[ACEMenuView alloc] initWithFrame:CGRectMake(2, 26, 45, 45)];
        [g_visWin92 addSubview:g_menuView95];
        ACETrace(@"[menu] ★菜单球已装(全屏透传顶层窗, 可拖动, 点按=必切换面板显隐)");
    } @catch (NSException *e) { ACETrace(@"[menu] 安装异常: %@", e); }
}
// ═══ v7.54 ═══
// v7.52
// ═══ v7.57 ═══
static void (*g_orig_draw)(id, SEL, id) = NULL;
static void (*g_orig_73)(id, SEL, id) = NULL;
static volatile int g_drawCalls = 0;   // v7.58
// v7.58
static void ACE_drive_draw(id m) {
    @try {
        if (m) ((void (*)(id, SEL))objc_msgSend)(m, NSSelectorFromString(@"draw"));
    } @catch (NSException *e) {}
    dispatch_after(dispatch_time(0, 16000000LL), dispatch_get_main_queue(), ^{ ACE_drive_draw(m); });
}
static void ACE_hook_73(id self, SEL _cmd, id n) {
    @try { ACETrace(@"[73] _0x73C9A1E5: 被调用(后台/resign通知→可能藏面板) notif=%@", n); } @catch (NSException *e) {}
    if (g_orig_73) g_orig_73(self, _cmd, n);
}
// ═══ v7.66 ═══
static void (*g_orig_setHidden)(id, SEL, BOOL) = NULL;
static void ACE_hook_setHidden(id self, SEL _cmd, BOOL h) {
    @try {
        void *ra = __builtin_return_address(0);
        uintptr_t ro = (uintptr_t)ra;
        uintptr_t off = (g_tgt_base && ro >= g_tgt_base && ro < g_tgt_base + 0x3e8000ULL)
                        ? (ro - g_tgt_base) : 0;
        static uint64_t shLast = 0; static long shCnt = 0;
        mach_timebase_info_data_t ti; mach_timebase_info(&ti);
        uint64_t now = (mach_absolute_time() * (uint64_t)ti.numer / (uint64_t)ti.denom) / 1000000ULL;
        shCnt++;
        if (now - shLast > 1000ULL) {
            shLast = now;
            ACETrace(@"[setHidden] h=%d caller=%llx(8d0e4=失败分支 8d140=成功分支 8c7c0=init) 1s次数=%ld self=%p",
                     (int)h, (unsigned long long)off, shCnt, (__bridge void *)self);
            shCnt = 0;
        }
    } @catch (NSException *e) {}
    if (g_orig_setHidden) g_orig_setHidden(self, _cmd, h);
}
static void ACE_hook_draw(id self, SEL _cmd, id view) {
    g_drawCalls++;   // v7.58
// ═══ v7.62 帧级裁决探针 ═══
    static volatile long g_vTot = 0, g_vFail = 0;
    static uint64_t vLastNs = 0; static int vCnt = 0;
    volatile uint8_t *vsw = g_tgt_base ? (volatile uint8_t *)(g_tgt_base + 0x3ff7a4ULL) : NULL;
    int preHid = (int)((UIView *)self).hidden;
    if (vsw) *vsw = (uint8_t)g_panelWant;
// ═══ v7.74 ═══
    if (!g_cfgPtr && g_mtkView)
        g_cfgPtr = ((void *(*)(id, SEL))objc_msgSend)(g_mtkView, NSSelectorFromString(@"_0xE4C8719B"));
    if (g_cfgPtr) *(volatile uint8_t *)g_cfgPtr = (uint8_t)g_panelWant;
    uint8_t preB0 = vsw ? *vsw : 0;
    @try {
        if (g_tgt_base) {
            static uint64_t lastNs = 0; static int cnt = 0;
            mach_timebase_info_data_t ti; mach_timebase_info(&ti);
            uint64_t nowNs = mach_absolute_time() * (uint64_t)ti.numer / (uint64_t)ti.denom;
            if (cnt < 30 && nowNs - lastNs > 1000000000ULL) {
                lastNs = nowNs;
                uintptr_t B = g_tgt_base;
                uint64_t S = *(volatile uint64_t *)(B + 0x3ff660ULL) ^ 0xb75e8052babd72a6ULL;
                uint32_t Slo = (uint32_t)S, Shi = (uint32_t)(S >> 32);
                uint32_t a8 = *(volatile uint32_t *)(B + 0x3ff668ULL);
                uint32_t ac = *(volatile uint32_t *)(B + 0x3ff66cULL);
                uint32_t b0 = *(volatile uint32_t *)(B + 0x3ff670ULL);
                uint32_t e2 = ACE_mix32((Slo ^ Shi) ^ 0xd18ddb25u);
                uint32_t G = ACE_pmix32(a8 ^ 0x1767cedcu);
                uint32_t e3 = (Slo ^ (G >> 17)) ^ G;   // v7.61
                uint32_t H = ACE_pmix32(ac ^ 0x5d41c293u);
                uint32_t e4 = (Shi ^ (H >> 17)) ^ H;
                uint64_t ms = nowNs / 1000000ULL;
                uintptr_t ctx = *(volatile uintptr_t *)(B + 0x3ff658ULL);
                uint32_t p8e = 0, p92 = 0, c0 = 0, s10 = 0, s18 = 0, s20 = 0, chk = 0;
                uint64_t C = 0, A = 0, E = 0;
                if (ctx >= 0x100000000ULL) {
                    p8e = *(volatile uint32_t *)(ctx + 0x8e); p92 = *(volatile uint32_t *)(ctx + 0x92);
                    C = *(volatile uint64_t *)(ctx + 0x119a); A = *(volatile uint64_t *)(ctx + 0x11a2);
                    E = *(volatile uint64_t *)(ctx + 0x78); c0 = *(volatile uint32_t *)ctx;
                    s10 = *(volatile uint32_t *)(ctx + 0x11aa); s18 = *(volatile uint32_t *)(ctx + 0x11b2);
                    s20 = *(volatile uint32_t *)(ctx + 0x11ba); chk = *(volatile uint32_t *)(ctx + 0x11c2);
                }
                uint32_t m = (uint32_t)(A >> 32) ^ (uint32_t)A;
                m *= 0x45d9f3b7u; m ^= s10; m *= 0x8e4b1395u; m ^= s18;
                m *= 0x1f3d6a71u; m ^= s20; m ^= m >> 16;
                int f1 = (a8 == 0), f2 = (a8 != e2), f3 = (ac != e3), f4 = (b0 != e4);
                int f5 = (ms < S || ms - S > 45000ULL);
                int f6 = (ctx < 0x100000000ULL), f7 = (p8e == 0), f8 = (p92 == 0), f9 = (C == 0);
                int f10 = (E != (C ^ A ^ 0xa5c3e1f7b6d2489aULL));
                int f11 = (p8e != ((uint32_t)(C >> 7) ^ s10 ^ 0x4a9b5206u));
                int f12 = (p92 != ((uint32_t)(C >> 13) ^ s18 ^ 0x8c1a73e5u));
                int f13 = (c0 != ((uint32_t)(C >> 19) ^ s20 ^ 0x5f8a16e3u));
                int f14 = (chk != m);
                unsigned bits = (unsigned)(f1 | f2 << 1 | f3 << 2 | f4 << 3 | f5 << 4 | f6 << 5 |
                                           f7 << 6 | f8 << 7 | f9 << 8 | f10 << 9 | f11 << 10 |
                                           f12 << 11 | f13 << 12 | f14 << 13);
                ACETrace(@"[drawgate] 活体评估 bits=0x%x c0=%x age=%lld hidden=%d S=%llu C=%llx",
                         bits, c0, (long long)(ms - S), preHid, (unsigned long long)S, (unsigned long long)C);
                cnt++;
            }
        }
    } @catch (NSException *e) {}
// ═══ v7.63 帧内同步快照喂值 ═══
    uint64_t snapS = 0; uint32_t snapA8 = 0, snapAc = 0, snapB0 = 0;   // v7.65
    g_freeze_web = 1;
    usleep(2000);
    @try {
        if (g_tgt_base) {
            mach_timebase_info_data_t ti3; mach_timebase_info(&ti3);
            uint64_t Ss = (mach_absolute_time() * (uint64_t)ti3.numer / (uint64_t)ti3.denom) / 1000000ULL;
            uint32_t SloS = (uint32_t)Ss, ShiS = (uint32_t)(Ss >> 32);
            uint32_t a8s = ACE_mix32((SloS ^ ShiS) ^ 0xd18ddb25u);
            uint32_t t2s = a8s ^ 0x1767cedcu;
            t2s ^= t2s >> 15; t2s *= 0x1f3d6a71u; t2s ^= t2s >> 11; t2s *= 0x8e4b1395u;
            uint32_t acs = SloS ^ (t2s >> 17) ^ t2s;
            uint32_t t3s = acs ^ 0x5d41c293u;
            t3s ^= t3s >> 15; t3s *= 0x1f3d6a71u; t3s ^= t3s >> 11; t3s *= 0x8e4b1395u;
            uint32_t b0s = ShiS ^ (t3s >> 17) ^ t3s;
            *(volatile uint32_t *)(g_tgt_base + 0x3ff668ULL) = a8s;
            *(volatile uint32_t *)(g_tgt_base + 0x3ff66cULL) = acs;
            *(volatile uint32_t *)(g_tgt_base + 0x3ff670ULL) = b0s;
            *(volatile uint64_t *)(g_tgt_base + 0x3ff660ULL) = Ss ^ 0xb75e8052babd72a6ULL;
            snapS = Ss; snapA8 = a8s; snapAc = acs; snapB0 = b0s;   // v7.65
// ═══ v7.67 执行水印 ═══
            volatile uint32_t *wtb = (volatile uint32_t *)(g_tgt_base + 0x3f28c0ULL);
            wtb[0] = 0xdeadbeefu; wtb[1] = 0xdeadbeefu; wtb[2] = 0u;
// ═══ v7.64 双探针 ═══
            static int c2Once = 0;
            if (!c2Once) {
                c2Once = 1;
                static const uintptr_t cOff[9] = { 0x8bd14ULL, 0x8bd74ULL, 0x8bda8ULL, 0x8bdb0ULL,
                                                   0x8bdecULL, 0x8be44ULL, 0x8be50ULL, 0x8bf98ULL, 0x8bf9cULL };
                static const uint32_t cExp[9] = { 0x34001468u, 0x6b0b015fu, 0x4a4946ccu, 0x6b09017fu,
                                                  0x6b08013fu, 0xeb160108u, 0x54000a88u, 0x6b09011fu, 0x540003e0u };
                NSMutableString *cs = [NSMutableString string];
                int cBad = 0;
                for (int i = 0; i < 9; i++) {
                    uint32_t cw = *(volatile uint32_t *)(g_tgt_base + cOff[i]);
                    if (cw != cExp[i]) cBad++;
                    [cs appendFormat:@"%x:%x%s ", (unsigned)(uintptr_t)cOff[i], cw, cw == cExp[i] ? "" : "!!"];
                }
                ACETrace(@"[code2] draw门码字(偏移:运行时,!!=与文件不符) 失配=%d %@", cBad, cs);
// v7.66
                uint32_t fp = 0;
                for (uintptr_t o = 0x8bcc0ULL; o < 0x8c02cULL; o += 4) {
                    uint32_t w = *(volatile uint32_t *)(g_tgt_base + o);
                    fp = ((fp ^ w) * 0x9e3779b1u) + (uint32_t)o;
                }
                ACETrace(@"[code3] 门段全220字指纹=%08x 期望=be2d9c22 %s",
                         fp, fp == 0xbe2d9c22u ? "✓全段一致" : "★★★不一致=代码被换!");
            }
            static uint64_t rdLast = 0;
            if (Ss - rdLast > 1000ULL) {
                rdLast = Ss;
                uint64_t Sraw = *(volatile uint64_t *)(g_tgt_base + 0x3ff660ULL);
                uint32_t a8r = *(volatile uint32_t *)(g_tgt_base + 0x3ff668ULL);
                uint32_t acr = *(volatile uint32_t *)(g_tgt_base + 0x3ff66cULL);
                uint32_t b0r = *(volatile uint32_t *)(g_tgt_base + 0x3ff670ULL);
                ACETrace(@"[rawdump] S槽=%llx 解=%llu a8=%x(写=%x) ac=%x(写=%x) b0=%x(写=%x)",
                         (unsigned long long)Sraw, (unsigned long long)Ss,
                         a8r, a8s, acr, acs, b0r, b0s);
                uintptr_t rctx = *(volatile uintptr_t *)(g_tgt_base + 0x3ff658ULL);
                if (rctx >= 0x100000000ULL) {
                    uint64_t rC = *(volatile uint64_t *)(rctx + 0x119a);
                    uint64_t rA = *(volatile uint64_t *)(rctx + 0x11a2);
                    uint64_t rE = *(volatile uint64_t *)(rctx + 0x78);
                    uint32_t rc0 = *(volatile uint32_t *)rctx;
                    uint32_t rs10 = *(volatile uint32_t *)(rctx + 0x11aa);
                    uint32_t rs18 = *(volatile uint32_t *)(rctx + 0x11b2);
                    uint32_t rs20 = *(volatile uint32_t *)(rctx + 0x11ba);
                    uint32_t rchk = *(volatile uint32_t *)(rctx + 0x11c2);
                    uint32_t rp8e = *(volatile uint32_t *)(rctx + 0x8e);
                    uint32_t rp92 = *(volatile uint32_t *)(rctx + 0x92);
                    uint32_t xp8e = (uint32_t)(rC >> 7) ^ rs10 ^ 0x4a9b5206u;
                    uint32_t xp92 = (uint32_t)(rC >> 13) ^ rs18 ^ 0x8c1a73e5u;
                    uint32_t xc0 = (uint32_t)(rC >> 19) ^ rs20 ^ 0x5f8a16e3u;
                    uint64_t xE = rC ^ rA ^ 0xa5c3e1f7b6d2489aULL;
                    uint32_t xm = (uint32_t)(rA >> 32) ^ (uint32_t)rA;
                    xm *= 0x45d9f3b7u; xm ^= rs10; xm *= 0x8e4b1395u; xm ^= rs18;
                    xm *= 0x1f3d6a71u; xm ^= rs20; xm ^= xm >> 16;
                    ACETrace(@"[rawdump2] C=%llx A=%llx E=%llx(期=%llx) c0=%x(期=%x)",
                             (unsigned long long)rC, (unsigned long long)rA,
                             (unsigned long long)rE, (unsigned long long)xE, rc0, xc0);
                    ACETrace(@"[rawdump3] p8e=%x(期=%x) p92=%x(期=%x) chk=%x(期=%x) s10=%x s18=%x s20=%x",
                             rp8e, xp8e, rp92, xp92, rchk, xm, rs10, rs18, rs20);
                }
            }
        }
    } @catch (NSException *e) {}
// ═══ v7.72 装弹 ═══
    int doTrap = (g_tgt_base != 0);
    if (doTrap) {
        g_addrTrapRounds++;
        ACE_arm_signal_trap();
        if (g_real_tsep && g_exc_port)
            g_real_tsep(mach_task_self(),
                        EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT,
                        g_exc_port, EXCEPTION_DEFAULT, ACE_ARM64_STATE);
        g_addrTrapArmed = 1;
        mprotect((void *)(g_tgt_base + 0x3fc000ULL), 16384, PROT_NONE);
    }
    @try {
        if (g_orig_draw) g_orig_draw(self, _cmd, view);
    } @catch (NSException *e) {
        ACETrace(@"[trap] draw异常穿透已兜底(页面即将恢复): %@", e);
    }
    if (doTrap) {
        mprotect((void *)(g_tgt_base + 0x3fc000ULL), 16384, PROT_READ | PROT_WRITE);
        g_addrTrapArmed = 0;
    }
// v7.67
    uint32_t wm0 = 0, wm1 = 0, wm2 = 0;
    @try {
        if (g_tgt_base) {
            volatile uint32_t *rtb = (volatile uint32_t *)(g_tgt_base + 0x3f28c0ULL);
            wm0 = rtb[0]; wm1 = rtb[1]; wm2 = rtb[2];
        }
    } @catch (NSException *e) {}
    g_freeze_web = 0;
    @try {
        uint8_t postB0 = vsw ? *vsw : 0;
        int postHid = (int)((UIView *)self).hidden;
        g_vTot++;
        if (preB0 && postB0 == 0) g_vFail++;
// ═══ v7.65 执行期写者探针 ═══
// v7.64
        static volatile long g_xw = 0, g_wmHit = 0, g_wmMiss = 0;
// v7.67
        if (wm0 == 125u && wm1 == 3u && wm2 == 1u) g_wmHit++; else g_wmMiss++;
        if (snapS && g_tgt_base) {
            uint64_t xS = *(volatile uint64_t *)(g_tgt_base + 0x3ff660ULL) ^ 0xb75e8052babd72a6ULL;
            uint32_t x8 = *(volatile uint32_t *)(g_tgt_base + 0x3ff668ULL);
            uint32_t xc = *(volatile uint32_t *)(g_tgt_base + 0x3ff66cULL);
            uint32_t xb = *(volatile uint32_t *)(g_tgt_base + 0x3ff670ULL);
            if (xS != snapS || x8 != snapA8 || xc != snapAc || xb != snapB0) {
                g_xw++;
                if (g_xw <= 5)
                    ACETrace(@"[xw] ★执行期写者! 快照S=%llu a8=%x ac=%x b0=%x → 执行后S=%llu a8=%x ac=%x b0=%x",
                             (unsigned long long)snapS, snapA8, snapAc, snapB0,
                             (unsigned long long)xS, x8, xc, xb);
            }
        }
        mach_timebase_info_data_t ti2; mach_timebase_info(&ti2);
        uint64_t nowNs2 = mach_absolute_time() * (uint64_t)ti2.numer / (uint64_t)ti2.denom;
        if (nowNs2 - vLastNs > 1000000000ULL && vCnt < 60) {
            vLastNs = nowNs2; vCnt++;
            ACETrace(@"[verdict] 1s: 帧=%ld 失败分支=%ld 手术跳=%ld 执行期改写=%ld 水印:自初始化=%ld 未到达=%ld(槽=%x/%x/%x) 陷阱=%ld | preH=%d→postH=%d b0:%d→%d gpu:curD=%ld nil=%ld pres=%ld",
                     g_vTot, g_vFail, g_jumpCnt, g_xw, g_wmHit, g_wmMiss, wm0, wm1, wm2, g_addrTrapCnt,
                     preHid, postHid, (int)preB0, (int)postB0,
                     g_curDCnt, g_curDNil, g_presCnt);
// ═══ v7.74 ═══
            if (g_getDrawData) {
                @try {
                    void *dd = ((void *(*)(void))g_getDrawData)();
                    if (dd) {
                        uint32_t w0 = *(volatile uint32_t *)((uintptr_t)dd);
                        uint64_t w8 = *(volatile uint64_t *)((uintptr_t)dd + 8);
                        uint64_t w16 = *(volatile uint64_t *)((uintptr_t)dd + 16);
                        uint32_t w24 = *(volatile uint32_t *)((uintptr_t)dd + 24);
                        ACETrace(@"[dd] drawData=%p w0=%x w8=%llx w16=%llx w24=%x | m1=%ld n0=%ld m2=%ld m3=%ld (w8或w16非零=UI已建)",
                                 dd, w0, (unsigned long long)w8, (unsigned long long)w16, w24,
                                 g_m1Cnt, g_n0Cnt, g_m2Cnt, g_m3Cnt);
                        ACE_dump_wins80(2, g_vTot);   // v7.81
                        ACE_scan_windows82(g_vTot);   // v7.82
                    } else {
                        ACETrace(@"[dd] GetDrawData→nil | m1=%ld n0=%ld m2=%ld m3=%ld",
                                 g_m1Cnt, g_n0Cnt, g_m2Cnt, g_m3Cnt);
                    }
                } @catch (NSException *e) {}
            }
// ═══ v7.78 ═══
            @try {
                uintptr_t ctxp = *(volatile uintptr_t *)(g_tgt_base + 0x3ff840ULL);
                if (ctxp) {
                    static uint32_t prevScan[1536];
                    static int haveScan = 0;
                    int hitA = -1, hitB = -1; uint32_t growA = 0, growB = 0;
                    for (int i = 0; i < 1536; i++) {
                        uint32_t v = *(volatile uint32_t *)(ctxp + (size_t)i * 4);
                        if (haveScan) {
                            uint32_t d = v - prevScan[i];
                            if (d >= 20 && d <= 240 && v > 100) {
                                if (hitA < 0) { hitA = i; growA = d; }
                                else if (hitB < 0) { hitB = i; growB = d; }
                            }
                        }
                        prevScan[i] = v;
                    }
                    haveScan = 1;
                    uintptr_t fonts = *(volatile uintptr_t *)(ctxp + 0x50);
                    uint32_t f48 = fonts ? *(volatile uint32_t *)(fonts + 0x48) : 0;
                    uint32_t f19 = fonts ? (uint32_t)*(volatile uint8_t *)(fonts + 0x19) : 0;
                    void *f40 = fonts ? (void *)(uintptr_t)*(volatile uintptr_t *)(fonts + 0x40) : NULL;
                    ACETrace(@"[ctxd] 增长字段A:ctx+0x%x(+%u/s) B:ctx+0x%x(+%u/s) (任一≈帧率=NewFrame在跑) 探针帧=%ld | Fonts=%p +0x19=%u +0x40=%p +0x48=%u",
                             hitA * 4, growA, hitB * 4, growB, g_probeDraws,
                             (void *)fonts, f19, f40, f48);
                }
            } @catch (NSException *e) {}
// v7.68
            static int trapLogged = 0;
            if (!trapLogged && g_addrTrapCnt > 0) {
                trapLogged = 1;
                for (int n = 0; n < 3 && n < (int)g_addrTrapCnt; n++) {
                    unsigned long long tpc = g_trapPCs[n];
                    unsigned long long r8 = g_trapRegs[n][8], r9 = g_trapRegs[n][9];
                    unsigned long long r10 = g_trapRegs[n][10], r22 = g_trapRegs[n][22];
                    ACETrace(@"[trap#%d] PC=+%llx x8=+%llx x9=+%llx x10=+%llx x22=%llx (门1@8ce24时x9应=3ff6a8)",
                             n,
                             (unsigned long long)(tpc >= g_tgt_base ? tpc - g_tgt_base : tpc),
                             (unsigned long long)(r8 >= g_tgt_base && r8 < g_tgt_base + 0x400000ULL ? r8 - g_tgt_base : r8),
                             (unsigned long long)(r9 >= g_tgt_base && r9 < g_tgt_base + 0x400000ULL ? r9 - g_tgt_base : r9),
                             (unsigned long long)(r10 >= g_tgt_base && r10 < g_tgt_base + 0x400000ULL ? r10 - g_tgt_base : r10),
                             (unsigned long long)r22);
                }
            }
            g_vTot = 0; g_vFail = 0; g_xw = 0; g_wmHit = 0; g_wmMiss = 0;
        }
    } @catch (NSException *e) {}
}

// ═══ v7.73 显示链诊断 ═══
static id ACE_hook_curD(id self, SEL _cmd) {
    id d = g_orig_curD ? g_orig_curD(self, _cmd) : nil;
    g_curDCnt++;
    if (!d) {
        g_curDNil++;
        if (g_curDNil <= 3 || (g_curDNil % 600) == 0) {
            CGSize ds = {0, 0};
            if (g_mtkView)
                ds = ((CGSize (*)(id, SEL))objc_msgSend)(g_mtkView, NSSelectorFromString(@"drawableSize"));
            ACETrace(@"[gpu] ★currentDrawable→nil#%ld — drawable不可用=无画面直接原因 (drawableSize=%g×%g)",
                     g_curDNil, ds.width, ds.height);
        }
    } else if (g_curDCnt <= 2) {
        @try {
            id tex = ((id (*)(id, SEL))objc_msgSend)(d, NSSelectorFromString(@"texture"));
            long tw = tex ? (long)((NSUInteger (*)(id, SEL))objc_msgSend)(tex, NSSelectorFromString(@"width")) : -1;
            long th = tex ? (long)((NSUInteger (*)(id, SEL))objc_msgSend)(tex, NSSelectorFromString(@"height")) : -1;
            ACETrace(@"[gpu] currentDrawable→%p texture=%p size=%ld×%ld (GPU drawable有效)",
                     (__bridge void *)d, (__bridge void *)tex, tw, th);
        } @catch (NSException *e) { ACETrace(@"[gpu] curD读取异常: %@", e); }
    }
    return d;
}
static void ACE_hook_present(id cb, SEL _cmd, id drawable) {
    @try {
        if (drawable && g_mtlLayer && [drawable respondsToSelector:@selector(layer)]
                && (__bridge void *)((id (*)(id, SEL))objc_msgSend)(drawable, @selector(layer)) == g_mtlLayer) {
            g_presCnt++;
            if (g_presCnt <= 2 || (g_presCnt % 600) == 0)
                ACETrace(@"[gpu] presentDrawable#%ld — 帧已提交上屏(GPU侧在出帧)", g_presCnt);
        }
    } @catch (NSException *e) {}
    if (g_orig_pres) g_orig_pres(cb, _cmd, drawable);
}
static void ACE_install_gpu_probes(id mtk, Class clsM) {
    @try {
        g_mtkView = mtk;
        g_mtlLayer = (__bridge void *)[(UIView *)mtk layer];
        SEL selD = NSSelectorFromString(@"currentDrawable");
        Method mD = class_getInstanceMethod(clsM, selD);
        if (mD && !g_orig_curD) {
            g_orig_curD = (id (*)(id, SEL))method_getImplementation(mD);
            if (!class_addMethod(clsM, selD, (IMP)ACE_hook_curD, "@@:")) {
                Method m2 = class_getInstanceMethod(clsM, selD);
                if (m2) method_setImplementation(m2, (IMP)ACE_hook_curD);
            }
        }
        id dev = ((id (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"device"));
        id q = dev ? ((id (*)(id, SEL))objc_msgSend)(dev, NSSelectorFromString(@"newCommandQueue")) : nil;
        id cb = q ? ((id (*)(id, SEL))objc_msgSend)(q, NSSelectorFromString(@"commandBuffer")) : nil;
        const char *cbName = "-";
        if (cb) {
            Class cbCls = object_getClass(cb);
            cbName = class_getName(cbCls);
            Method mP = class_getInstanceMethod(cbCls, NSSelectorFromString(@"presentDrawable:"));
            if (mP && !g_orig_pres) {
                g_orig_pres = (void (*)(id, SEL, id))method_getImplementation(mP);
                method_setImplementation(mP, (IMP)ACE_hook_present);
            }
        }
        int fboSet = 0;
        if ([mtk respondsToSelector:NSSelectorFromString(@"setFramebufferOnly:")]) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(mtk, NSSelectorFromString(@"setFramebufferOnly:"), NO);
            fboSet = 1;
        }
        ACETrace(@"[gpu] 探针已装: curD=%d pres=%d cbCls=%s layer=%p dev=%d fbo=%d",
                 !!g_orig_curD, !!g_orig_pres, cbName, g_mtlLayer, !!dev, fboSet);
    } @catch (NSException *e) { ACETrace(@"[gpu] 探针异常: %@", e); }
}
// v7.73b
// v7.15
typedef struct {
    size_t (*igw)(CGImageRef);
    size_t (*igh)(CGImageRef);
    CGColorSpaceRef (*csc)(void);
    void (*csr)(CGColorSpaceRef);
    CGContextRef (*bcc)(void *, size_t, size_t, size_t, size_t, CGColorSpaceRef, uint32_t);
    void (*cdi)(CGContextRef, CGRect, CGImageRef);
    void (*cre)(CGContextRef);
} ACECgSyms;
static int ACE_load_cg_syms(ACECgSyms *out) {
    static ACECgSyms s;
    static int done = 0, ok = 0;
    if (done) { *out = s; return ok; }
    done = 1;
    memset(&s, 0, sizeof(s));
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm || !strstr(nm, "CoreGraphics")) continue;
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!mh) continue;
        const struct symtab_command *st = NULL;
        uintptr_t p = (uintptr_t)mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const ACESegCmd64 *lc = (const ACESegCmd64 *)p;
            if (lc->cmd == 0x2 ) { st = (const struct symtab_command *)p; break; }
            p += lc->cmdsize;
        }
        if (!st) continue;
        uintptr_t le_va = 0; uint64_t le_off = 0;
        p = (uintptr_t)mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const ACESegCmd64 *sg = (const ACESegCmd64 *)p;
            if (sg->cmd == 0x19  && !strcmp(sg->segname, "__LINKEDIT")) {
                le_va = (uintptr_t)(sg->vmaddr + slide);
                le_off = sg->fileoff;
                break;
            }
            p += sg->cmdsize;
        }
        if (!le_va) continue;
        const uint8_t *le = (const uint8_t *)le_va;
        const ACENlist64 *syms = (const ACENlist64 *)(le + (st->symoff - le_off));
        const char *strs = (const char *)(le + (st->stroff - le_off));
        int found = 0;
        for (uint32_t k = 0; k < st->nsyms; k++) {
            uint32_t so = syms[k].n_strx;
            if (so == 0 || so >= st->strsize || !syms[k].n_value) continue;
            const char *sn = strs + so;
            if (sn[0] == '_') sn++;
            void *fp = (void *)(uintptr_t)(syms[k].n_value + slide);
            if      (!strcmp(sn, "CGImageGetWidth"))             { s.igw = (size_t (*)(CGImageRef))fp; found++; }
            else if (!strcmp(sn, "CGImageGetHeight"))            { s.igh = (size_t (*)(CGImageRef))fp; found++; }
            else if (!strcmp(sn, "CGColorSpaceCreateDeviceRGB")) { s.csc = (CGColorSpaceRef (*)(void))fp; found++; }
            else if (!strcmp(sn, "CGColorSpaceRelease"))         { s.csr = (void (*)(CGColorSpaceRef))fp; found++; }
            else if (!strcmp(sn, "CGBitmapContextCreate"))       { s.bcc = (CGContextRef (*)(void *, size_t, size_t, size_t, size_t, CGColorSpaceRef, uint32_t))fp; found++; }
            else if (!strcmp(sn, "CGContextDrawImage"))          { s.cdi = (void (*)(CGContextRef, CGRect, CGImageRef))fp; found++; }
            else if (!strcmp(sn, "CGContextRelease"))            { s.cre = (void (*)(CGContextRef))fp; found++; }
            if (found >= 7) break;
        }
        ok = (s.igw && s.igh && s.csc && s.bcc && s.cdi) ? 1 : 0;
        if (ok) {
            ACETrace(@"[snap] CG符号镜像解析OK: found=%d igw=%p cdi=%p", found, (void *)s.igw, (void *)s.cdi);
            break;
        }
    }
    *out = s;
    return ok;
}
static void ACE_snap_window(UIWindow *pw, int run) {
    @try {
        CGRect b = pw.bounds;
        if (b.size.width < 1 || b.size.height < 1) {
            ACETrace(@"[snap#%d] 面板窗bounds=%@非法 — 快照无意义(几何即病根)", run, NSStringFromCGRect(b));
            return;
        }
        ACECgSyms cg;
        if (!ACE_load_cg_syms(&cg)) {
            ACETrace(@"[snap#%d] CG符号解析失败 — 快照放弃(diag/gpu/win-fix不受影响)", run);
            return;
        }
        UIGraphicsBeginImageContextWithOptions(b.size, NO, 0.5);
        [pw drawViewHierarchyInRect:b afterScreenUpdates:NO];
        UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
        CGImageRef cgi = img.CGImage;
        if (!cgi) { ACETrace(@"[snap#%d] 快照失败(无CGImage)", run); return; }
        size_t W = cg.igw(cgi), H = cg.igh(cgi);
        size_t bpr = W * 4;
        uint8_t *buf = (uint8_t *)calloc(bpr * H + 16, 1);
        if (!buf) return;
        CGColorSpaceRef cs = cg.csc();
        CGContextRef bc = cg.bcc(buf, W, H, 8, bpr, cs, (uint32_t)kCGImageAlphaPremultipliedLast);
        if (cg.csr) cg.csr(cs);
        if (!bc) { free(buf); ACETrace(@"[snap#%d] bitmap ctx创建失败", run); return; }
        cg.cdi(bc, CGRectMake(0, 0, (CGFloat)W, (CGFloat)H), cgi);
        if (cg.cre) cg.cre(bc);
        long nonT = 0, colored = 0, zoneNonT = 0;
        unsigned maxA = 0;
        for (size_t y = 0; y < H; y++) {
            const uint8_t *row = buf + y * bpr;
            for (size_t x = 0; x < W; x++) {
                const uint8_t *p = row + x * 4;
                unsigned a = p[3];
                if (a > maxA) maxA = a;
                if (a > 8) {
                    nonT++;
                    if ((unsigned)p[0] + p[1] + p[2] > 24) colored++;
                    if (x < W / 2 && y < H / 2) zoneNonT++;
                }
            }
        }
        ACETrace(@"[snap#%d] %zu×%zu 非透明=%ld 彩色=%ld maxA=%u 左上象限非透明=%ld/%ld %s",
                 run, W, H, nonT, colored, maxA, zoneNonT, (long)(W / 2) * (long)(H / 2),
                 nonT == 0 ? "★整窗全透明—窗口在但没画出任何内容(与gpu计数联判)" : "(有像素!)");
        size_t px[3] = { W / 8, W / 4, W / 2 }, py[3] = { H / 8, H / 4, H / 2 };
        for (int i = 0; i < 3; i++) {
            const uint8_t *p = buf + py[i] * bpr + px[i] * 4;
            ACETrace(@"[snap#%d] 样点(%zu,%zu) RGBA=(%u,%u,%u,%u)", run, px[i], py[i], p[0], p[1], p[2], p[3]);
        }
        free(buf);
    } @catch (NSException *e) { ACETrace(@"[snap#%d] 异常: %@", run, e); }
}
static void ACE_dump_mtk(int run) {
    id mtk = g_mtkView;
    if (!mtk) { ACETrace(@"[mtk#%d] g_mtkView未设", run); return; }
    @try {
        CGSize ds = ((CGSize (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"drawableSize"));
        ACEClearColor cc = ((ACEClearColor (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"clearColor"));
        BOOL paused = ((BOOL (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"isPaused"));
        long fps = (long)((NSInteger (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"preferredFramesPerSecond"));
        id dev = ((id (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"device"));
        UIView *mv = (UIView *)mtk;
        CALayer *ly = mv.layer;
        ACETrace(@"[mtk#%d] ds=(%g,%g) frame=%@ paused=%d fps=%ld dev=%d clear=(%g,%g,%g,a=%g)",
                 run, ds.width, ds.height, NSStringFromCGRect(mv.frame), (int)paused, fps, !!dev,
                 cc.r, cc.g, cc.b, cc.a);
        if ([ly respondsToSelector:NSSelectorFromString(@"drawableSize")]) {
            CGSize lds = ((CGSize (*)(id, SEL))objc_msgSend)(ly, NSSelectorFromString(@"drawableSize"));
            int fbo = [ly respondsToSelector:NSSelectorFromString(@"framebufferOnly")]
                    ? (int)((BOOL (*)(id, SEL))objc_msgSend)(ly, NSSelectorFromString(@"framebufferOnly")) : -1;
            ACETrace(@"[mtk#%d] layer=%s lyFrame=%@ lyDS=(%g,%g) lyHid=%d lyOp=%g fbo=%d",
                     run, class_getName(object_getClass(ly)), NSStringFromCGRect(ly.frame),
                     lds.width, lds.height, (int)ly.hidden, (double)ly.opacity, fbo);
        }
        int d = 0;
        for (UIView *v = mv; v && d < 8; v = v.superview, d++) {
            ACETrace(@"[mtk#%d] 链%d: %s(%p) frame=%@ hid=%d alpha=%g clips=%d",
                     run, d, class_getName(object_getClass(v)), (__bridge void *)v,
                     NSStringFromCGRect(v.frame), (int)v.hidden, (double)v.alpha, (int)v.clipsToBounds);
        }
    } @catch (NSException *e) { ACETrace(@"[mtk#%d] 异常: %@", run, e); }
}
static void ACE_dump_tree(UIView *v, int depth, int run) {
    if (!v || depth > 3) return;
    ACETrace(@"[tree#%d]%*s%s(%p) frame=%@ hid=%d alpha=%g layer=%s",
             run, depth * 2, "", class_getName(object_getClass(v)), (__bridge void *)v,
             NSStringFromCGRect(v.frame), (int)v.hidden, (double)v.alpha,
             class_getName(object_getClass(v.layer)));
    for (UIView *s in v.subviews) ACE_dump_tree(s, depth + 1, run);
}
static void ACE_diag_display(int run) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIApplication *app = [UIApplication sharedApplication];
            ACETrace(@"[diag#%d] ═══ 显示链诊断 ═══ key=%p screen=%@ gpu:curD=%ld nil=%ld pres=%ld",
                     run, (__bridge void *)app.keyWindow,
                     NSStringFromCGRect([UIScreen mainScreen].bounds),
                     g_curDCnt, g_curDNil, g_presCnt);
            for (UIWindow *w in app.windows) {
                ACETrace(@"[diag#%d] win=%p %s frame=%@ level=%g hid=%d alpha=%g scene=%d rootVC=%s rvFrame=%@",
                         run, (__bridge void *)w, class_getName(object_getClass(w)),
                         NSStringFromCGRect(w.frame), (double)w.windowLevel, (int)w.hidden, (double)w.alpha,
                         w.windowScene ? 1 : 0,
                         w.rootViewController ? class_getName(object_getClass(w.rootViewController)) : "-",
                         w.rootViewController ? NSStringFromCGRect(w.rootViewController.view.frame) : @"-");
            }
            if (g_tgt_base) {
                uintptr_t pwin = *(volatile uintptr_t *)(g_tgt_base + 0x3f2810ULL);
                UIWindow *pw = (__bridge UIWindow *)(void *)pwin;
                if (pw && [pw isKindOfClass:[UIWindow class]]) {
                    CGRect sb = [UIScreen mainScreen].bounds;
                    UIWindow *kw = app.keyWindow;
                    CGRect kf = (kw && kw != pw && kw.frame.size.width > 1) ? kw.frame : sb;
                    BOOL bad = (pw.frame.size.width < 1 || pw.frame.size.height < 1
                                || pw.frame.origin.x < -1 || pw.frame.origin.y < -1
                                || pw.frame.origin.x >= sb.size.width || pw.frame.origin.y >= sb.size.height);
                    if (bad || !pw.windowScene) {
                        ACETrace(@"[win-fix#%d] ★面板窗frame=%@ scene=%d → 矫正frame=%@ + hidden=NO alpha=1",
                                 run, NSStringFromCGRect(pw.frame), pw.windowScene ? 1 : 0,
                                 NSStringFromCGRect(kf));
                        if (!pw.windowScene && kw.windowScene) pw.windowScene = kw.windowScene;
                        if (bad) pw.frame = kf;
                        pw.hidden = NO; pw.alpha = 1;
                        [pw setNeedsLayout]; [pw layoutIfNeeded];
                    } else {
                        ACETrace(@"[win-fix#%d] 面板窗几何正常 frame=%@ scene=1", run, NSStringFromCGRect(pw.frame));
                    }
                    ACE_dump_tree(pw.rootViewController ? pw.rootViewController.view : (UIView *)pw, 0, run);
                    ACE_snap_window(pw, run);
                } else {
                    ACETrace(@"[diag#%d] 面板窗槽[0x3f2810]非法: %p", run, (void *)pwin);
                }
            }
            ACE_dump_mtk(run);
        } @catch (NSException *e) { ACETrace(@"[diag#%d] 异常: %@", run, e); }
    });
}
// ═══ v7.73 显示链诊断 END ═══

// ═══ v7.74 m1 取证+现场喂值 ═══
// v7.74
static uint64_t ACE_feed_chain_now(void) {
    volatile uint32_t *tb = (volatile uint32_t *)(g_tgt_base + 0x3f6b00);
    uint32_t num = tb[0], den = tb[1];
    if (!num || !den) { num = 125; den = 3; }
    uint64_t ns = (uint64_t)mach_absolute_time() * num / den;
    uint64_t S = ns / 1000000ULL;
    uint32_t Slo = (uint32_t)S, Shi = (uint32_t)(S >> 32);
    *(volatile uint64_t *)(g_tgt_base + 0x3ff660) = S ^ 0xb75e8052babd72a6ULL;
    uint32_t a8 = ACE_mix32((Slo ^ Shi) ^ 0xd18ddb25u);
    *(volatile uint32_t *)(g_tgt_base + 0x3ff668) = a8;
    uint32_t t2 = a8 ^ 0x1767cedcu;
    t2 ^= t2 >> 15; t2 *= 0x1f3d6a71u; t2 ^= t2 >> 11; t2 *= 0x8e4b1395u;
    uint32_t ac = Slo ^ (t2 >> 17) ^ t2;
    *(volatile uint32_t *)(g_tgt_base + 0x3ff66c) = ac;
    uint32_t t3 = ac ^ 0x5d41c293u;
    t3 ^= t3 >> 15; t3 *= 0x1f3d6a71u; t3 ^= t3 >> 11; t3 *= 0x8e4b1395u;
    *(volatile uint32_t *)(g_tgt_base + 0x3ff670) = Shi ^ (t3 >> 17) ^ t3;
    return S;
}
static int ACE_eval_m1_gates(void) {
    int m = 0;
    uint64_t S = *(volatile uint64_t *)(g_tgt_base + 0x3ff660) ^ 0xb75e8052babd72a6ULL;
    uint32_t Slo = (uint32_t)S, Shi = (uint32_t)(S >> 32);
    uint32_t a8 = *(volatile uint32_t *)(g_tgt_base + 0x3ff668);
    uint32_t ac = *(volatile uint32_t *)(g_tgt_base + 0x3ff66c);
    uint32_t b0 = *(volatile uint32_t *)(g_tgt_base + 0x3ff670);
    if (a8) m |= 1;
    if (a8 == ACE_mix32((Slo ^ Shi) ^ 0xd18ddb25u)) m |= 2;
    uint32_t t2 = a8 ^ 0x1767cedcu;
    t2 ^= t2 >> 15; t2 *= 0x1f3d6a71u; t2 ^= t2 >> 11; t2 *= 0x8e4b1395u;
    if (ac == (Slo ^ (t2 >> 17) ^ t2)) m |= 4;
    uint32_t t3 = ac ^ 0x5d41c293u;
    t3 ^= t3 >> 15; t3 *= 0x1f3d6a71u; t3 ^= t3 >> 11; t3 *= 0x8e4b1395u;
    if (b0 == (Shi ^ (t3 >> 17) ^ t3)) m |= 8;
    {
        volatile uint32_t *tb2 = (volatile uint32_t *)(g_tgt_base + 0x3fad80);
        uint32_t n2 = tb2[0], d2 = tb2[1];
        if (!n2 || !d2) { n2 = 125; d2 = 3; }
        uint64_t nowMs = (uint64_t)mach_absolute_time() * n2 / d2 / 1000000ULL;
        if (nowMs >= S && (nowMs - S) <= 45000ULL) m |= 16;
    }
    uintptr_t ctx = *(volatile uintptr_t *)(g_tgt_base + 0x3ff658);
    if (ctx) {
        uint32_t p8e = *(volatile uint32_t *)(ctx + 0x8e);
        uint32_t p92 = *(volatile uint32_t *)(ctx + 0x92);
        uint64_t C = *(volatile uint64_t *)(ctx + 0x119a);
        uint64_t A = *(volatile uint64_t *)(ctx + 0x11a2);
        uint64_t E = *(volatile uint64_t *)(ctx + 0x78);
        uint64_t s10 = *(volatile uint64_t *)(ctx + 0x11aa);
        uint64_t s18 = *(volatile uint64_t *)(ctx + 0x11b2);
        uint64_t s20 = *(volatile uint64_t *)(ctx + 0x11ba);
        if (p8e && p92 && C) m |= 32;
        if ((C ^ A ^ 0xa5c3e1f7b6d2489aULL) == E) m |= 64;
        if ((((uint32_t)s10 ^ 0x4a9b5206u) ^ (uint32_t)(C >> 7)) == p8e
                && (((uint32_t)s18 ^ 0x8c1a73e5u) ^ (uint32_t)(C >> 13)) == p92
                && (((uint32_t)s20 ^ 0x5f8a16e3u) ^ (uint32_t)(C >> 19)) == *(volatile uint32_t *)ctx) m |= 128;
        uint32_t w = (uint32_t)(A >> 32) ^ (uint32_t)A;
        w *= 0x45d9f3b7u; w ^= (uint32_t)s10;
        w *= 0x8e4b1395u; w ^= (uint32_t)s18;
        w *= 0x1f3d6a71u; w ^= (uint32_t)s20;
        w ^= w >> 16;
        if (w == *(volatile uint32_t *)(ctx + 0x11c2)) m |= 256;
    }
    return m;
}
// ═══ v7.78 对照实验 + NewFrame 守卫强制放行 ═══
// v7.75
static void ACE_probe_imgui_core(void) {
    if (!g_tgt_base) return;
    g_probeDraws++;
    @try {
        uintptr_t ctxp = *(volatile uintptr_t *)(g_tgt_base + 0x3ff840ULL);
        uintptr_t fonts = ctxp ? *(volatile uintptr_t *)(ctxp + 0x50) : 0;
        static int guardLogged = 0;
        if (fonts) {
            volatile uint32_t *f48 = (volatile uint32_t *)(fonts + 0x48);
            volatile uint8_t *f19 = (volatile uint8_t *)(fonts + 0x19);
            if (*f48 == 1u && *f19 == 0) {
                if (!guardLogged) {
                    guardLogged = 1;
                    ACETrace(@"[v78] ★NewFrame字体图集守卫命中: Fonts=%p +0x48=1 +0x19=0 → 强制+0x19=1破guard(下一帧生效)", (void *)fonts);
                }
                *f19 = 1;
            }
        }
// v7.79
    } @catch (NSException *e) {}
}
// ═══ v7.79 Style.Alpha 强制 + 窗口取证 ═══
// v7.76
// v7.79
// v7.80
#define ACE_MAXWINS 8
static void *g_wins80[ACE_MAXWINS];
static volatile int g_winCnt80 = 0;
static void *g_winPtr79 = NULL;   // 兼容: 首个捕获窗口
static volatile int g_winSpin79 = 0;   // 自旋线程已启动
static void *ACE_win_spin79(void *arg) {
    (void)arg;
    for (int i = 0; i < 400000; i++) {
        if (g_tgt_base) {
            uintptr_t ctxp = *(volatile uintptr_t *)(g_tgt_base + 0x3ff840ULL);
            if (ctxp) {
                uintptr_t w = *(volatile uintptr_t *)(ctxp + 0x3e28);
                if (w) {
                    int dup = 0;
                    for (int k = 0; k < g_winCnt80; k++) if (g_wins80[k] == (void *)w) { dup = 1; break; }
                    if (!dup && g_winCnt80 < ACE_MAXWINS) {
                        g_wins80[g_winCnt80++] = (void *)w;
                        if (!g_winPtr79) g_winPtr79 = (void *)w;
                    }
                }
            }
        }
        if (g_winCnt80 >= 6 && i > 40000) break;   // 收齐提前退出
        usleep(1);
    }
    ACETrace(@"[v80spin] 窗口收集完成: %d 个", g_winCnt80);
    return NULL;
}
static void ACE_dump_wins80(int phase, long n) {
    int cnt = g_winCnt80;
    if (cnt == 0) return;
    for (int k = 0; k < cnt; k++) {
        uintptr_t w = (uintptr_t)g_wins80[k];
        if (!w) continue;
        @try {
            int8_t *bb = (int8_t *)w;
            volatile float *f = (volatile float *)w;
            uintptr_t nmp = *(volatile uintptr_t *)w;
            unsigned char nb[13] = {0};
            if (nmp > 0x100000000ULL) memcpy(nb, (void *)nmp, 12);
            int isPanel = (nb[0] == 0xe7 && nb[1] == 0x90 && nb[2] == 0x83);   // 「球」UTF8 首3字节
            ACETrace(@"[v80w%d.%d#%ld]%s ptr=%p name=%02x%02x%02x%02x%02x%02x(%.12s) Skip=%d b0=%d b1=%d b2=%d b3=%d 8e=%d 91=%d 94=%d 95=%d",
                     phase, k, n, isPanel ? "★面板主窗" : "", (void *)w,
                     nb[0], nb[1], nb[2], nb[3], nb[4], nb[5],
                     (nmp > 0x100000000ULL) ? (const char *)nb : "-",
                     (int)bb[0x93], (int)bb[0xb0], (int)bb[0xb1], (int)bb[0xb2], (int)bb[0xb3],
                     (int)(uint8_t)bb[0x8e], (int)(uint8_t)bb[0x91], (int)(uint8_t)bb[0x94], (int)(uint8_t)bb[0x95]);
            ACETrace(@"[v80w%d.%d#%ld] Pos@e8=(%g,%g) f10=(%g,%g) f18=(%g,%g) f20=(%g,%g) Clip@210=(%g,%g,%g,%g) cursor@d8=(%g,%g) +110=%g LFA=%u",
                     phase, k, n,
                     (double)f[0xe8 / 4], (double)f[0xec / 4], (double)f[0x10 / 4], (double)f[0x14 / 4],
                     (double)f[0x18 / 4], (double)f[0x1c / 4], (double)f[0x20 / 4], (double)f[0x24 / 4],
                     (double)f[0x210 / 4], (double)f[0x214 / 4], (double)f[0x218 / 4], (double)f[0x21c / 4],
                     (double)f[0xd8 / 4], (double)f[0xdc / 4], (double)f[0x110 / 4],
                     *(volatile uint32_t *)(w + 0x238));
// v7.81
            uintptr_t dl = *(volatile uintptr_t *)(w + 0x270);
            if (dl > 0x100000000ULL) {
                ACETrace(@"[v81w%d.%d#%ld] DrawList=%p ★Cmd=%u Idx=%u ★Vtx=%u (>0=有顶点!)",
                         phase, k, n, (void *)dl,
                         *(volatile uint32_t *)(dl), *(volatile uint32_t *)(dl + 0x10), *(volatile uint32_t *)(dl + 0x20));
            } else {
                ACETrace(@"[v81w%d.%d#%ld] ★DrawList[+0x270]=%p 非法!", phase, k, n, (void *)dl);
            }
            ACETrace(@"[v80w%d.%d#%ld] raw174=%g %g %g %g | raw184=%g %g %g %g | raw194=%g %g",
                     phase, k, n,
                     (double)f[0x174 / 4], (double)f[0x178 / 4], (double)f[0x17c / 4], (double)f[0x180 / 4],
                     (double)f[0x184 / 4], (double)f[0x188 / 4], (double)f[0x18c / 4], (double)f[0x190 / 4],
                     (double)f[0x194 / 4], (double)f[0x198 / 4]);
        } @catch (NSException *e) { ACETrace(@"[v80w%d.%d#%ld] dump异常: %@", phase, k, n, e); }
    }
    if (phase == 1) {
        @try {
            uintptr_t ctxp = *(volatile uintptr_t *)(g_tgt_base + 0x3ff840ULL);
            uintptr_t ini = ctxp ? *(volatile uintptr_t *)(ctxp + 8 + 0x18) : 0;
            if (ini) {
                char ib[65] = {0};
                memcpy(ib, (void *)ini, 64);
                long off = (g_tgt_base && ini >= g_tgt_base && ini < g_tgt_base + 0x400000ULL) ? (long)(ini - g_tgt_base) : -1;
                ACETrace(@"[v80ini#%ld] IniFilename=%p(base+%ld) = \"%s\"", n, (void *)ini, off, ib);
            }
        } @catch (NSException *e) {}
    }
}
// ═══ v7.82 Windows/Viewports 列表枚举 ═══
static void ACE_scan_windows82(long tag) {
    if (!g_tgt_base) return;
    @try {
        uintptr_t ctxp = *(volatile uintptr_t *)(g_tgt_base + 0x3ff840ULL);
        if (!ctxp) return;
        uint32_t rvN = *(volatile uint32_t *)(ctxp + 0x4028);
        uintptr_t rvD = *(volatile uintptr_t *)(ctxp + 0x4030);
        uint32_t vpN = *(volatile uint32_t *)(ctxp + 0x42a8);
        uintptr_t vpD = *(volatile uintptr_t *)(ctxp + 0x42b0);
        uint32_t wN  = *(volatile uint32_t *)(ctxp + 0x3dc8);
        uintptr_t wD = *(volatile uintptr_t *)(ctxp + 0x3dd0);
        uintptr_t navW = *(volatile uintptr_t *)(ctxp + 0x41a0);
        uintptr_t x41b0 = *(volatile uintptr_t *)(ctxp + 0x41b0);
        ACETrace(@"[v82#%ld] ctx列表: Render迭代(n=%u,%p) Viewports(n=%u,%p) ★Windows(n=%u,%p) Nav=%p x41b0=%p FrameCount=%u/%u",
                 tag, rvN, (void *)rvD, vpN, (void *)vpD, wN, (void *)wD, (void *)navW, (void *)x41b0,
                 *(volatile uint32_t *)(ctxp + 0x3da8), *(volatile uint32_t *)(ctxp + 0x3dac));
        if (vpD && vpN && vpN <= 16) {
            for (uint32_t i = 0; i < vpN; i++) {
                uintptr_t vp = vpD + (uintptr_t)i * 0x208ULL;
                ACETrace(@"[v82#%ld] VP[%u]=%p ID=%x flags=%x DrawData区: Valid=%u CmdListsCount=%u TotIdx=%u TotVtx=%u CmdLists=%p",
                         tag, i, (void *)vp, *(volatile uint32_t *)vp, *(volatile uint32_t *)(vp + 4),
                         *(volatile uint32_t *)(vp + 0x48), *(volatile uint32_t *)(vp + 0x4c),
                         *(volatile uint32_t *)(vp + 0x50), *(volatile uint32_t *)(vp + 0x54),
                         (void *)(uintptr_t)*(volatile uint64_t *)(vp + 0x58));
            }
        }
        if (rvD && rvN && rvN <= 16) {
            for (uint32_t i = 0; i < rvN; i++) {
                uintptr_t e = *(volatile uintptr_t *)(rvD + (uintptr_t)i * 8);
                if (!e) continue;
                ACETrace(@"[v82#%ld] RenderIt[%u]=%p +0x48=%x +0x4c(DL数)=%u +0x50=%p +0x78(n)=%d",
                         tag, i, (void *)e, *(volatile uint32_t *)(e + 0x48),
                         *(volatile uint32_t *)(e + 0x4c), (void *)(uintptr_t)*(volatile uint64_t *)(e + 0x50),
                         *(volatile int32_t *)(e + 0x78));
            }
        }
// ★Windows 列表全枚举
        if (wD && wN && wN <= 64) {
            for (uint32_t i = 0; i < wN; i++) {
                uintptr_t w = *(volatile uintptr_t *)(wD + (uintptr_t)i * 8);
                if (w < 0x100000000ULL) { ACETrace(@"[v82#%ld] WIN[%u]=%p 非法!", tag, i, (void *)w); continue; }
                uintptr_t nmp = *(volatile uintptr_t *)w;
                unsigned char nb[13] = {0};
                if (nmp > 0x100000000ULL) memcpy(nb, (void *)nmp, 12);
                uintptr_t dl = *(volatile uintptr_t *)(w + 0x270);
                uint32_t cmd = 0xffffffff, vtx = 0xffffffff;
                if (dl > 0x100000000ULL) { cmd = *(volatile uint32_t *)dl; vtx = *(volatile uint32_t *)(dl + 0x20); }
                int8_t *bb = (int8_t *)w;
                ACETrace(@"[v82#%ld] ★WIN[%u]=%p name=%02x%02x%02x%02x%02x%02x(%.12s) Act8e=%d +95=%d Skip93=%d flags=%x VpIdx188=%d Par340=%p Cmd=%u ★Vtx=%u LFA=%u",
                         tag, i, (void *)w, nb[0], nb[1], nb[2], nb[3], nb[4], nb[5],
                         (nmp > 0x100000000ULL) ? (const char *)nb : "-",
                         (int)(uint8_t)bb[0x8e], (int)(uint8_t)bb[0x95], (int)bb[0x93],
                         *(volatile uint32_t *)(w + 0xc), *(volatile int32_t *)(w + 0x188),
                         (void *)(uintptr_t)*(volatile uint64_t *)(w + 0x340), cmd, vtx,
                         *(volatile uint32_t *)(w + 0x238));
            }
        } else {
            ACETrace(@"[v82#%ld] ★★Windows列表异常: n=%u data=%p — Render收集循环%s!", tag, wN, (void *)wD,
                     (wN == 0) ? "一次都不会跑(=CmdLists恒0的直接原因)" : "数据指针非法");
        }
    } @catch (NSException *e) { ACETrace(@"[v82#%ld] 扫描异常: %@", tag, e); }
}
// ═══ v7.82 END ═══
// ═══ v7.84 运行时代码完整性对照 ═══
static const uintptr_t g_v84Off[8] = {
    0x39bc0,   // m1 入口
    0x39e98,   // m1 主体首块(一次性初始化)
    0x3a098,
    0x3f1dc,   // m1 早退出口
    0x1310c8,   // ImGui Begin 入口
    0x1260a8,   // n0 入口(alpha窗)
    0x8c750,
    0x28dbc
};
static const uint8_t g_v84Exp[8][16] = {
    {0xff,0x43,0x05,0xd1,0xeb,0x2b,0x0d,0x6d,0xe9,0x23,0x0e,0x6d,0xfc,0x6f,0x0f,0xa9},
    {0xb4,0x1d,0x00,0xb0,0x88,0xc6,0x5e,0x39,0x35,0x1e,0x00,0xd0,0x88,0x00,0x00,0x34},
    {0x0c,0xdc,0x03,0x94,0xe8,0x02,0x04,0x94,0x08,0x40,0x20,0x1e,0x29,0x40,0x20,0x1e},
    {0xa8,0x03,0x58,0xf8,0x49,0x1d,0x00,0xb0,0x29,0x81,0x40,0xf9,0x29,0x01,0x40,0xf9},
    {0xef,0x3b,0xb6,0x6d,0xed,0x33,0x01,0x6d,0xeb,0x2b,0x02,0x6d,0xe9,0x23,0x03,0x6d},
    {0xff,0xc3,0x00,0xd1,0xfd,0x7b,0x02,0xa9,0xfd,0x83,0x00,0x91,0x3e,0x15,0x00,0x94},
    {0x1c,0x09,0x03,0x94,0xe0,0x03,0x16,0xaa,0x20,0x09,0x03,0x94,0x08,0x1b,0x00,0xb0},
    {0xff,0xc3,0x01,0xd1,0xe9,0x23,0x01,0x6d,0xfa,0x67,0x02,0xa9,0xf8,0x5f,0x03,0xa9}
};
static void ACE_code_check84(long n) {
    if (!g_tgt_base) return;
    int bad = 0;
    for (int i = 0; i < 8; i++) {
        const volatile uint8_t *rt = (const volatile uint8_t *)(g_tgt_base + g_v84Off[i]);
        int same = 1;
        for (int k = 0; k < 16; k++) if (rt[k] != g_v84Exp[i][k]) { same = 0; break; }
        if (!same) bad++;
        ACETrace(@"[v84#%ld] 点%d @+%llx %s 运行时=%02x%02x%02x%02x %02x%02x%02x%02x 文件=%02x%02x%02x%02x %02x%02x%02x%02x",
                 n, i, (unsigned long long)g_v84Off[i], same ? "OK" : "★★MISMATCH=运行时被改写★",
                 rt[0], rt[1], rt[2], rt[3], rt[4], rt[5], rt[6], rt[7],
                 g_v84Exp[i][0], g_v84Exp[i][1], g_v84Exp[i][2], g_v84Exp[i][3],
                 g_v84Exp[i][4], g_v84Exp[i][5], g_v84Exp[i][6], g_v84Exp[i][7]);
    }
    ACETrace(@"[v84#%ld] 总结: %d/8 点被改写 %s", n, bad,
             bad ? "★静态分析作废, 需dump运行时代码重建" : "(代码与文件一致, 悖论另有解释)");
}
// ═══ v7.84 END ═══
// ═══ v7.79 END ═══
static void ACE_hook_m1(id self, SEL _cmd) {
    long n = ++g_m1Cnt;
    int sample = (n <= 10) || (n % 120 == 0);   // v7.81
    int gBefore = 0, gAfter = 0;
    uint8_t b0B = 0, b0A = 0;
    if (sample) gBefore = ACE_eval_m1_gates();
// ═══ v7.81 ═══
// ═══ v7.76 ═══
    if (g_tgt_base) {
        static uint8_t v81LastB = 0xff;
        static uintptr_t v81LastO = ~(uintptr_t)0;
        uint8_t bNow = *(volatile uint8_t *)(g_tgt_base + 0x3ee7b1ULL);
        uintptr_t oNow = *(volatile uintptr_t *)(g_tgt_base + 0x3ff3c8ULL);
        if (bNow != v81LastB || oNow != v81LastO) {
            ACETrace(@"[v81#%ld] ★m1主体执行状态变化: [3ee7b1] %u→%u [3ff408] %p→%p (3ee7b1变0=主体已执行铁证)",
                     n, (unsigned)v81LastB, (unsigned)bNow, (void *)v81LastO, (void *)oNow);
            v81LastB = bNow; v81LastO = oNow;
        }
    }
// ═══ v7.76 终轮 ═══
    if (g_tgt_base) {
// v7.79
// v7.76
        volatile float *pAcc = (volatile float *)(g_tgt_base + 0x3f0a54ULL);
        volatile uint8_t *pFlag = (volatile uint8_t *)(g_tgt_base + 0x3f0a08ULL);
        volatile uint32_t *pTab = (volatile uint32_t *)(g_tgt_base + 0x3f0a58ULL);
        static int v776Once = 0;
        if (!v776Once) {
            v776Once = 1;
            float a0 = *pAcc; uint8_t f0 = *pFlag; uint32_t t0 = *pTab;
            uintptr_t o1 = *(volatile uintptr_t *)(g_tgt_base + 0x3ff3c8ULL);
            uint8_t b1 = *(volatile uint8_t *)(g_tgt_base + 0x3ee7b1ULL);
            ACETrace(@"[v76] 修前: alpha累加[3f0a58]=%g flag[3f0a0a]=%u tab[3f0a5c]=%u 一次性([3ee7b1]=%u [3ff408]=%p)",
                     (double)a0, (unsigned)f0, t0, (unsigned)b1, (void *)o1);
            ACETrace(@"[v76] 强制: alpha=1.0 flag=1 tab=%u(越界才归0)", t0);
        }
        *pAcc = 1.0f; *pFlag = 1;
        if (*pTab > 6u) *pTab = 0;
    }
// ═══ v7.79 ═══
    if (g_tgt_base) {
        uintptr_t ctxp79 = *(volatile uintptr_t *)(g_tgt_base + 0x3ff840ULL);
        if (ctxp79) {
            volatile float *pA = (volatile float *)(ctxp79 + 0x3778);
            float a0 = *pA;
            static long v79FixCnt = 0;
            if (!(a0 > 0.0f) || a0 > 1.0f) { *pA = 1.0f; v79FixCnt++; }
            if (n <= 3 || n % 300 == 0) {
                volatile float *sf = (volatile float *)(ctxp79 + 0x3778);
                ACETrace(@"[v79#%ld] ★Style.Alpha 修前=%g 修后=%g 累计强制=%ld | Style+4=%g +8=%g +0xc=%g +0x10=%g (+4≈0.6且+8≈8=基址确认)",
                         n, (double)a0, (double)*pA, v79FixCnt,
                         (double)sf[1], (double)sf[2], (double)sf[3], (double)sf[4]);
            }
            if (n == 2 && !g_winSpin79) {
                g_winSpin79 = 1;
                pthread_t th;
                if (pthread_create(&th, NULL, ACE_win_spin79, NULL) == 0) pthread_detach(th);
            }
        }
    }
// ═══ v7.85 ═══
// v7.82
    if (g_tgt_base) {
        volatile uint32_t *tb85 = (volatile uint32_t *)(g_tgt_base + 0x3f0dbcULL);
        volatile uint32_t *fl85 = (volatile uint32_t *)(g_tgt_base + 0x3f0a6cULL);
        volatile uint32_t *tbOld = (volatile uint32_t *)(g_tgt_base + 0x3fad80ULL);
        static int v85Once = 0;
        if (!v85Once) {
            v85Once = 1;
            ACETrace(@"[v85#%ld] ★m1真时基: flag[3f0a70]=%u num[3f0dc0]=%u den[3f0dc4]=%u | 旧eval时基[3fadc0]=%u/%u (den=0即45s窗恒挂=主体永不执行)",
                     n, *fl85, tb85[0], tb85[1], tbOld[0], tbOld[1]);
        }
        if (tb85[1] == 0 || tb85[0] == 0) {
            tb85[0] = 125; tb85[1] = 3; *fl85 = 1;
            if (n <= 3 || n % 300 == 0)
                ACETrace(@"[v85#%ld] ★已修复时基→125/3 (下一帧m1的45s窗应通过)", n);
        }
    }
    if (n <= 2) ACE_code_check84(n);   // v7.84
    if (sample) ACE_dump_wins80(0, n);   // v7.80
// ═══ v7.83 停手实验 ═══
    int fw = 1;   // v7.83
    g_freeze_web = 1;
// v7.83
    if (sample) gAfter = ACE_eval_m1_gates();
// ═══ v7.75 ═══
    if (g_tgt_base) {
        uintptr_t ctxp = *(volatile uintptr_t *)(g_tgt_base + 0x3ff840ULL);
        uintptr_t io = ctxp ? (ctxp + 8) : 0;
        if (io) {
            volatile float *dsX = (volatile float *)(io + 8);
            volatile float *dsY = (volatile float *)(io + 0xc);
            volatile float *dt  = (volatile float *)(io + 0x10);
            int fixed = 0;
            if (!(*dsX > 1.0f) || !(*dsY > 1.0f)) { *dsX = 1080.0f; *dsY = 810.0f; fixed |= 1; }
            if (!(*dt > 0.0f) || *dt > 1.0f) { *dt = 0.016f; fixed |= 2; }
            if (sample) {
                ACETrace(@"[io#%ld] ctx=%p DisplaySize=(%g,%g) DeltaTime=%g 矫正bits=%d(1=尺寸2=时步)",
                         n, (void *)ctxp, *dsX, *dsY, *dt, fixed);
                for (int q = 0; q < 4; q++)
                    ACETrace(@"[io#%ld] IO+%02x: %llx %llx %llx %llx", n, q * 32,
                             (unsigned long long)*(volatile uint64_t *)(io + q * 32),
                             (unsigned long long)*(volatile uint64_t *)(io + q * 32 + 8),
                             (unsigned long long)*(volatile uint64_t *)(io + q * 32 + 16),
                             (unsigned long long)*(volatile uint64_t *)(io + q * 32 + 24));
                uint32_t inc = *(volatile uint32_t *)(ctxp + 0x5340);
                uintptr_t be = *(volatile uintptr_t *)(g_tgt_base + 0x3f2748ULL);
                void *ftex = NULL;
                @try {
                    if (be) ftex = (__bridge void *)((id (*)(id, SEL))objc_msgSend)((__bridge id)(void *)be, NSSelectorFromString(@"fontTexture"));
                } @catch (NSException *e) {}
                ACETrace(@"[io#%ld] backend=%p fontTexture=%p NewFrame计数[ctx+0x5340]=%u", n, (void *)be, ftex, inc);
                if (g_getDrawData) {
                    @try {
                        void *dd = ((void *(*)(void))g_getDrawData)();
                        if (dd) {
                            float f24 = *(volatile float *)((uintptr_t)dd + 24), f28 = *(volatile float *)((uintptr_t)dd + 28);
                            float f32 = *(volatile float *)((uintptr_t)dd + 32), f36 = *(volatile float *)((uintptr_t)dd + 36);
                            float f40 = *(volatile float *)((uintptr_t)dd + 40), f44 = *(volatile float *)((uintptr_t)dd + 44);
                            ACETrace(@"[io#%ld] 上帧drawData浮点@24..44: %g %g %g %g %g %g (任一对=(0,0)即尺寸未喂)",
                                     n, (double)f24, (double)f28, (double)f32, (double)f36, (double)f40, (double)f44);
                        }
                    } @catch (NSException *e) {}
                }
            }
        } else if (sample) {
            ACETrace(@"[io#%ld] ★ctx[0x3ff840]=%p — ImGui上下文缺失!", n, (void *)ctxp);
        }
    }
    if (g_tgt_base) b0B = *(volatile uint8_t *)(g_tgt_base + 0x3ff7a4ULL);
    if (g_orig_m1) g_orig_m1(self, _cmd);
    ACE_probe_imgui_core();   // v7.79
    if (sample) ACE_dump_wins80(1, n);   // v7.80
    if (sample && n <= 3) ACE_scan_windows82(-n);   // v7.82
    if (g_tgt_base) b0A = *(volatile uint8_t *)(g_tgt_base + 0x3ff7a4ULL);
    g_freeze_web = fw;
    if (sample) {
        if (!g_cfgPtr && g_mtkView)
            g_cfgPtr = ((void *(*)(id, SEL))objc_msgSend)(g_mtkView, NSSelectorFromString(@"_0xE4C8719B"));
        ACETrace(@"[m1#%ld] 门:喂前=%x 喂后=%x(1ff=全过) cfgPtr=%p(base+%llx) byte0:%d→%d %s",
                 n, gBefore, gAfter, g_cfgPtr,
                 (unsigned long long)(g_cfgPtr && g_tgt_base ? ((uintptr_t)g_cfgPtr - g_tgt_base) : 0ULL),
                 (int)b0B, (int)b0A,
                 (b0B && !b0A) ? "★m1走到尾=UI已构建!" : "(byte0未消费=m1早退)");
        if (g_getDrawData) {
            @try {
                void *dd = ((void *(*)(void))g_getDrawData)();
                if (dd) {
                    uint32_t w0 = *(volatile uint32_t *)((uintptr_t)dd);
                    uint64_t w8 = *(volatile uint64_t *)((uintptr_t)dd + 8);
                    uint64_t w16 = *(volatile uint64_t *)((uintptr_t)dd + 16);
                    uint32_t w24 = *(volatile uint32_t *)((uintptr_t)dd + 24);
                    ACETrace(@"[dd] drawData=%p w0=%x w8=%llx w16=%llx w24=%x (旧布局:w8=列表指针,w16低32=命令列表数; 非零=UI已建)",
                             dd, w0, (unsigned long long)w8, (unsigned long long)w16, w24);
                } else {
                    ACETrace(@"[dd] GetDrawData→nil");
                }
            } @catch (NSException *e) {}
        }
    }
}
static void ACE_hook_n0(id self, SEL _cmd) { g_n0Cnt++; if (g_orig_n0) g_orig_n0(self, _cmd); }
static void ACE_hook_m2(id self, SEL _cmd) { g_m2Cnt++; if (g_orig_m2) g_orig_m2(self, _cmd); }
static void ACE_hook_m3(id self, SEL _cmd) { g_m3Cnt++; if (g_orig_m3) g_orig_m3(self, _cmd); }
static void ACE_install_m1_probes(Class clsB, Class clsC) {
    @try {
        g_getDrawData = (void *)(g_tgt_base + 0x12b62cULL);
        Method m;
        m = class_getInstanceMethod(clsB, NSSelectorFromString(@"m1"));
        if (m && !g_orig_m1) { g_orig_m1 = (void (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)ACE_hook_m1); }
        m = class_getInstanceMethod(clsC, NSSelectorFromString(@"n0"));
        if (m && !g_orig_n0) { g_orig_n0 = (void (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)ACE_hook_n0); }
        m = class_getInstanceMethod(clsB, NSSelectorFromString(@"m2"));
        if (m && !g_orig_m2) { g_orig_m2 = (void (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)ACE_hook_m2); }
        m = class_getInstanceMethod(clsB, NSSelectorFromString(@"m3"));
        if (m && !g_orig_m3) { g_orig_m3 = (void (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)ACE_hook_m3); }
        ACETrace(@"[m1] 探针已装 m1=%d n0=%d m2=%d m3=%d getDrawData=%p",
                 !!g_orig_m1, !!g_orig_n0, !!g_orig_m2, !!g_orig_m3, g_getDrawData);
// v7.81
        ACETrace(@"[v81imp] m1=+%llx(期望3a8b4) n0=+%llx m2=+%llx m3=+%llx",
                 (unsigned long long)(g_orig_m1 ? ((uintptr_t)g_orig_m1 - g_tgt_base) : 0ULL),
                 (unsigned long long)(g_orig_n0 ? ((uintptr_t)g_orig_n0 - g_tgt_base) : 0ULL),
                 (unsigned long long)(g_orig_m2 ? ((uintptr_t)g_orig_m2 - g_tgt_base) : 0ULL),
                 (unsigned long long)(g_orig_m3 ? ((uintptr_t)g_orig_m3 - g_tgt_base) : 0ULL));
    } @catch (NSException *e) { ACETrace(@"[m1] 探针异常: %@", e); }
}
// ═══ v7.74 m1 取证 END ═══
static void ACE_native_panel_build(int tag) {
    @try {
        if (!g_tgt_base) return;
        volatile uint8_t *flag = (volatile uint8_t *)(g_tgt_base + 0x3fc308ULL);
        if (*flag & 1) {
            if (!g_nativeBuilt) { g_nativeBuilt = YES; ACETrace(@"[native] tag%d: flag已置位=面板已在, 补装可见球", tag); }
            ACE_install_visible_ball();
            return;
        }
        if (g_nativeBuilt) return;
        Class clsC = NSClassFromString(@"_0xC8E2A541");
        Class clsB = NSClassFromString(@"_0xB1D7F3A9");
        Class clsM = NSClassFromString(@"_0x1E6B7A93");
        Class clsBall = NSClassFromString(@"_0xD4E9A3C7");
        if (!clsC || !clsB || !clsM || !clsBall) {
            ACETrace(@"[native] tag%d: 类缺失 C=%d B=%d M=%d 球=%d", tag, !!clsC, !!clsB, !!clsM, !!clsBall);
            return;
        }
        UIApplication *app = [UIApplication sharedApplication];
        UIWindow *kw = app.keyWindow;
        if (!kw) for (UIWindow *w in app.windows) if (!w.hidden && w.alpha > 0.01) { kw = w; break; }
        if (!kw) { ACETrace(@"[native] tag%d: 无可用窗口", tag); return; }
        void *cfg = (void *)(g_tgt_base + 0x3ff7a4ULL);
        CGRect full = kw.frame;
// v7.60
// v7.59
        {
            uintptr_t slots[3] = { 0x3f28c0ULL, 0x3fc30cULL, 0x3fb940ULL };
            for (int i = 0; i < 3; i++) {
                volatile uint32_t *tb = (volatile uint32_t *)(g_tgt_base + slots[i]);
                ACETrace(@"[tb] 槽%llx 修前: num=%u den=%u flag=%u",
                         (unsigned long long)slots[i], tb[0], tb[1], tb[2]);
                tb[0] = 125u; tb[1] = 3u; tb[2] = 1u;
            }
        }
        SEL sF  = NSSelectorFromString(@"initWithFrame:");
        SEL sF4 = NSSelectorFromString(@"initWithFrame::::");
        SEL sF2 = NSSelectorFromString(@"initWithFrame::");
// v7.50
        ACE_web_tick();
        g_freeze_web = 1;
        usleep(3000);
        id container = ((id (*)(id, SEL, void *))objc_msgSend)([clsC alloc], sF, cfg);
        id bridge    = ((id (*)(id, SEL, void *))objc_msgSend)([clsB alloc], sF, cfg);
        id mtk = ((id (*)(id, SEL, void *, id, id, CGRect))objc_msgSend)([clsM alloc], sF4,
                                                                         cfg, container, bridge, full);
        ACETrace(@"[native] tag%d: 容器=%p 桥接=%p mtk=%p", tag,
                 (__bridge void *)container, (__bridge void *)bridge, (__bridge void *)mtk);
        if (!mtk) {
            g_freeze_web = 0;
            ACETrace(@"[native] tag%d: MTKView init返nil(Metal失败?), 本次中止", tag);
            return;
        }
// v7.57
        @try {
            Method md = class_getInstanceMethod(clsM, NSSelectorFromString(@"drawInMTKView:"));
            if (md && !g_orig_draw) g_orig_draw = (void (*)(id, SEL, id))method_setImplementation(md, (IMP)ACE_hook_draw);
            Method m73 = class_getInstanceMethod(clsM, NSSelectorFromString(@"_0x73C9A1E5:"));
            if (m73 && !g_orig_73) g_orig_73 = (void (*)(id, SEL, id))method_setImplementation(m73, (IMP)ACE_hook_73);
// v7.66
            if (!g_orig_setHidden) {
                Method msh = class_getInstanceMethod([UIView class], @selector(setHidden:));
                if (msh) g_orig_setHidden = (void (*)(id, SEL, BOOL))method_getImplementation(msh);
                class_addMethod(clsM, @selector(setHidden:), (IMP)ACE_hook_setHidden, "v@:B");
            }
            ACETrace(@"[native] draw仪表已挂 draw=%d 73=%d setHidden取证=%d origIMP偏移=%llx(应=8cdd4)",
                     !!g_orig_draw, !!g_orig_73, !!g_orig_setHidden,
                     (unsigned long long)(g_orig_draw ? ((uintptr_t)g_orig_draw - g_tgt_base) : 0));
// ═══ v7.73 ═══
            ACE_install_gpu_probes(mtk, clsM);
// ═══ v7.74 ═══
            ACE_install_m1_probes(clsB, clsC);
        } @catch (NSException *e) { ACETrace(@"[native] draw仪表挂载异常: %@", e); }
        id ball = ((id (*)(id, SEL, void *, CGRect))objc_msgSend)([clsBall alloc], sF2,
                                                                  cfg, CGRectMake(489, 58, 45, 45));
        ((void (*)(id, SEL, id))objc_msgSend)(kw, @selector(addSubview:), ball);
        volatile uintptr_t *p328 = (volatile uintptr_t *)(g_tgt_base + 0x3fc2e8ULL);
        volatile uintptr_t *p330 = (volatile uintptr_t *)(g_tgt_base + 0x3fc2f0ULL);
        uintptr_t old328 = *p328, old330 = *p330;
        *p328 = (uintptr_t)CFBridgingRetain(mtk);
        *p330 = (uintptr_t)CFBridgingRetain(ball);
        if (old328) CFBridgingRelease((void *)old328);
        if (old330) CFBridgingRelease((void *)old330);
        *flag = 1;
        volatile uint8_t *sw = (volatile uint8_t *)(g_tgt_base + 0x3ff7a4ULL);
        uint8_t sw0 = *sw;
        if (sw0 == 0) *sw = 1;
        g_nativeBuilt = YES;
        g_panelWant = 1;
        uintptr_t pwin = *(volatile uintptr_t *)(g_tgt_base + 0x3f2810ULL);
// v7.56
// v7.55
        uintptr_t tsrc = *(volatile uintptr_t *)(g_tgt_base + 0x3fc300ULL);
        if (tsrc) {
            dispatch_suspend((__bridge dispatch_source_t)(void *)tsrc);
            ACETrace(@"[native] 巡检timer已挂起(source=%p) — 拆除路径缴械", (void *)tsrc);
        } else {
            ACETrace(@"[native] 警告: [0x3fc300]巡检source为空, 无法挂起!");
        }
        g_freeze_web = 0;
        ACETrace(@"[native] ★tag%d: 原生面板复刻构建完成! flag=1 开关%d→%d 面板窗=%p 球=%p",
                 tag, (int)sw0, (int)*sw, (void *)pwin, (__bridge void *)ball);
        ACE_install_visible_ball();
// v7.58
        @try {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(mtk, NSSelectorFromString(@"setPaused:"), NO);
            ((void (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"setNeedsDisplay"));
            UIWindow *mw = ((id (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"window"));
            id sv = ((id (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"superview"));
            BOOL pz = ((BOOL (*)(id, SEL))objc_msgSend)(mtk, NSSelectorFromString(@"isPaused"));
            UIWindow *pw = (__bridge UIWindow *)(void *)pwin;
            ACETrace(@"[native] 渲染器戳醒: mtk.window=%p superview=%p paused=%d | 面板窗=%p hidden=%d level=%g scene=%d",
                     (__bridge void *)mw, (__bridge void *)sv, (int)pz,
                     (__bridge void *)pw, (int)pw.hidden, (double)pw.windowLevel, pw.windowScene ? 1 : 0);
        } @catch (NSException *e) { ACETrace(@"[native] 戳醒异常: %@", e); }
        dispatch_after(dispatch_time(0, 1000000000LL), dispatch_get_main_queue(), ^{
            @try {
                volatile uint8_t *f2 = (volatile uint8_t *)(g_tgt_base + 0x3fc308ULL);
                uintptr_t w2 = *(volatile uintptr_t *)(g_tgt_base + 0x3f2810ULL);
                uint8_t s2 = *(volatile uint8_t *)(g_tgt_base + 0x3ff7a4ULL);
                uintptr_t m2 = *(volatile uintptr_t *)(g_tgt_base + 0x3fc2e8ULL);
                ACETrace(@"[native] 1s复查: flag=%d 开关=%d 面板窗=%p 槽328=%p", (int)(*f2 & 1), (int)s2, (void *)w2, (void *)m2);
// v7.58
                if (g_drawCalls == 0 && mtk) {
                    ACETrace(@"[native] displayLink未转(draw=0次) → 启动60fps手动驱动");
                    ACE_drive_draw(mtk);
                }
                if (!(*f2 & 1) && g_rebuildCnt < 3) {
                    g_rebuildCnt++; g_nativeBuilt = NO;
                    ACETrace(@"[native] 被拆! 0.5s后重建(第%d/3次)", g_rebuildCnt);
                    dispatch_after(dispatch_time(0, 500000000LL), dispatch_get_main_queue(), ^{ ACE_native_panel_build(8 + g_rebuildCnt); });
                }
            } @catch (NSException *e) {}
        });
        dispatch_after(dispatch_time(0, 5000000000LL), dispatch_get_main_queue(), ^{
            @try {
                volatile uint8_t *f3 = (volatile uint8_t *)(g_tgt_base + 0x3fc308ULL);
                uintptr_t w3 = *(volatile uintptr_t *)(g_tgt_base + 0x3f2810ULL);
                uint8_t s3 = *(volatile uint8_t *)(g_tgt_base + 0x3ff7a4ULL);
                ACETrace(@"[native] 5s复查: flag=%d 开关=%d 面板窗=%p (稳了=点左上角菜单球验证显隐)", (int)(*f3 & 1), (int)s3, (void *)w3);
            } @catch (NSException *e) {}
        });
// v7.73
        dispatch_after(dispatch_time(0, 1800000000LL), dispatch_get_main_queue(), ^{ ACE_diag_display(1); });
        dispatch_after(dispatch_time(0, 5200000000LL), dispatch_get_main_queue(), ^{ ACE_diag_display(2); });
    } @catch (NSException *e) { g_freeze_web = 0; ACETrace(@"[native] tag%d 异常: %@", tag, e); }
}
static void ACE_schedule_sec_posts(void) {
    dispatch_after(dispatch_time(0, 1000000000LL), dispatch_get_main_queue(), ^{ ACE_post_sec_notif(1); ACE_build_panel_direct(1); });
// v7.54
    dispatch_after(dispatch_time(0, 2500000000LL), dispatch_get_main_queue(), ^{ ACE_native_panel_build(1); });
    dispatch_after(dispatch_time(0, 3000000000LL), dispatch_get_main_queue(), ^{ ACE_post_sec_notif(2); ACE_build_panel_direct(2); });
    dispatch_after(dispatch_time(0, 6000000000LL), dispatch_get_main_queue(), ^{ ACE_post_sec_notif(3); ACE_build_panel_direct(3); });
    dispatch_after(dispatch_time(0, 8000000000LL), dispatch_get_main_queue(), ^{ ACE_native_panel_build(2); });   // 重试(幂等)
}
static void ACE_install_notif_probe(void) {
    @try {
        Method m = class_getInstanceMethod([NSNotificationCenter class],
                                           @selector(postNotificationName:object:));
        if (m) g_orig_post2 = (void (*)(id, SEL, NSString *, id))
            method_setImplementation(m, (IMP)ACE_post2);
// v7.41
        Method mdc = class_getClassMethod([NSNotificationCenter class],
                                          @selector(defaultCenter));
        if (mdc) g_orig_dc = (id (*)(id, SEL))method_setImplementation(mdc, (IMP)ACE_dc);
// v7.44
        Method m4 = class_getInstanceMethod([NSNotificationCenter class],
                @selector(addObserverForName:object:queue:usingBlock:));
        if (m4) g_orig_addObs4 = (id (*)(id, SEL, NSString *, id, id, void *))
            method_setImplementation(m4, (IMP)ACE_addObs4);
        Method m5 = class_getInstanceMethod([NSNotificationCenter class],
                @selector(addObserver:selector:name:object:));
        if (m5) g_orig_addObsSel = (void (*)(id, SEL, id, SEL, NSString *, id))
            method_setImplementation(m5, (IMP)ACE_addObsSel);
        ACETrace(@"通知中心探针已挂=%d defaultCenter=%d 观察者探针=%d%d",
                 g_orig_post2 != NULL, g_orig_dc != NULL,
                 g_orig_addObs4 != NULL, g_orig_addObsSel != NULL);
    } @catch (NSException *e) { ACETrace(@"notif探针异常: %@", e); }
}
// ═══ v7.45 ═══
static void (*g_orig_iconClick)(id, SEL) = NULL;
static void ACE_icon_click(id self, SEL _cmd) {
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"[ball] iconOnClick 触发(开始过S链门禁)");
        g_ace_busy = 0;
    }
    if (g_orig_iconClick) g_orig_iconClick(self, _cmd);
    @try {
        void *st = ((void *(*)(id, SEL))objc_msgSend)(self, NSSelectorFromString(@"_0xE4C8719B"));
        if (st) {
// v7.90
// v7.89
            g_panelWant = (int)*(volatile uint8_t *)st;
            if (g_ace_ready && !g_ace_busy) {
                g_ace_busy = 1;
                ACETrace(@"[ball] 门禁结果: 面板标志byte[0]=%d → 意愿已同步 g_panelWant=%d",
                         *(volatile uint8_t *)st, g_panelWant);
                g_ace_busy = 0;
            }
        }
    } @catch (NSException *e) {}
}
static void (*g_orig_ballTouch)(id, SEL, void *, void *) = NULL;
static void ACE_ball_touch(id self, SEL _cmd, void *a, void *b) {
    @try {
        UIView *v = (UIView *)self;
        if (g_ace_ready && !g_ace_busy) {
            g_ace_busy = 1;
            ACETrace(@"[ball] touchesBegan 命中! frame=(%g,%g,%g,%g)",
                     v.frame.origin.x, v.frame.origin.y, v.frame.size.width, v.frame.size.height);
            g_ace_busy = 0;
        }
    } @catch (NSException *e) {}
    if (g_orig_ballTouch) g_orig_ballTouch(self, _cmd, a, b);
}
static void ACE_install_ball_probe(void) {
    @try {
        Class ball = NSClassFromString(@"_0xD4E9A3C7");
        if (!ball) { ACETrace(@"[ball] 类_0xD4E9A3C7不存在"); return; }
        Method m1 = class_getInstanceMethod(ball, NSSelectorFromString(@"iconOnClick"));
        if (m1) g_orig_iconClick = (void (*)(id, SEL))method_setImplementation(m1, (IMP)ACE_icon_click);
        Method m2 = class_getInstanceMethod(ball, NSSelectorFromString(@"touchesBegan:withEvent:"));
        if (m2) g_orig_ballTouch = (void (*)(id, SEL, void *, void *))method_setImplementation(m2, (IMP)ACE_ball_touch);
        ACETrace(@"[ball] 悬浮球探针已挂 iconOnClick=%d touches=%d",
                 g_orig_iconClick != NULL, g_orig_ballTouch != NULL);
    } @catch (NSException *e) { ACETrace(@"[ball] 探针异常: %@", e); }
}
// ═══ v7.48 ═══
// ═══ v7.49 修正 ═══
// v7.48
static id (*g_orig_initC)(id, SEL, void *) = NULL;
static id (*g_orig_initB)(id, SEL, void *) = NULL;
// v7.55
// v7.49
static id (*g_orig_initM)(id, SEL, void *, void *, void *, CGRect) = NULL;
static id ACE_hook_initC(id self, SEL _cmd, void *fp) {
    ACETrace(@"[initF] 容器_C8E2A541 initWithFrame:(%p) 被调用!", fp);
    id r = g_orig_initC ? g_orig_initC(self, _cmd, fp) : self;
    ACETrace(@"[initF] 容器init返回 %p", (__bridge void *)r);
    return r;
}
static id ACE_hook_initB(id self, SEL _cmd, void *fp) {
    ACETrace(@"[initF] 桥接_B1D7F3A9 initWithFrame:(%p) 被调用!", fp);
    id r = g_orig_initB ? g_orig_initB(self, _cmd, fp) : self;
    ACETrace(@"[initF] 桥接init返回 %p", (__bridge void *)r);
    return r;
}
static id ACE_hook_initM(id self, SEL _cmd, void *fp, void *a1, void *a2, CGRect r) {
    ACETrace(@"[initF] MTKView_1E6B7A93 initWithFrame::::(cfg=%p,容器=%p,桥接=%p,rect={%g,%g,%g,%g}) 被调用!",
             fp, a1, a2, r.origin.x, r.origin.y, r.size.width, r.size.height);
    id rr = g_orig_initM ? g_orig_initM(self, _cmd, fp, a1, a2, r) : self;
    ACETrace(@"[initF] MTKView init返回 %p %s", (__bridge void *)rr,
             rr ? "" : "★★nil=Metal创建失败");
    return rr;
}
// v7.49
static UIWindow *(*g_orig_keyWin)(id, SEL) = NULL;
static UIWindow *ACE_hook_keyWin(id self, SEL _cmd) {
    UIWindow *w = g_orig_keyWin ? g_orig_keyWin(self, _cmd) : nil;
    @try {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        if (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end)
            ACETrace(@"[kw] keyWindow caller=TGT+0x%lx → %p",
                     (unsigned long)(ra - g_tgt_base), (__bridge void *)w);
    } @catch (NSException *e) {}
    return w;
}
static void ACE_install_init_probe(void) {
    return;   // v7.95
    @try {
        Class c = NSClassFromString(@"_0xC8E2A541");
        if (c) { Method m = class_getInstanceMethod(c, NSSelectorFromString(@"initWithFrame:"));
                 if (m) g_orig_initC = (id (*)(id, SEL, void *))method_setImplementation(m, (IMP)ACE_hook_initC); }
        Class b = NSClassFromString(@"_0xB1D7F3A9");
        if (b) { Method m = class_getInstanceMethod(b, NSSelectorFromString(@"initWithFrame:"));
                 if (m) g_orig_initB = (id (*)(id, SEL, void *))method_setImplementation(m, (IMP)ACE_hook_initB); }
        Class mk = NSClassFromString(@"_0x1E6B7A93");
        if (mk) { Method m = class_getInstanceMethod(mk, NSSelectorFromString(@"initWithFrame::::"));
                 if (m) g_orig_initM = (id (*)(id, SEL, void *, void *, void *, CGRect))method_setImplementation(m, (IMP)ACE_hook_initM); }
// keyWindow 探针
        Method kw = class_getInstanceMethod([UIApplication class], @selector(keyWindow));
        if (kw) g_orig_keyWin = (UIWindow *(*)(id, SEL))method_setImplementation(kw, (IMP)ACE_hook_keyWin);
        ACETrace(@"[initF] v7.49探针已挂 容器=%d 桥接=%d MTKView=%d keyWindow=%d",
                 g_orig_initC != NULL, g_orig_initB != NULL, g_orig_initM != NULL, g_orig_keyWin != NULL);
    } @catch (NSException *e) { ACETrace(@"[initF] 探针异常: %@", e); }
}
static void ACE_ui_scan(const char *when) {
    (void)when; return;   // v7.95
    @try {
        NSMutableArray *stack = [NSMutableArray array];
        for (UIWindow *w in [[UIApplication sharedApplication] windows]) [stack addObject:w];
        int logged = 0;
        while ([stack count] > 0 && logged < 40) {
            UIView *v = (UIView *)[stack lastObject];
            [stack removeLastObject];
            for (UIView *s in [v subviews]) [stack addObject:s];
            NSString *cn = NSStringFromClass([v class]);
            if ([cn hasPrefix:@"_0x"]) {
                ACETrace(@"[ui-scan/%s] %s frame=(%g,%g,%g,%g) hidden=%d alpha=%g", when,
                         cn.UTF8String, v.frame.origin.x, v.frame.origin.y,
                         v.frame.size.width, v.frame.size.height, (int)v.hidden, v.alpha);
                logged++;
            }
        }
        if (logged == 0)
            ACETrace(@"[ui-scan/%s] 未发现靶场自建视图(观察者可能没跑/窗口未挂)", when);
    } @catch (NSException *e) { ACETrace(@"[ui-scan] 异常: %@", e); }
}
// ═══ v7.43 ═══
static volatile int g_secinit_hit = 0;
static void ACE_secinit_noop(void *block) {
    (void)block;
    if (!g_secinit_hit) {
        g_secinit_hit = 1;
        if (g_ace_ready && !g_ace_busy) {
            g_ace_busy = 1;
            ACETrace(@"[secinit] ★安保init被劫持为空操作—自毁链已掐断(存活)");
            g_ace_busy = 0;
        }
    }
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
// v7.42
// v7.41
    g_saved_slot_val = *slot;

    *slot = (void *)ACE_dispatch_async_hook;
// v7.87
    void **slotA = ACE_find_ptr_slot(hdr, "_dispatch_after");
    if (slotA) {
        *slotA = (void *)ACE_dispatch_after_hook;
        ACETrace(@"[hook] dispatch_after槽已改写 → %p", (void *)ACE_dispatch_after_hook);
    } else {
        ACETrace(@"[hook] 未找到 _dispatch_after 槽(靶场不用它或偏移漂移)");
    }
    ACETrace(@"结果hook 已安装: 靶场基址=%p __TEXT=0x%llx 槽=%p 原值=%p → %p",
             (void *)base, (unsigned long long)textsize, slot, g_saved_slot_val,
             (void *)ACE_dispatch_async_hook);
// v7.37
    volatile void **pcs = (volatile void **)(base + 0x3e87c8ULL);
    void *pcold = *pcs;
    Dl_info pcdi;
    if (pcold && dladdr(pcold, &pcdi) && pcdi.dli_fname && strstr(pcdi.dli_fname, "libsystem_pthread")) {
        g_real_pc = (ACE_pc_fn)pcold;
        *pcs = (void *)ACE_pc_gate;
        ACETrace(@"[gate] pthread_create槽已改写: %p(%s) → %p", pcold, pcdi.dli_fname, (void *)ACE_pc_gate);
    } else {
        ACETrace(@"[gate] pthread_create槽验证失败不改写: %p", pcold);
    }
// ═══ v7.43 核心 ═══
    {
        volatile uintptr_t *sinv = (volatile uintptr_t *)(base + 0x3e9240ULL);
        uintptr_t cur = *sinv;
        uintptr_t expect = base + 0xefe20ULL;
// ═══ v7.90 ═══
// v7.43
// v7.86
        (void)sinv;
        if (cur == expect || cur == 0xefe20ULL) {
            ACETrace(@"[secinit] v7.90 安保init已放行(invoke=0x%lx 原样) — 等它发命脉令牌[3ff6b8]",
                     (unsigned long)cur);
        } else {
            ACETrace(@"[secinit] 槽值0x%lx≠base+0xefe20(0x%lx), 未改(疑偏移漂移, 需核对)",
                     (unsigned long)cur, (unsigned long)expect);
        }
    }
}


// ═══ v8.02 ═══
static unsigned long long ACE_knm_noop0(id self, SEL _cmd) {
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"[knm] %@ -> 0", NSStringFromSelector(_cmd));
        g_ace_busy = 0;
    }
    return 0;
}
static unsigned long long ACE_knm_noop1(id self, SEL _cmd, id a) {
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"[knm] %@(%@) -> 0", NSStringFromSelector(_cmd), ACETrimStr(a, 80));
        g_ace_busy = 0;
    }
    return 0;
}
static int g_knm_hooked = 0;
static void ACE_knm_neuter(Class cls, const char *selname, IMP imp) {
    if (!cls) return;
    SEL s = NSSelectorFromString([NSString stringWithUTF8String:selname]);
    if (!s) return;
    Method m = class_getInstanceMethod(cls, s);
    if (!m) return;
    IMP cur = method_getImplementation(m);
    if (cur == imp) return;
    method_setImplementation(m, imp);
    g_knm_hooked++;
    ACETrace(@"[knm] 检测/处决方法已致盲: %@.%s (原IMP=%p)", NSStringFromClass(cls), selname, cur);
}
static void ACE_knm_sweep(void) {
    @try {
        static const char *detCls[] = { "_0x3F6A8E1C", "_0x7F2B4A6E", "_0xA5C3E8D1" };
        static const char *detSel[] = { "performFullDetection", "isJailbroken",
            "detectInjectedLibraries", "detectTweakInject", "detectSuspiciousFrameworks" };
        for (int c = 0; c < 3; c++) {
            Class k = NSClassFromString([NSString stringWithUTF8String:detCls[c]]);
            if (!k) continue;
            for (unsigned i = 0; i < sizeof(detSel)/sizeof(detSel[0]); i++)
                ACE_knm_neuter(k, detSel[i], (IMP)ACE_knm_noop0);
            ACE_knm_neuter(k, "getOffset:", (IMP)ACE_knm_noop1);
        }
        static const char *desSel[] = { "cleanupAndExit:", "forceExitWithReason:",
            "showBanAlertWithReason:", "showServerClosedAlert:", "showVersionUpdateAlert:",
            "showServerMessage:" };
        Class d = NSClassFromString(@"_0x3A8D7F4C");
        if (d) {
            for (unsigned i = 0; i < sizeof(desSel)/sizeof(desSel[0]); i++)
                ACE_knm_neuter(d, desSel[i], (IMP)ACE_knm_noop1);
            ACE_knm_neuter(d, "isShuttingDown", (IMP)ACE_knm_noop0);
        }
    } @catch (NSException *e) { ACETrace(@"[knm] sweep异常: %@", e); }
}
static void ACE_knm_tick(void) {
    ACE_knm_sweep();
    dispatch_after(dispatch_time(0, 1000000000LL), dispatch_get_main_queue(), ^{ ACE_knm_tick(); });
}


// ═══ v8.03 ═══
#import <mach-o/getsect.h>
#import <mach-o/dyld_images.h>
#include <mach/task_info.h>
typedef kern_return_t (*ACE_ti_fn)(mach_port_t, task_flavor_t, task_info_t, mach_msg_type_number_t *);
typedef kern_return_t (*ACE_vr64_fn)(vm_map_t, vm_address_t *, vm_size_t *, vm_region_flavor_t, vm_region_info_64_t, mach_msg_type_number_t *);
typedef kern_return_t (*ACE_vrr64_fn)(vm_map_t, vm_address_t *, vm_size_t *, vm_region_flavor_t, vm_region_info_64_t, mach_msg_type_number_t *, natural_t *);
typedef kern_return_t (*ACE_mvrr_fn)(task_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, natural_t *);
static ACE_ti_fn g_real_ti = NULL;
static ACE_vr64_fn g_real_vr64 = NULL;
static ACE_vrr64_fn g_real_vrr64 = NULL;
static ACE_mvrr_fn g_real_mvrr = NULL;
static uintptr_t g_self_lo = 0, g_self_hi = 0;
static long g_blindHits = 0;
static void ACE_self_range(void) {
    if (g_self_hi) return;
    const struct mach_header *h = ACE_self_header();
    if (!h) return;
    unsigned long sz = 0;
    getsegmentdata((const struct mach_header_64 *)h, "__LINKEDIT", &sz);
    g_self_lo = (uintptr_t)h;
    g_self_hi = (uintptr_t)h + sz;
}
static int ACE_addr_is_self(uintptr_t a) {
    ACE_self_range();
    return g_self_hi && a >= g_self_lo && a < g_self_hi;
}
static int ACE_addr_is_tramp(uintptr_t a) {
    Dl_info di;
    if (!a) return 0;
    if (dladdr((const void *)a, &di) && di.dli_fname)
        return strstr(di.dli_fname, "libobjc-trampolines") != NULL;
    return 0;
}
static void *g_ti_copy = NULL;
static uint32_t g_ti_cnt = 0xffffffffu;
static kern_return_t ACE_task_info_hook(mach_port_t tp, task_flavor_t flavor, task_info_t ti, mach_msg_type_number_t *cnt) {
    kern_return_t kr = g_real_ti(tp, flavor, ti, cnt);
    if (kr != KERN_SUCCESS || flavor != 17 || !ti || !cnt) return kr;   // 17=TASK_DYLD_INFO
    @try {
        uint32_t n = _dyld_image_count();
        if (!g_ti_copy || n != g_ti_cnt) {
            struct dyld_all_image_infos *real = *(struct dyld_all_image_infos **)ti;
            if (real && real->infoArrayCount > 0 && real->infoArrayCount < 4096) {
                ACE_self_range();
                struct dyld_all_image_infos *cp =
                    (struct dyld_all_image_infos *)calloc(1, sizeof(*cp));
                struct dyld_image_info *arr =
                    (struct dyld_image_info *)calloc(real->infoArrayCount, sizeof(*arr));
                *cp = *real;
                uint32_t k = 0;
                const struct mach_header *th = NULL;
                int t88 = ACE_find_tramp_index();
                if (t88 >= 0) th = _dyld_get_image_header((uint32_t)t88);
                for (uint32_t i = 0; i < real->infoArrayCount; i++) {
                    if ((uintptr_t)real->infoArray[i].imageLoadAddress == g_self_lo) continue;
                    if (th && real->infoArray[i].imageLoadAddress == th) continue;
                    arr[k++] = real->infoArray[i];
                }
                cp->infoArray = arr;
                cp->infoArrayCount = k;
                if (g_ti_copy) { free((void *)((struct dyld_all_image_infos *)g_ti_copy)->infoArray); free(g_ti_copy); }
                g_ti_copy = cp;
                g_ti_cnt = n;
                if (g_blindHits < 60) {
                    g_blindHits++;
                    ACETrace(@"[blind] task_info(DYLD_INFO) 过滤副本: %u→%u 项(摘除本镜像)",
                             real->infoArrayCount, k);
                }
            }
        }
        if (g_ti_copy) {
            *(struct dyld_all_image_infos **)ti = (struct dyld_all_image_infos *)g_ti_copy;
        }
    } @catch (NSException *e) {}
    return kr;
}
static kern_return_t ACE_vm_region_64_hook(vm_map_t tm, vm_address_t *addr, vm_size_t *sz,
        vm_region_flavor_t flav, vm_region_info_64_t info, mach_msg_type_number_t *cnt) {
    for (int guard = 0; guard < 64; guard++) {
        kern_return_t kr = g_real_vr64(tm, addr, sz, flav, info, cnt);
        if (kr != KERN_SUCCESS || !addr) return kr;
        if (!ACE_addr_is_self(*addr) && !ACE_addr_is_tramp(*addr)) return kr;
        if (g_blindHits < 60) { g_blindHits++;
            ACETrace(@"[blind] vm_region_64 摘除本镜像区域 @0x%lx", (unsigned long)*addr); }
        *addr = (g_self_hi && *addr < g_self_hi) ? g_self_hi : (*addr + (sz ? *sz : 0x4000));
    }
    return KERN_FAILURE;
}
static kern_return_t ACE_vm_region_recurse_64_hook(vm_map_t tm, vm_address_t *addr, vm_size_t *sz,
        vm_region_flavor_t flav, vm_region_info_64_t info, mach_msg_type_number_t *cnt, natural_t *depth) {
    for (int guard = 0; guard < 64; guard++) {
        kern_return_t kr = g_real_vrr64(tm, addr, sz, flav, info, cnt, depth);
        if (kr != KERN_SUCCESS || !addr) return kr;
        if (!ACE_addr_is_self(*addr) && !ACE_addr_is_tramp(*addr)) return kr;
        if (g_blindHits < 60) { g_blindHits++;
            ACETrace(@"[blind] vm_region_recurse_64 摘除本镜像区域 @0x%lx", (unsigned long)*addr); }
        *addr = (g_self_hi && *addr < g_self_hi) ? g_self_hi : (*addr + (sz ? *sz : 0x4000));
    }
    return KERN_FAILURE;
}
static kern_return_t ACE_mach_vm_region_recurse_hook(task_t tm, mach_vm_address_t *addr, mach_vm_size_t *sz,
        vm_region_flavor_t flav, vm_region_info_t info, mach_msg_type_number_t *cnt, natural_t *depth) {
    for (int guard = 0; guard < 64; guard++) {
        kern_return_t kr = g_real_mvrr(tm, addr, sz, flav, info, cnt, depth);
        if (kr != KERN_SUCCESS || !addr) return kr;
        if (!ACE_addr_is_self((uintptr_t)*addr) && !ACE_addr_is_tramp((uintptr_t)*addr)) return kr;
        if (g_blindHits < 60) { g_blindHits++;
            ACETrace(@"[blind] mach_vm_region_recurse 摘除本镜像区域 @0x%llx", (unsigned long long)*addr); }
        *addr = (g_self_hi && *addr < g_self_hi) ? g_self_hi : (*addr + (sz ? *sz : 0x4000));
    }
    return KERN_FAILURE;
}
static void *ACE_resolve_real(const char *sym, void *saved) {
    Dl_info di;
    if (saved && dladdr(saved, &di)) {
        if (di.dli_sname && strstr(di.dli_sname, "stub_binder")) saved = NULL;
        if (di.dli_fbase == ACE_self_header()) saved = NULL;
    } else if (saved) {
        return saved;
    }
    if (saved) return saved;
    void *p = dlsym(RTLD_NEXT, sym + 1);
    if (!p) p = dlsym(RTLD_DEFAULT, sym + 1);
    return p;
}
static void ACE_hook_slot(const struct mach_header *hdr, const char *sym, void *rep, void **save) {
    void **slot = ACE_find_ptr_slot(hdr, sym);
    if (!slot) return;
    Dl_info di;
    if (dladdr(*slot, &di) && di.dli_fbase && di.dli_fbase == ACE_self_header()) return;
    void *real = ACE_resolve_real(sym, *slot);
    if (!real) { ACETrace(@"[blind] %s 真身解析失败, 不改写", sym); return; }
    if (save) *save = real;
    *slot = rep;
    ACETrace(@"[blind] %s 槽已改写 → %p (真身=%p)", sym, rep, real);
}
typedef int (*ACE_dladdr_fn)(const void *, Dl_info *);
static ACE_dladdr_fn g_real_dla = NULL;
static int ACE_dladdr_hook(const void *p, Dl_info *info) {
    uintptr_t a = (uintptr_t)p;
    if (ACE_addr_is_self(a)) return 0;
    if (g_real_dla) {
        Dl_info tmp;
        if (g_real_dla(p, &tmp) && tmp.dli_fname && strstr(tmp.dli_fname, "libobjc-trampolines"))
            return 0;
    }
    return g_real_dla ? g_real_dla(p, info) : 0;
}
static void ACE_install_blind_hooks(void) {
    @try {
        const struct mach_header *hdr = ACE_find_target_header();
        if (!hdr) return;
        ACE_self_range();
        ACE_hook_slot(hdr, "_task_info", (void *)ACE_task_info_hook, (void **)&g_real_ti);
        ACE_hook_slot(hdr, "_vm_region_64", (void *)ACE_vm_region_64_hook, (void **)&g_real_vr64);
        ACE_hook_slot(hdr, "_vm_region_recurse_64", (void *)ACE_vm_region_recurse_64_hook, (void **)&g_real_vrr64);
        ACE_hook_slot(hdr, "_mach_vm_region_recurse", (void *)ACE_mach_vm_region_recurse_hook, (void **)&g_real_mvrr);
        ACE_hook_slot(hdr, "_dladdr", (void *)ACE_dladdr_hook, (void **)&g_real_dla);
    } @catch (NSException *e) { ACETrace(@"[blind] 安装异常: %@", e); }
}
static void ACE_blind_tick(void) {
    if (g_tgt_base) ACE_install_blind_hooks();
    dispatch_after(dispatch_time(0, 1000000000LL), dispatch_get_main_queue(), ^{ ACE_blind_tick(); });
}


// ═══ v8.04 测量层 ═══
typedef void *(*ACE_dlsym_fn)(void *, const char *);
typedef int (*ACE_connect_fn)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*ACE_send_fn)(int, const void *, size_t, int);
typedef ssize_t (*ACE_recv_fn)(int, void *, size_t, int);
static ACE_dlsym_fn g_real_dlsym = NULL;
static ACE_connect_fn g_real_connect = NULL;
static ACE_send_fn g_real_send = NULL;
static ACE_recv_fn g_real_recv = NULL;
// --- il2cpp 蹦床(v8.05): ace 经 dlsym 拿 il2cpp 函数指针, 我们在此换包
typedef void *(*ACE_il2invoke_fn)(void *, void *, void **, void **);
typedef const char *(*ACE_il2mname_fn)(void *);
typedef const char *(*ACE_il2cname_fn)(void *);
typedef void *(*ACE_il2mfromname_fn)(void *, const char *, int);
typedef void *(*ACE_il2ffromname_fn)(void *, const char *);
typedef void (*ACE_il2fstatic_fn)(void *, void *);
typedef const char *(*ACE_il2fname_fn)(void *);
static ACE_il2invoke_fn g_il2_invoke = NULL;
static ACE_il2mname_fn g_il2_mname = NULL;
static ACE_il2cname_fn g_il2_cname = NULL;
static ACE_il2mfromname_fn g_il2_mfrom = NULL;
static ACE_il2ffromname_fn g_il2_ffrom = NULL;
static ACE_il2fstatic_fn g_il2_fstatic = NULL;
static ACE_il2fname_fn g_il2_fname = NULL;
static int g_il2_logn = 0;
static void ACE_il2_log(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void ACE_il2_log(const char *fmt, ...) {
    if (g_il2_logn > 600) return;
    g_il2_logn++;
    va_list ap; va_start(ap, fmt);
    NSString *f = [NSString stringWithUTF8String:fmt];
    NSString *body = [[NSString alloc] initWithFormat:f arguments:ap];
    va_end(ap);
    ACETrace(@"[il2] %@", body);
}
static void *ACE_il2_invoke_trap(void *method, void *obj, void **params, void **exc) {
    const char *mn = (g_il2_mname && method) ? g_il2_mname(method) : "?";
    ACE_il2_log("runtime_invoke method=%s obj=%p", mn ? mn : "?", obj);
    return g_il2_invoke(method, obj, params, exc);
}
static void *ACE_il2_mfrom_trap(void *cls, const char *name, int pc) {
    const char *cn = (g_il2_cname && cls) ? g_il2_cname(cls) : "?";
    void *r = g_il2_mfrom(cls, name, pc);
    ACE_il2_log("class_get_method_from_name class=%s name=%s(%d) → %p", cn ? cn : "?", name ? name : "?", pc, r);
    return r;
}
static void *ACE_il2_ffrom_trap(void *cls, const char *name) {
    const char *cn = (g_il2_cname && cls) ? g_il2_cname(cls) : "?";
    void *r = g_il2_ffrom(cls, name);
    ACE_il2_log("class_get_field_from_name class=%s name=%s → %p", cn ? cn : "?", name ? name : "?", r);
    return r;
}
static void ACE_il2_fstatic_trap(void *field, void *value) {
    const char *fn = (g_il2_fname && field) ? g_il2_fname(field) : "?";
    g_il2_fstatic(field, value);
    ACE_il2_log("field_static_get_value field=%s", fn ? fn : "?");
}
static void *ACE_dlsym_trace(void *h, const char *name) {
    void *r = g_real_dlsym ? g_real_dlsym(h, name) : NULL;
    static int n = 0;
    if (name && r) {
        if (!strcmp(name, "il2cpp_runtime_invoke") && !g_il2_invoke) { g_il2_invoke = (ACE_il2invoke_fn)r; r = (void *)ACE_il2_invoke_trap; }
        else if (!strcmp(name, "il2cpp_method_get_name") && !g_il2_mname) { g_il2_mname = (ACE_il2mname_fn)r; }
        else if (!strcmp(name, "il2cpp_class_get_name") && !g_il2_cname) { g_il2_cname = (ACE_il2cname_fn)r; }
        else if (!strcmp(name, "il2cpp_class_get_method_from_name") && !g_il2_mfrom) { g_il2_mfrom = (ACE_il2mfromname_fn)r; r = (void *)ACE_il2_mfrom_trap; }
        else if (!strcmp(name, "il2cpp_class_get_field_from_name") && !g_il2_ffrom) { g_il2_ffrom = (ACE_il2ffromname_fn)r; r = (void *)ACE_il2_ffrom_trap; }
        else if (!strcmp(name, "il2cpp_field_static_get_value") && !g_il2_fstatic) { g_il2_fstatic = (ACE_il2fstatic_fn)r; r = (void *)ACE_il2_fstatic_trap; }
        else if (!strcmp(name, "il2cpp_field_get_name") && !g_il2_fname) { g_il2_fname = (ACE_il2fname_fn)r; }
    }
    if (g_ace_ready && !g_ace_busy && n < 400 && name) {
        g_ace_busy = 1; n++;
        ACETrace(@"[sym] ace dlsym(%s) → %p%s", name, r,
                 (r == (void *)ACE_il2_invoke_trap || r == (void *)ACE_il2_mfrom_trap ||
                  r == (void *)ACE_il2_ffrom_trap || r == (void *)ACE_il2_fstatic_trap) ? " (已换蹦床)" : "");
        g_ace_busy = 0;
    }
    return r;
}
static int ACE_connect_trace(int fd, const struct sockaddr *sa, socklen_t len) {
    int rc = g_real_connect ? g_real_connect(fd, sa, len) : -1;
    if (sa && sa->sa_family == AF_INET) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)sa;
        char ip[32] = {0};
        inet_ntop(AF_INET, &si->sin_addr, ip, sizeof(ip));
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        ACETrace(@"[net] connect fd=%d %s:%d rc=%d caller=%p(%s)", fd, ip, ntohs(si->sin_port), rc,
                 (void *)ra, (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end) ? "ace" : "?");
    }
    return rc;
}
static int g_net_logn = 0;
static ssize_t ACE_send_trace(int fd, const void *buf, size_t n, int f) {
    ssize_t rc = g_real_send ? g_real_send(fd, buf, n, f) : -1;
    if (g_net_logn < 120 && buf && n) {
        g_net_logn++;
        size_t m = n < 48 ? n : 48;
        NSMutableString *hx = [NSMutableString stringWithCapacity:m*3];
        const unsigned char *p = (const unsigned char *)buf;
        for (size_t i = 0; i < m; i++) [hx appendFormat:@"%02x ", p[i]];
        ACETrace(@"[net] send fd=%d len=%zu rc=%zd head=%@", fd, n, rc, hx);
    }
    return rc;
}
static ssize_t ACE_recv_trace(int fd, void *buf, size_t n, int f) {
    ssize_t rc = g_real_recv ? g_real_recv(fd, buf, n, f) : -1;
    if (rc > 0 && g_net_logn < 240) {
        g_net_logn++;
        size_t m = (size_t)rc < 48 ? (size_t)rc : 48;
        NSMutableString *hx = [NSMutableString stringWithCapacity:m*3];
        const unsigned char *p = (const unsigned char *)buf;
        for (size_t i = 0; i < m; i++) [hx appendFormat:@"%02x ", p[i]];
        ACETrace(@"[net] recv fd=%d len=%zd head=%@", fd, rc, hx);
    }
    return rc;
}
// --- prologue 完整性探针
static void ACE_probe_prologues(void) {
    static const char *names[] = {
        "_dyld_image_count", "_dyld_get_image_name", "_dyld_get_image_header",
        "task_info", "task_threads", "vm_region_64", "vm_region_recurse_64",
        "mach_vm_region_recurse", "objc_getClassList", "objc_getClass",
        "class_getImageName", "pthread_create", "dlsym", "dladdr" };
    for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        void *p = dlsym(RTLD_DEFAULT, names[i]);
        if (!p) { ACETrace(@"[probe] %s 解析失败", names[i]); continue; }
        const uint32_t *w = (const uint32_t *)p;
        uint32_t w0 = w[0], w1 = w[1], w2 = w[2];
        int sus = 0;
        if ((w0 & 0xFC000000u) == 0x14000000u) sus = 1;                 // b far
        if ((w0 & 0xFFFFFC1Fu) == 0xD61F0000u) sus = 2;                 // br xN
        if ((w0 & 0x9F000000u) == 0x90000000u && (w1 & 0xFFFFFC1Fu) == 0xD61F0000u) sus = 3; // adrp+br
        if ((w0 & 0xFF00001Fu) == 0x58000010u) sus = 4;                 // ldr x16 literal
        ACETrace(@"[probe] %-22s %p %08x %08x %08x%s", names[i], p, w0, w1, w2,
                 sus ? "  ★★疑似被inline-hook(模式%d)" : "");
        if (sus) g_blindHits++;
    }
}
// --- 匿名 r-x trampoline 池扫描
static void ACE_scan_rx_pools(void) {
    // v8.09: 整体切除。全地址空间vm_region遍历会踩中iOS18桩函数OOL冷路径的NULL写
    // (两次闪退实证: vm_region_64+72 / +552, str w8,[x20] x20=0)。
    // 该探针目的(找Dobby蹦床池)已由ACE_probe_prologues覆盖, 且静态分析证明ace启动期不做inline hook。
    static int once = 0;
    if (!once) { once = 1; ACETrace(@"[pool] r-x池扫描已移除(v8.09): 系统vm_region桩函数边角崩溃, 探针无价值"); }
}
// --- UI 判决追踪+抑制
static BOOL ACE_text_is_kick(NSString *s) {
    if (!s) return NO;
    return [s containsString:@"官方客户端"] || [s containsString:@"绿色球球"] || [s containsString:@"球宝家园"];
}
static void ACE_log_caller_ra(const char *what, uintptr_t ra) {
    Dl_info di;
    const char *img = "?";
    if (dladdr((const void *)ra, &di) && di.dli_fname) {
        const char *sl = strrchr(di.dli_fname, '/');
        img = sl ? sl + 1 : di.dli_fname;
    }
    ACETrace(@"[ui] %s caller=%p img=%s%s", what, (void *)ra, img,
             (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end) ? "(ace内)" : "");
}
static void ACE_log_caller(const char *what) {
    ACE_log_caller_ra(what, (uintptr_t)__builtin_return_address(0));
}
static void (*g_orig_presentVC)(id, SEL, id, BOOL, id) = NULL;
static void ACE_hook_presentVC(id self, SEL _cmd, id vc, BOOL anim, id completion) {
    @try {
        NSString *t = [vc respondsToSelector:@selector(title)] ? [vc title] : nil;
        NSString *m = nil;
        if ([vc respondsToSelector:@selector(message)]) m = [vc message];
        if (ACE_text_is_kick(t) || ACE_text_is_kick(m)) {
            ACE_log_caller_ra("presentViewController 抑制判决弹窗", (uintptr_t)__builtin_return_address(0));
            ACETrace(@"[ui] 抑制: title=%@ msg=%@", t, m);
            return;
        }
        if (g_ace_busy == 0) ACE_log_caller_ra("presentViewController", (uintptr_t)__builtin_return_address(0));
    } @catch (NSException *e) {}
    if (g_orig_presentVC) g_orig_presentVC(self, _cmd, vc, anim, completion);
}
static void (*g_orig_addSubview)(id, SEL, id) = NULL;
static void ACE_hook_addSubview(id self, SEL _cmd, id v) {
    @try {
        if ([self isKindOfClass:[UIWindow class]]) {
            ACE_log_caller_ra("UIWindow addSubview", (uintptr_t)__builtin_return_address(0));
            ACETrace(@"[ui] window+%@ class=%s", v, class_getName(object_getClass(v)));
        }
    } @catch (NSException *e) {}
    if (g_orig_addSubview) g_orig_addSubview(self, _cmd, v);
}
static void (*g_orig_setText)(id, SEL, id) = NULL;
static void ACE_hook_setText(id self, SEL _cmd, id txt) {
    @try {
        if ([txt isKindOfClass:[NSString class]] && ACE_text_is_kick((NSString *)txt)) {
            ACE_log_caller_ra("UILabel setText 抑制判决文案", (uintptr_t)__builtin_return_address(0));
            ACETrace(@"[ui] 抑制setText: %@", txt);
            return;
        }
    } @catch (NSException *e) {}
    if (g_orig_setText) g_orig_setText(self, _cmd, txt);
}
static void ACE_install_ui_tracers(void) {
    @try {
        Method m = class_getInstanceMethod([UIViewController class], @selector(presentViewController:animated:completion:));
        if (m && !g_orig_presentVC) g_orig_presentVC = (void (*)(id, SEL, id, BOOL, id))method_setImplementation(m, (IMP)ACE_hook_presentVC);
        m = class_getInstanceMethod([UIView class], @selector(addSubview:));
        if (m && !g_orig_addSubview) g_orig_addSubview = (void (*)(id, SEL, id))method_setImplementation(m, (IMP)ACE_hook_addSubview);
        m = class_getInstanceMethod([UILabel class], @selector(setText:));
        if (m && !g_orig_setText) g_orig_setText = (void (*)(id, SEL, id))method_setImplementation(m, (IMP)ACE_hook_setText);
        ACETrace(@"[ui] 追踪器已装 present=%d addSub=%d setText=%d", !!g_orig_presentVC, !!g_orig_addSubview, !!g_orig_setText);
    } @catch (NSException *e) { ACETrace(@"[ui] 追踪器异常: %@", e); }
}
static void ACE_install_net_tracers(const struct mach_header *hdr) {
    ACE_hook_slot(hdr, "_dlsym", (void *)ACE_dlsym_trace, (void **)&g_real_dlsym);
    ACE_hook_slot(hdr, "_connect", (void *)ACE_connect_trace, (void **)&g_real_connect);
    ACE_hook_slot(hdr, "_send", (void *)ACE_send_trace, (void **)&g_real_send);
    ACE_hook_slot(hdr, "_recv", (void *)ACE_recv_trace, (void **)&g_real_recv);
}
static void ACE_measure_tick(int round) {
    @try {
        ACETrace(@"[measure] === 第%d轮测量 ===", round);
        ACE_probe_prologues();
        ACE_scan_rx_pools();
    } @catch (NSException *e) {}
    if (round < 10)
        dispatch_after(dispatch_time(0, 10000000000LL), dispatch_get_main_queue(), ^{ ACE_measure_tick(round + 1); });
}


// ═══ v8.07 HTTPS 轨迹 ═══
static id (*g_orig_dtReqComp)(id, SEL, id, id) = NULL;
static id (*g_orig_dtUrlComp)(id, SEL, id, id) = NULL;
static id (*g_orig_dtReqSolo)(id, SEL, id) = NULL;
static int g_http_logn = 0;
static void ACE_http_attr_ra(const char *tag, NSURL *u, NSData *body, NSString *method, uintptr_t ra) {
    if (g_http_logn >= 300) return;
    g_http_logn++;
    Dl_info di; const char *img = "?";
    if (dladdr((const void *)ra, &di) && di.dli_fname) {
        const char *sl = strrchr(di.dli_fname, '/'); img = sl ? sl+1 : di.dli_fname;
    }
    ACETrace(@"[http] %s %s %@ host=%@ img=%s%s bodylen=%lu",
             tag, method ? [method UTF8String] : "-", u ? u.absoluteString : @"(nil)",
             u ? u.host : @"-", img,
             (g_tgt_base && ra >= g_tgt_base && ra < g_tgt_end) ? "(ace内)" : "",
             (unsigned long)[body length]);
    if (body && [body length] && [body length] < 2000) {
        NSString *bs = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (bs) ACETrace(@"[http] body=%@", bs);
    }
}
static id ACE_hook_dtReqComp(id self, SEL _cmd, id req, id completion) {
    if (!g_http_arm) return g_orig_dtReqComp ? g_orig_dtReqComp(self, _cmd, req, completion) : nil;
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    @try {
        NSURL *u = [req respondsToSelector:@selector(URL)] ? [req URL] : nil;
        NSData *body = [req respondsToSelector:@selector(HTTPBody)] ? [req HTTPBody] : nil;
        NSString *m = [req respondsToSelector:@selector(HTTPMethod)] ? [req HTTPMethod] : nil;
        ACE_http_attr_ra("req", u, body, m, ra);
        if (completion) {
            void (^orig)(NSData *, id, NSError *) = (void (^)(NSData *, id, NSError *))completion;
            id wrapped = ^(NSData *d, id resp, NSError *e) {
                orig(d, resp, e);   // v8.08: 先原样转发, 日志异步补
                if (!g_http_logq) g_http_logq = dispatch_queue_create("ace.httplog", DISPATCH_QUEUE_SERIAL);
                NSURL *u2 = u;
                dispatch_async(g_http_logq, ^{
                    @try {
                        long sc = 0;
                        if ([resp respondsToSelector:@selector(statusCode)]) sc = (long)[(NSHTTPURLResponse *)resp statusCode];
                        if (g_http_logn < 300) {
                            g_http_logn++;
                            ACETrace(@"[http] resp status=%ld len=%lu url=%@", sc, (unsigned long)[d length], u2 ? u2.absoluteString : @"-");
                            if (d && [d length] && [d length] < 2000) {
                                NSString *ds = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                                if (ds) ACETrace(@"[http] respbody=%@", ds);
                            }
                        }
                    } @catch (NSException *e2) {}
                });
            };
            return g_orig_dtReqComp(self, _cmd, req, wrapped);
        }
    } @catch (NSException *e) {}
    return g_orig_dtReqComp ? g_orig_dtReqComp(self, _cmd, req, completion) : nil;
}
static id ACE_hook_dtUrlComp(id self, SEL _cmd, id url, id completion) {
    if (g_http_arm) { @try { ACE_http_attr_ra("reqURL", url, nil, @"GET", (uintptr_t)__builtin_return_address(0)); } @catch (NSException *e) {} }
    return g_orig_dtUrlComp ? g_orig_dtUrlComp(self, _cmd, url, completion) : nil;
}
static id ACE_hook_dtReqSolo(id self, SEL _cmd, id req) {
    if (g_http_arm) {
        @try {
            NSURL *u = [req respondsToSelector:@selector(URL)] ? [req URL] : nil;
            NSData *body = [req respondsToSelector:@selector(HTTPBody)] ? [req HTTPBody] : nil;
            NSString *m = [req respondsToSelector:@selector(HTTPMethod)] ? [req HTTPMethod] : nil;
            ACE_http_attr_ra("reqSolo", u, body, m, (uintptr_t)__builtin_return_address(0));
        } @catch (NSException *e) {}
    }
    return g_orig_dtReqSolo ? g_orig_dtReqSolo(self, _cmd, req) : nil;
}
static void ACE_install_http_tracers(void) {
    @try {
        Class c = [NSURLSession class];
        Method m = class_getInstanceMethod(c, @selector(dataTaskWithRequest:completionHandler:));
        if (m && !g_orig_dtReqComp) g_orig_dtReqComp = (id (*)(id, SEL, id, id))method_setImplementation(m, (IMP)ACE_hook_dtReqComp);
        m = class_getInstanceMethod(c, @selector(dataTaskWithURL:completionHandler:));
        if (m && !g_orig_dtUrlComp) g_orig_dtUrlComp = (id (*)(id, SEL, id, id))method_setImplementation(m, (IMP)ACE_hook_dtUrlComp);
        m = class_getInstanceMethod(c, @selector(dataTaskWithRequest:));
        if (m && !g_orig_dtReqSolo) g_orig_dtReqSolo = (id (*)(id, SEL, id))method_setImplementation(m, (IMP)ACE_hook_dtReqSolo);
        ACETrace(@"[http] NSURLSession 追踪已装 req=%d url=%d solo=%d", !!g_orig_dtReqComp, !!g_orig_dtUrlComp, !!g_orig_dtReqSolo);
    } @catch (NSException *e) { ACETrace(@"[http] 追踪安装异常: %@", e); }
}

// ═══ 屏幕悬浮按钮 ═══
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
            if (g_logWin || g_btn_retry > 80) return;
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
            ACETrace(@"interpose命中: tsep=%d taskThreads=%d exit=%d abort=%d _exit=%d (tsep>0=隐身层实锤生效)",
                     g_hit_tsep, g_hit_tt, g_hit_exit, g_hit_abort, g_hit__exit);
            ACETrace(@"悬浮按钮已显示：点一下=复制全部日志，按住可拖动");
        } @catch (NSException *e) { ACETrace(@"按钮创建失败: %@", e); }
    }
}

// ═══ 第 1 层 ═══
@interface ACELicensePatch : NSObject
@end

@implementation ACELicensePatch

static IMP g_pwGet_imp = NULL;
// v7.7
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

// ═══ v7.20 采集器 A ═══
static void ACE_dump_ctx_full(NSString *tag) {
    @try {
        if (!g_tgt_base) { ACETrace(@"[dump] %s: g_tgt_base 未就绪", tag.UTF8String); return; }
        uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff658);
        if (ctx < 0x100000000ULL) { ACETrace(@"[dump] %@: ctx 指针无效=%llx", tag, (unsigned long long)ctx); return; }
        const unsigned char *p = (const unsigned char *)ctx;
        ACETrace(@"[dump] %@ ctx=%p 全量0x11c6:", tag, (void *)ctx);
        for (int off = 0; off < 0x11c6; off += 32) {
            NSMutableString *hex = [NSMutableString stringWithCapacity:100];
            int n = (0x11c6 - off) < 32 ? (0x11c6 - off) : 32;
            for (int i = 0; i < n; i++) [hex appendFormat:@"%02x", p[off + i]];
            ACETrace(@"[dump] +%04x: %@", off, hex);
        }
    } @catch (NSException *e) { ACETrace(@"[dump] 异常: %@", e); }
}

// ═══ v7.20 采集器 B ═══
static const char *ACE_SRV_IP = "111.170.155.161";
static uint16_t    ACE_SRV_PORT = 9527;   // htons 前主机序
static void ACE_hexdump_bytes(NSString *tag, const unsigned char *b, int n) {
    if (n <= 0) { ACETrace(@"[probe] %@: (空)", tag); return; }
    for (int off = 0; off < n; off += 32) {
        NSMutableString *hex = [NSMutableString string];
        NSMutableString *asc = [NSMutableString string];
        int m = (n - off) < 32 ? (n - off) : 32;
        for (int i = 0; i < m; i++) {
            [hex appendFormat:@"%02x", b[off + i]];
            unsigned char c = b[off + i];
            [asc appendFormat:@"%c", (c >= 0x20 && c < 0x7f) ? c : '.'];
        }
        ACETrace(@"[probe] %@ +%03x: %-64s |%@|", tag, off, hex.UTF8String, asc);
    }
}
static void *ACE_net_probe(void *arg) {
    (void)arg; return NULL;   // v7.95
    (void)arg;
    @autoreleasepool {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { ACETrace(@"[probe] socket 失败 errno=%d", errno); return NULL; }
        struct timeval tv; tv.tv_sec = 4; tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(ACE_SRV_PORT);
        inet_pton(AF_INET, ACE_SRV_IP, &sa.sin_addr);
        ACETrace(@"[probe] 连接 %s:%d fd=%d ...", ACE_SRV_IP, ACE_SRV_PORT, fd);
        int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
        if (rc != 0) {
            ACETrace(@"[probe] connect 失败 errno=%d (%s) —— 服务器不可达, -404 可能是本地伪造",
                     errno, strerror(errno));
            close(fd); return NULL;
        }
        ACETrace(@"[probe] ★ connect 成功: 服务器存活, -404 是真实回包!");
        unsigned char buf[4096];
        int got = (int)recv(fd, buf, sizeof(buf), 0);
        if (got > 0) {
            ACETrace(@"[probe] 连上即收到 %d 字节(握手/banner):", got);
            ACE_hexdump_bytes(@"banner", buf, got);
        } else {
            ACETrace(@"[probe] 连上无 banner (recv=%d errno=%d), 主动发探测帧", got, errno);
        }
        unsigned char probe[9] = { 0xAC, 0x01, 0x02, 0,0, 0,0,0,0 };
        int sent = (int)send(fd, probe, sizeof(probe), 0);
        ACETrace(@"[probe] 发送探测帧 %d 字节: AC 01 02 len=0", sent);
        got = (int)recv(fd, buf, sizeof(buf), 0);
        ACETrace(@"[probe] 探测回包 %d 字节 errno=%d:", got, got > 0 ? 0 : errno);
        if (got > 0) ACE_hexdump_bytes(@"resp", buf, got);
        close(fd);
        ACETrace(@"[probe] 完成");
    }
    return NULL;
}
static void ACE_start_net_probe(void) {
    pthread_t th; pthread_attr_t at; pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &at, ACE_net_probe, NULL);
    pthread_attr_destroy(&at);
}

static id ACE_alert_init(id cls, SEL _cmd, id title, id msg, NSInteger style) {
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"UIAlert title=[%@] msg=[%@]", ACETrimStr(title, 96), ACETrimStr(msg, 160));
// v7.20
        NSString *t = [title isKindOfClass:[NSString class]] ? title : @"";
        NSString *m = [msg isKindOfClass:[NSString class]] ? msg : @"";
        if ([t containsString:@"授权"] || [t containsString:@"到期"] ||
            [m containsString:@"到期"] || [m containsString:@"激活"]) {
            ACE_dump_ctx_full(@"成功弹窗");
        }
// v7.44
        if ([t containsString:@"授权成功"] || [t containsString:@"激活成功"]) {
            ACE_schedule_sec_posts();
// v7.45
            dispatch_after(dispatch_time(0, 2500000000LL), dispatch_get_main_queue(), ^{ ACE_ui_scan("成功后2.5s"); });
            dispatch_after(dispatch_time(0, 8000000000LL), dispatch_get_main_queue(), ^{ ACE_ui_scan("成功后8s"); });
        }
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
    g_ace_ready = 1;
    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            g_ace_busy = 1;
            g_main_th = mach_thread_self();   // v7.31
            ACETrace(@"=== v8.09 启动（★v8.09: 整体切除r-x池扫描(iOS18 vm_region桩NULL写闪退根因, 两次实证); HTTPS轨迹维持v8.08验卡后武装; 仍零修改ace逻辑: 断点扫描器sub_53df8真值供血(v7.94分流规则原样)/区域冻结freezer全区扫描/全屏透传窗菜单球点按必切换(byte0/cfgPtr/hidden三直写+keeper自愈)）===");
            @try { ACE_report_last_crash(); } @catch (NSException *e) {}
            @try { ACE_install_crash_catcher(); } @catch (NSException *e) { ACETrace(@"崩溃捕捉器异常: %@", e); }
            @try { ACE_install_exc_server(); } @catch (NSException *e) { ACETrace(@"异常捕捉层异常: %@", e); }
            @try { ACE_install_heartbeat(); } @catch (NSException *e) { ACETrace(@"心跳异常: %@", e); }
            @try { ACE_install_v79_threads(); } @catch (NSException *e) { ACETrace(@"v7.9线程异常: %@", e); }
            @try { ACE_boot_purge(); } @catch (NSException *e) { ACETrace(@"启动净化异常: %@", e); }
            @try { ACE_install_result_hook(); } @catch (NSException *e) { ACETrace(@"结果hook异常: %@", e); }
            @try {
// v7.95
                ACE_install_notif_probe();   // v7.40
                ACE_install_ball_probe();   // v7.45
                ACE_install_init_probe();   // v7.48
            } @catch (NSException *e) { ACETrace(@"探针挂设异常: %@", e); }
            @try { ACE_install_tel_hooks(); } @catch (NSException *e) { ACETrace(@"[tel] 安装异常: %@", e); }
            g_ace_busy = 0;
            dispatch_after(dispatch_time(0, 1000000000), dispatch_get_main_queue(), ^{ ACE_setup_button(); });
            ACE_knm_tick();   // v8.02
            ACE_blind_tick();   // v8.03
            ACE_install_ui_tracers();   // v8.04
            ACE_install_http_tracers();   // v8.07
            if (g_tgt_base) { const struct mach_header *h804 = ACE_find_target_header(); if (h804) ACE_install_net_tracers(h804); }
            dispatch_after(dispatch_time(0, 1200000000LL), dispatch_get_main_queue(), ^{ ACE_measure_tick(1); });   // v8.05
// v7.44
            dispatch_after(dispatch_time(0, 8000000000LL), dispatch_get_main_queue(), ^{ ACE_post_sec_notif(0); });
            dispatch_after(dispatch_time(0, 9000000000LL), dispatch_get_main_queue(), ^{ ACE_build_panel_direct(0); });
            dispatch_after(dispatch_time(0, 10000000000LL), dispatch_get_main_queue(), ^{ ACE_ui_scan("boot10s"); });
// v7.54
            dispatch_after(dispatch_time(0, 14000000000LL), dispatch_get_main_queue(), ^{ ACE_native_panel_build(0); });
// v7.20
            @try { ACE_start_net_probe(); } @catch (NSException *e) { ACETrace(@"[probe] 启动异常: %@", e); }
        }
    });
}

@end
