
            
#define ACE_TRACE 1   // 必须保持 1

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach/mach.h>
#import <mach/mach_time.h>   // v7.23: mach_absolute_time 声明(新SDK不再随 mach.h 带出)
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
#import <sys/socket.h>     // v7.20: 活服务器探针
#import <netinet/in.h>
#import <arpa/inet.h>
#import <errno.h>
#include <libkern/OSCacheControl.h>

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
    const char *nm = _dyld_get_image_name((o >= 0 && i >= (uint32_t)o) ? i + 1 : i);
    // v7.37: 对靶场隐藏 libsystem_pthread —— 其导出树扫描(q4@0x9eaa4, 解密实证
    // 目标="libsystem_pthread"+"/_pthread_create")解析不到真 pthread_create
    // → 缓存[0x3f65a8]永远为空 → 复核线程(entry 0xaeda8)孵化只能走 GOT 桩
    // 0x14fdf4 → 被 ACE_pc_gate 拦截。decoy 不含原子串, strcmp/strstr 都不中。
    if (nm && strstr(nm, "libsystem_pthread")) return "libsystem_pthr_ead.dylib";
    return nm;
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
    g_hit_tsep++;
    return KERN_SUCCESS;
}
static void ACE_exit(int code) { g_hit_exit++; (void)code; for (;;) sleep(86400); }
static void ACE_abort(void) { g_hit_abort++; for (;;) sleep(86400); }

// ══════════════ 第 0.5 层：观测日志（存内存，悬浮按钮导出）══════════════
static NSMutableArray *g_logbuf = NULL;
static int g_trace_lines = 0;
static int g_ace_busy = 0;
static int g_ace_ready = 0;
static int g_livefd = -1;   // v7.29: 写直通日志 fd(ace_log.txt 每行即时落盘)

static void ACETraceLine(NSString *line) {
    if (g_trace_lines > 20000) return; // 总量封顶(v7.11 面包屑需要更大容量)
    g_trace_lines++;
    @autoreleasepool { NSLog(@"%@", line); }
    @synchronized ([NSMutableArray class]) {
        if (!g_logbuf) g_logbuf = [[NSMutableArray alloc] init];
        [g_logbuf addObject:line];
    }
    // v7.29: 写直通——死亡发生在成功后 <1s 内, 心跳每秒落盘来不及, 死前日志(含 q18: 遗言)全靠这个
    if (g_livefd >= 0 && line) {
        const char *u = [line UTF8String];
        if (u) {
            ssize_t w1 = write(g_livefd, u, strlen(u));
            ssize_t w2 = write(g_livefd, "\n", 1);
            (void)w1; (void)w2;
        }
    }
}
// v7.17b: ACETrace 由宏改为函数——彻底避开 ##__VA_ARGS__ 宏展开的解析级联错误
static void ACETrace(NSString *fmt, ...) {
    if (g_trace_lines > 20000) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    ACETraceLine([NSString stringWithFormat:@"[ace] %@", body]);
}
static uintptr_t g_tgt_base, g_tgt_end;      // 前置声明(定义在第 2 段)
static uintptr_t g_self_base;                // 前置声明(定义在第 2 段)
static int g_ace_ready, g_ace_busy;
// ═══ v7.41: _exit interpose（补上未设防暗杀通道）═══
// 导入表实证靶场同时导入 exit / abort / _exit。此前只挂了 exit+abort，
// _exit(9) 是完全裸的：不产崩溃文件、瞬死、无信号——与全部死相吻合。
// 这里挂起并记录 caller 偏移（区分是靶场哪条 kill 分支开的枪）。
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
// ═══ v7.18: 安保线程孵化拦截(pthread_create interpose) ═══
// 实证链: v7.17 burst 死亡瞬间 PC=0xf177c = 安保初始化函数(内含两个 pthread_create:
// 0xf1b64→孵化看门狗线程0xf26cc, 0xf1ea4→孵化校验线程0xf4650); SIGKILL 处决簇
// (0xf8308/0xf83d0, getpid+kill 裸svc)就在校验线程函数体内, 且该函数含 AC 01 协议帧
// 校验(0xf4884 cmp w8,#0xac) → 成功路径孵化校验线程 → 连服务器复核 → 假卡必死。
// 修法: 拦截 pthread_create, 靶场安保线程(入口+0xf26cc/+0xf4650)直接不孵化。
static void ACE_ensure_tgt_base(void);   // v7.19 前置声明(定义在镜像识别段之后)
static int ACE_pthread_create(pthread_t *t, const pthread_attr_t *a,
                              void *(*fn)(void *), void *arg) {
    if (fn) ACE_ensure_tgt_base();   // v7.19: 构造器期孵化也要能拦——基址现场解析
    if (g_tgt_base && fn) {
        uintptr_t e = (uintptr_t)fn;
        if (e >= g_tgt_base && e < g_tgt_end) {
            uintptr_t off = e - g_tgt_base;
            if (off == 0xf26ccULL || off == 0xf4650ULL) {
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
    return pthread_create(t, a, fn, arg);   // interpose 不影响本镜像内部调用, 直达真身
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
ACE_INTERPOSE(ACE__exit,                _exit)   // v7.41: 补暗杀通道


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
static volatile int g_freeze_web = 0;   // v7.47: 直调建面板期间冻结喂值(防跨tick不自洽)
static void ACE_web_tick(void);   // v7.24 前置声明(定义在守护线程段)
// ═══ v7.4: EndTime 补喂 ═══
static void ACE_prime_endtime(void) {
    @try {
        if (!g_tgt_base) return;
                // v7.47: 直调建面板期间冻结喂值——sub_11ffb0 入口门+建后门多次读 S 链,
        // 若喂值线程在读间隙刷新 S, 会读到跨 tick 的不自洽快照 → 门失败。
        if (g_freeze_web) return;
        uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff698);
        if (ctx < 0x100000000ULL) return;
        // v7.21 铁证修正: 0xe411c 无配置分支用 scvtf 把 ctx+0x78 当有符号整数转 double。
        // 之前写 double 位模式 → 被当 ~4.7e18 秒 → NSDate 溢出 → 到期时间空白。
        // 正确: 写整数 Unix 秒, 到期 = now + 3650 天。
        volatile long long *endp = (volatile long long *)(ctx + 0x78);
        long long nowll = (long long)time(NULL);
        long long target = nowll + 3650LL * 86400LL;
        if (*endp < nowll + 86400LL) {
            ACETrace(@"[prime] EndTime(int64) %lld → %lld (now+3650天)", *endp, target);
            *endp = target;
        }
        ACE_web_tick();   // v7.24: 到期值一动, 立刻同步重建封印网(消除 canary 失配窗口)
    } @catch (NSException *e) {}
}

// ═══ v7.4: 自带崩溃现场捕捉器 ═══
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
// v7.5: 崩溃报告同步进剪贴板 + 启动0.3s弹窗
static UIViewController *ACE_topVC(void);   // 前置声明(定义在悬浮按钮段)
static void ACE_report_last_crash(void) {
    @try {
        // v7.29: 最先抢救上次运行的 ace_log.txt(此刻还没被截断), 随后立刻开写直通 fd
        NSString *logp = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ace_log.txt"];
        NSData *ld3 = [NSData dataWithContentsOfFile:logp];
        g_livefd = open(logp.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC | O_APPEND, 0644);
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
                // v7.29: ld3 已在函数开头抢救读取(写直通截断前)
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
            // v7.34: burst 全量 T 行提炼 —— 「全部嫌疑人活动全记录」。
            // T行 = 某线程 PC 当时在靶场 __text 内(300µs 采样的每一瞬间)。旧版只贴尾
            // 6000 字节 = 只见死前 idle; 真凶的活动在更早的拍里。按线程压缩 PC 连续段
            // (同 PC 连续多拍合并 ×N), 整个 6 秒窗口所有靶场活动浓缩成几十行。
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
static volatile long long g_burst_until = 0;   // v7.17: 高精度突发采样截止时间(秒)

static void *ACE_heartbeat(void *arg) {
    (void)arg;
    for (;;) {
        sleep(1);
        @autoreleasepool {
            // v7.29: ace_log.txt 改为 ACETraceLine 写直通, 心跳不再整文件重写
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

// ═══ v7.9/v7.17: 飞行记录器——平时50ms采样; 验卡后6秒内1ms高精度采样(PC+LR直写文件) ═══
typedef kern_return_t (*ACE_tt_fn)(mach_port_t, thread_act_array_t *, mach_msg_type_number_t *);
static ACE_tt_fn ACE_real_task_threads(void);   // v7.15 前置声明(定义在下一段)
// ═══ v7.32: 嫌疑人岗哨表(全部嫌疑人行为一次列进日志) ═══
// 24 个自毁点 + 11 个关键函数入口。采样线程 PC 落在 [入口,+0x60) 即算路过,
// 每线程×每岗哨首见立写直通日志——死没死都能看到"谁、什么时候、路过了哪个现场"。
static const unsigned g_sus_off[] = {
    // 0-23 自毁点(已缴械, 命中 = 有人开枪但打不响)
    0x9f668, 0xa6220, 0xa62b8, 0xa630c, 0xa69d0, 0xa6ae8, 0xae820, 0xc2e34,
    0xefe34, 0xf1738, 0xf1768, 0xf9580, 0xd1818, 0xd183c, 0xf8308, 0xf83d0,
    0x31c14, 0xe61c0, 0xe6224, 0xf2668, 0xefe40, 0xf1744, 0xf1774, 0xf958c,
    // 24-34 关键函数入口(正常路径, 命中 = 检查在跑)
    0xf177c, 0x9de64, 0x9ddec, 0xaeda8, 0xf26cc, 0xf4650,
    0x9f840, 0xae808, 0xc65b0, 0xd27ac, 0xdcf88
};
#define ACE_SUS_N 35
static mach_port_t g_main_th = MACH_PORT_NULL;   // v7.31: 主线程端口(冻结排除用, 声明前移供 recorder 用)
static unsigned char g_sus_seen[96][ACE_SUS_N];
// v7.33: 专职反篡改线程「区域冻结」——它们整条命都在这些区间里, 冻在开枪之前
// (自毁点上冻结太晚: svc 亚微秒完成; 函数体区域有 ms 级窗口, 300µs 采样必中)
//  z0: 复核巨函数入口+时间检测+dispatcher [0xaeda8,0xaf000)
//  z1: 复核巨函数网络客户端+once块 [0xb1e00,0xbc000) (0xaf000-0xb1e00 留缝: 0xafe40 失败计数属验卡路径, 不误伤)
//  z2: 看门狗 [0xf26cc,0xf2900)   z3: 校验线程 [0xf4650,0xf4a00)   z4: kill簇 [0xf82a0,0xf8400)
static unsigned char g_zone_frozen[96];
static int ace_freeze_zone(unsigned long long off) {
    // v7.35: 区域0合并扩至整个巨函数家族 [0xaeda8,0xc7900) —— 实证链:
    //  q4 给线程参数+0x10 写死状态1(0x9ea60) → 调度器 b.eq 0xaf090 →
    //  状态1=遥测上报流水线(设备信息+钥匙串+JSON序列化+哈希+上传, 选择子全解码) →
    //  服务器裁决无真会话 → kill。v7.34 抓到现行: t3d @0xc7740 (LR=0xaee84)。
    //  旧区边界 0xbc000 漏掉了 0xc2e2c kill块/0xc6xxx once块/0xc7740 助手, 全部纳入。
    if (off >= 0xaeda8ULL && off < 0xc7900ULL) return 0;
    if (off >= 0xf26ccULL && off < 0xf2900ULL) return 2;
    if (off >= 0xf4650ULL && off < 0xf4a00ULL) return 3;
    if (off >= 0xf82a0ULL && off < 0xf8400ULL) return 4;
    return -1;
}
static void *ACE_flight_recorder(void *arg) {
    (void)arg;
    mach_port_t self_th = mach_thread_self();   // v7.33: 岗哨冻结时排除采样线程自己
    ACE_tt_fn real_tt = ACE_real_task_threads();
    if (!real_tt) { ACETrace(@"[rec] 真实task_threads解析失败, 线程采样不可用"); return NULL; }
    ACETrace(@"[rec] 采样启动 real_tt=%p", (void *)real_tt);
    int burstfd = -1, was_burst = 0;
    long long burst_bytes = 0;   // v7.27: burst 文件字节计数(6MB 上限)
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
        usleep(burst ? 300 : 50000);   // v7.25: burst 提到 300µs
        if (!g_tgt_base) continue;
        thread_act_array_t list = NULL;
        mach_msg_type_number_t n = 0;
        if (real_tt(mach_task_self(), &list, &n) != KERN_SUCCESS || !list) continue;
        char line[240]; int p = 0;
        memcpy(line, "PC:", 3); p = 3;
        static const char *hd = "0123456789abcdef";
        char blk[4096]; int bq = 0;   // v7.27: burst 全线程块(单次 write, 降扰动)
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
                    // v7.33: 区域冻结——专职反篡改线程踩进危险区立即永久挂起(非主/非采样线程)
                    // v7.35: +桩区LR规则——巨函数每次调 Foundation 都路过桩区(0x14fxxx,
                    // 靶场内), 此刻 LR 必指回巨函数体 → 一生上百次过桩, 采样必中一次。
                    // 只在 PC 位于靶场自身代码/桩区时冻结(不在 malloc/objc 内部冻, 防锁死)。
                    if (i < 96 && !g_zone_frozen[i] && list[i] != g_main_th
                        && list[i] != self_th) {
                        int z = ace_freeze_zone(off);
                        if (z < 0 && off >= 0x14f000ULL && off < 0x150000ULL && lrInT) {
                            unsigned long long lro = lr - g_tgt_base;
                            if (lro >= 0xaeda8ULL && lro < 0xc7900ULL) z = 9;
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

                    // v7.33: 区域冻结——专职反篡改线程踩进危险区立即永久挂起(非主/非采样线程)
                    if (i < 96 && !g_zone_frozen[i] && list[i] != g_main_th
                        && list[i] != self_th) {
                        int z = ace_freeze_zone(off);
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
                // v7.27: burst 期间记录【全部线程】——凶手线程死前多在 libsystem(不在靶场),
                // 旧过滤器把它挡掉了。全线程最后一拍 = 每条线程死前位置, 真凶必现形。
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
        if (burstfd >= 0 && bq > 0 && burst_bytes < 6 * 1024 * 1024) {
            char sm[12]; int sq = 0;
            sm[sq++] = 'S'; sm[sq++] = hd[(sweep >> 4) & 0xf]; sm[sq++] = hd[sweep & 0xf]; sm[sq++] = '\n';
            write(burstfd, sm, (size_t)sq);
            int w1 = (int)write(burstfd, blk, (size_t)bq);
            burst_bytes += sq + (w1 > 0 ? w1 : 0);   // 6MB 上限防写爆
        }
        
        line[p] = 0;
        vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(mach_port_t));
        int hadTarget = (p > 3);
        strcpy(g_ring[g_ring_i], line);
        g_ring_i = (g_ring_i + 1) & 7;
        if (g_ring_n < 8) g_ring_n++;
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
                ACETrace(@"[rec] 首拍命中靶场PC, 指纹落盘已激活");
            }
        }
    }
    return NULL;
}

// ═══ v7.9: EndTime 持续补喂——每50ms把 ctx+0x78 顶回 2100 ═══
static void *ACE_endtime_keeper(void *arg) {
    (void)arg;
    for (;;) {
        usleep(50000);
        @try {
            if (!g_tgt_base) continue;
            uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff698);
            if (ctx < 0x100000000ULL) continue;
            // v7.21: 按 scvtf 整数语义写 int64 Unix 秒
            volatile long long *endp = (volatile long long *)(ctx + 0x78);
            long long nowll = (long long)time(NULL);
            if (*endp < nowll + 86400LL) *endp = nowll + 3650LL * 86400LL;
        } @catch (NSException *e) {}
    }
    return NULL;
}
static void *ACE_clock_keeper(void *arg) {
    (void)arg;
    static int prearmed = 0;   // v7.30
    for (;;) {
        usleep(50000);
        @autoreleasepool { @try {
            if (!g_tgt_base) continue;
            volatile double  *wbase = (volatile double *)(g_tgt_base + 0x3f65a0);
            const volatile uint32_t *tb   = (const volatile uint32_t *)(g_tgt_base + 0x3f65b0);
            const volatile uint64_t *mbase= (const volatile uint64_t *)(g_tgt_base + 0x3f65c8);
            volatile double  *epoch = (volatile double *)(g_tgt_base + 0x3f65d0);
            volatile double  *ovr   = (volatile double *)(g_tgt_base + 0x3f65e0);
                        // ═══ v7.30: once 预武装(抢在靶场中毒初始化块之前) ═══
            // Block A(0xc69a8) 把 epoch[0x3f65d0] 初始化成栈残留的次正规垃圾(~1.7e-314)
            // → 时间跳变线程出生即自检: computed≈开机秒数 vs 墙钟17.8亿 → 差>30s → exit_group(9),
            //   全程微秒级, 50ms 守护来不及修(v7.29 burst: t39 PC=0 未及执行首指令即死, 实证)。
            // dispatch_once token == -1 即"已执行": 抢先预置两个 token 并自写一致基线, 中毒块永不跑。
            if (!prearmed) {
                prearmed = 1;
                volatile uint64_t *tokD8 = (volatile uint64_t *)(g_tgt_base + 0x3f65d8);
                volatile uint64_t *tokB8 = (volatile uint64_t *)(g_tgt_base + 0x3f65b8);
                if (*tokD8 != ~(uint64_t)0) {
                    if (tb[0] == 0 || tb[1] == 0) {
                        mach_timebase_info_data_t ti; mach_timebase_info(&ti);
                        ((volatile uint32_t *)(g_tgt_base + 0x3f65b0))[0] = ti.numer;
                        ((volatile uint32_t *)(g_tgt_base + 0x3f65b0))[1] = ti.denom;
                        *(volatile uint32_t *)(g_tgt_base + 0x3f65f8) = 1;   // block B 同款 flag
                    }
                    uint32_t pn = tb[0], pd = tb[1];
                    uint64_t pabs = mach_absolute_time();
                    uint64_t pms = pd ? ((pabs * (uint64_t)pn) / (uint64_t)pd) / 1000000ULL : 0ULL;
                    *(volatile uint64_t *)(g_tgt_base + 0x3f65c8) = pms;    // mbase=单调毫秒now
                    *(volatile double *)(g_tgt_base + 0x3f65d0) =
                        [[NSDate date] timeIntervalSince1970];               // epoch=墙钟now(一致!)
                    *tokB8 = ~(uint64_t)0;   // 基线就绪后再落 token(数据先于标志)
                    *tokD8 = ~(uint64_t)0;
                }
            }
            if (*ovr != 0.0) *ovr = 0.0;               // v7.28: 锁死主检分支
            double K = *(const double *)(g_tgt_base + 0x3ba280);
            uint64_t abst = mach_absolute_time();
            uint32_t num = tb[0], den = tb[1];
            uint64_t mono_ms = den ? ((abst * (uint64_t)num) / (uint64_t)den) / 1000000ULL : 0ULL;
            double delta = (double)(mono_ms - *mbase); // u64 回绕减法, 与靶场 0xaeeb8-0xaef00 逐项一致
            double computed = (K != 0.0 && isfinite(K)) ? (delta / K) : delta;
            computed += *epoch;
            double wall = [[NSDate date] timeIntervalSince1970];
            double diff = wall - computed;
            if (!(diff < 5.0 && diff > -5.0)) {      // NaN/超差都纠正
                double ne = *epoch + diff;
                *epoch = isfinite(ne) ? ne : wall;   // 毒值兜底
            }
            // wall_base 保鲜: 靶场 q4 正常会自己刷; 只在停滞/未设时代劳
            double wb = *wbase;
            if (!(wb > 0.0) || wall - wb > 15.0 || wall - wb < -30.0) *wbase = wall;
        } @catch (NSException *e) {} }
    }
    return NULL;
}
// ═══ v7.24: 封印网守护(安保初始化 11 道 canary 校验方程的伪造器) ═══
// 实证(0xf1eec-0xf2164): 成功后安保初始化校验一张"封印网":
//   全局链 [0x3ff6a0/a8/ac/b0] = 单调秒种子S的哈希链 + 45000s 新鲜度窗;
//   ctx 绑定: +0x78(到期)^canary(+0x119a)^magic == +0x11a2; +0x8e/+0x92/ctx[0]
//   各与 canary 槽(+0x11aa/+0x11b2/+0x11ba, 经 C>>7/>>13/>>19)绑定; +0x11c2=混合校验和。
// 真流程该网由验卡函数解析服务器成功响应时构建; -404 错误响应 → 网空 →
// 第一道 cbz [0x3ff6a8] → exit_group(9)。守护: 每 20ms 按同款公式解方程回写。
static uint32_t ACE_mix32(uint32_t x) {
    x ^= x >> 15; x *= 0x1f3d6a71u; x ^= x >> 11; x *= 0x8e4b1395u; x ^= x >> 17;
    return x;
}
static void ACE_web_tick(void) {
    @try {
        if (!g_tgt_base) return;
        // v7.37: 真 pthread_create 缓存槽恒清零——q4/q5 孵化复核线程优先走
        // blr [0x3f65a8](导出树解析缓存, 绕过GOT); 清零后 cbz 必落 GOT 桩路径,
        // 与镜像名隐藏(libsystem_pthread)+GOT门神构成三层封锁。
        *(volatile uint64_t *)(g_tgt_base + 0x3f65a8ULL) = 0;
        // ── ① 全局时钟哈希链(时间相关, 持续刷新保证新鲜度窗) ──
        volatile uint32_t *tb = (volatile uint32_t *)(g_tgt_base + 0x3f6b40);
        uint32_t num = tb[0], den = tb[1];
        if (num == 0 || den == 0) {
            mach_timebase_info_data_t ti; mach_timebase_info(&ti);
            num = ti.numer; den = ti.denom;
            tb[0] = num; tb[1] = den;
        }
        uint64_t ns = (uint64_t)mach_absolute_time();
        if (den) ns = ns * num / den;
        uint64_t S = ns / 1000000ULL;             // v7.26: 单调毫秒(靶场时间门魔数=除1e6, 实证)
        uint32_t Slo = (uint32_t)S, Shi = (uint32_t)(S >> 32);
        *(volatile uint64_t *)(g_tgt_base + 0x3ff6a0) = S ^ 0xb75e8052badb72a6ULL;
        uint32_t a8 = ACE_mix32(Slo ^ 0xd18ddb25u);
        *(volatile uint32_t *)(g_tgt_base + 0x3ff6a8) = a8;
        uint32_t t2 = a8 ^ 0x1767cedcu;
        t2 ^= t2 >> 15; t2 *= 0x1f3d6a71u; t2 ^= t2 >> 11; t2 *= 0x8e4b1395u;
        uint32_t ac = Slo ^ (t2 >> 17) ^ t2;
        *(volatile uint32_t *)(g_tgt_base + 0x3ff6ac) = ac;
        uint32_t t3 = ac ^ 0x5d41c293u;
        t3 ^= t3 >> 15; t3 *= 0x1f3d6a71u; t3 ^= t3 >> 11; t3 *= 0x8e4b1395u;
        uint32_t b0 = Shi ^ (t3 >> 17) ^ t3;
        *(volatile uint32_t *)(g_tgt_base + 0x3ff6b0) = b0;
        // ── ①b v7.45: 第二S链(0x3ff680-690) = iconOnClick 的面板门禁 ──
        // 实证: 点悬浮球→第一链canary→45s时间门→ctx eq⑨-⑬→查第二链([0x3ff688]≠0
        // +镜像方程+7分钟窗)→全过才翻转面板可见字节(_0xE4C8719B byte[0]^=1)。
        // 第二链原由复核线程(已被拦)在真验卡成功后写 → 恒0 → 面板永不出。
        // 全靶场读它的只有 iconOnClick(失败=静默return,无kill) → 喂它零风险。
        *(volatile uint64_t *)(g_tgt_base + 0x3ff680) = S ^ 0xb75e8052badb72a6ULL;
        uint32_t a88 = ACE_mix32(((uint32_t)S ^ 0xd18ddb25u) ^ Shi);
        *(volatile uint32_t *)(g_tgt_base + 0x3ff688) = a88;
        uint32_t g2 = a88 ^ 0x1767cedcu;
        g2 ^= g2 >> 15; g2 *= 0x1f3d6a71u; g2 ^= g2 >> 11; g2 *= 0x8e4b1395u;  // pmix
        uint32_t ac8c = Slo ^ (g2 >> 17) ^ g2;
        *(volatile uint32_t *)(g_tgt_base + 0x3ff68c) = ac8c;
        uint32_t h2 = ac8c ^ 0x5d41c293u;
        h2 ^= h2 >> 15; h2 *= 0x1f3d6a71u; h2 ^= h2 >> 11; h2 *= 0x8e4b1395u;  // pmix
        uint32_t b090 = Shi ^ (h2 >> 17) ^ h2;
        *(volatile uint32_t *)(g_tgt_base + 0x3ff690) = b090;
        // ── ② ctx canary 网(时间无关, 每 tick 自洽重建) ──
        uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff698);
        if (ctx < 0x100000000ULL) return;
        volatile long long *endp = (volatile long long *)(ctx + 0x78);
        long long nowll = (long long)time(NULL);
        if (*endp < nowll + 86400LL) *endp = nowll + 3650LL * 86400LL;
        volatile uint32_t *p8e = (volatile uint32_t *)(ctx + 0x8e);
        volatile uint32_t *p92 = (volatile uint32_t *)(ctx + 0x92);
        if (*p8e == 0) *p8e = 0x61636561u;           // 武装标志: 任意非零
        if (*p92 == 0) *p92 = 0x61636562u;
        uint64_t C = *(volatile uint64_t *)(ctx + 0x119a);
        if (C == 0) { C = 0xc6a45bd1a793e995ULL; *(volatile uint64_t *)(ctx + 0x119a) = C; }
        uint64_t E = (uint64_t)*endp;
        uint64_t A = E ^ C ^ 0xa5c3e1f7b6d2489aULL;
        *(volatile uint64_t *)(ctx + 0x11a2) = A;
        uint32_t V8e = *p8e, V92 = *p92;
        // ═══ v7.36 真凶修复: s20/校验和钉死按 C0=0xffffffff 推导 ═══
        // 实证链: eq⑫(0xf2128) 校验 ctx[0]==lo32((C>>19)^(s20^0x5f8a16e3)),
        // 而 ctx[0]=验卡 socket fd(ctx# 监控行实锤: ffffffff→0x61→ffffffff 随
        // 连接开合翻转)。fd 关闭→安保初始化校验在 <20ms 内完成, tick(20ms)追不上,
        // 按瞬时 fd 推导的 s20 在校验时必陈旧 → eq⑫⑬必崩 → 0xf2630 → 主线程
        // svc 自毁(µs级, 一切线程采样抓不到)。两个校验时刻(boot复核/成功后
        // 安保初始化) ctx[0] 恒为 -1 → 按常量 -1 推导, 竞态物理消失。
        uint32_t C0 = 0xffffffffu;
        uint32_t s10 = V8e ^ (uint32_t)(C >> 7)  ^ 0x4a9b5206u;
        uint32_t s18 = V92 ^ (uint32_t)(C >> 13) ^ 0x8c1a73e5u;
        uint32_t s20 = C0  ^ (uint32_t)(C >> 19) ^ 0x5f8a16e3u;
        *(volatile uint32_t *)(ctx + 0x11aa) = s10;
        *(volatile uint32_t *)(ctx + 0x11b2) = s18;
        *(volatile uint32_t *)(ctx + 0x11ba) = s20;
        uint32_t m = (uint32_t)(A >> 32) ^ (uint32_t)A;
        m *= 0x45d9f3b7u; m ^= s10; m *= 0x8e4b1395u; m ^= s18;
        m *= 0x1f3d6a71u; m ^= s20; m ^= m >> 16;
        *(volatile uint32_t *)(ctx + 0x11c2) = m;
    } @catch (NSException *e) {}
}
static void *ACE_web_keeper(void *arg) {
    (void)arg;
    // v7.38: C 重播种哨兵——全 text 共 20 处 getentropy 写 C(ctx+0x119a)。门神拦掉
    // 看门狗/校验线程两个入口重播种后, 游戏功能区仍有 ~17 处可能在游玩中重播种。
    // 1ms 高频盯 C: 一变立即整发 web_tick 重建导数网(A/s10/s18/s20/chk),
    // 把"重播种→方程校验"竞态窗口从 20ms 压到 ~1ms; C 稳定时按 20ms 常规刷新。
    uint64_t lastC = 0;
    int n20 = 0;
    for (;;) {
        usleep(1000);
        @try {
            if (g_tgt_base) {
                uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff698);
                if (ctx >= 0x100000000ULL) {
                    uint64_t Cnow = *(volatile uint64_t *)(ctx + 0x119a);
                    if (Cnow != lastC) {
                    if (lastC != 0)
                            ACETrace(@"[creseed] C: %llx → %llx (谁在重播种?)", lastC, Cnow);
                        lastC = Cnow;
                        ACE_web_tick();   // C 变了(重播种/首建) → 立即重建全部导数
                        n20 = 0;
                        continue;
                    }
                }
            }
            if (++n20 >= 20) { n20 = 0; ACE_web_tick(); }
        } @catch (NSException *e) {}
    }
    return NULL;
}
// ═══ v7.31: 复核线程冷冻器 ═══
// q4 扫描后用「导出树解析的真 pthread_create」孵化 entry=0xaeda8 的复核巨函数线程
// (interpose 拦不到)。该线程: 时间检测(v7.30 已中和) → 裸svc socket/connect 到
// 111.170.155.161:9527 二次复核 → 服务器判无真卡 → dispatcher → exit_group(9)。
// 裸 svc 网络无法 hook, 但线程阻塞在 connect/read 时 PC 停在靶场内 svc 指令
// (0xb1e00-0xb2d00 区间), WAN 往返数百 ms = 大捕获窗口 → 3ms 巡逻,
// 非主线程 PC 命中区间 → thread_suspend 永久冻结(它永远等不到判决)。
// 只冻网络区间: 验卡主流程 d27ac 在 0xdxxxx(区间外)不受影响, 主线程按端口排除。

static int g_freeze_n = 0;
static void *ACE_freezer(void *arg) {
    (void)arg;
    ACE_tt_fn real_tt = ACE_real_task_threads();
    if (!real_tt) return NULL;
    for (;;) {
        usleep(3000);
        @try {
            if (!g_tgt_base) continue;
            uintptr_t lo = g_tgt_base + 0xb1e00ULL, hi = g_tgt_base + 0xb2d00ULL;
            thread_act_array_t list = NULL;
            mach_msg_type_number_t n = 0;
            if (real_tt(mach_task_self(), &list, &n) != KERN_SUCCESS || !list) continue;
            for (unsigned i = 0; i < n; i++) {
                if (list[i] == g_main_th) continue;
                unsigned long long stt[34];
                memset(stt, 0, sizeof(stt));
                mach_msg_type_number_t c = 68;
                if (thread_get_state(list[i], ACE_ARM64_STATE, (thread_state_t)stt, &c) == 0 && c >= 66) {
                    uintptr_t pc = (uintptr_t)stt[32];
                    if (pc >= lo && pc < hi) {
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
static void *ACE_ctx_monitor(void *arg);   // v7.13 前置声明(定义在下方)

static void ACE_install_v79_threads(void) {
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &at, ACE_flight_recorder, NULL);
    // v7.24: endtime keeper 并入 web tick(单写者, 消除竞态)
    pthread_create(&th, &at, ACE_web_keeper, NULL);      // v7.24: 封印网守护
    pthread_create(&th, &at, ACE_clock_keeper, NULL);   // v7.23: 时钟一致性守护
    pthread_create(&th, &at, ACE_freezer, NULL);         // v7.31: 复核线程冷冻器
    pthread_create(&th, &at, ACE_ctx_monitor, NULL);
    
    pthread_attr_destroy(&at);
    ACETrace(@"v7.9 飞行记录器+EndTime守护已启动");
}
// ═══ v7.14: 硬件断点哨兵——16 个裸 svc 处决点全部下 CPU 硬件断点 ═══
// 原理: ARM debug 寄存器(DBGBCR/DBGBVR)经 thread_set_state 设置, 不写靶场一个字节。
// 命中 → EXC_BREAKPOINT → 异常层记录 PC+LR(凶手与调用者) 并跳过 svc+brk(枪打不响)。
// 靶场的断点扫描器(0x545f8)靠 task_threads 枚举线程, 已被隐身层致盲。
typedef struct { unsigned long long bvr[16], bcr[16], wvr[16], wcr[16]; } ACEDbgState64;
#define ACE_ARM_DEBUG64 15
static const unsigned long long g_kill_sites[16] = {
    0x9f668ULL, 0xa6220ULL, 0xa62b8ULL, 0xa630cULL, 0xa69d0ULL, 0xa6ae8ULL,
    0xae820ULL, 0xc2e34ULL, 0xefe40ULL, 0xf1744ULL, 0xf1768ULL, 0xf1774ULL,
    0xf958cULL, 0xf8308ULL, 0xf831cULL, 0xf83d0ULL };
static int g_bp_logged = 0;
// v7.15: dlsym 会被 dyld interpose 折回自家空壳(实证), 改为直接解析
// libsystem_kernel 镜像的符号表拿裸指针——interpose 只改绑定表, 不改真身。
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
            if (lc->cmd == 0x2 /*LC_SYMTAB*/) { st = (const struct symtab_command *)p; break; }
            p += lc->cmdsize;
        }
        if (!st) continue;
        uintptr_t le_va = 0; uint64_t le_off = 0;
        p = (uintptr_t)mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const ACESegCmd64 *sg = (const ACESegCmd64 *)p;
            if (sg->cmd == 0x19 /*LC_SEGMENT_64*/ && !strcmp(sg->segname, "__LINKEDIT")) {
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
        for (uint32_t k = 0; k < st->nsyms; k++) {
            uint32_t so = syms[k].n_strx;
            if (so == 0 || so >= st->strsize) continue;
            const char *snm = strs + so;
            if (snm[0] == '_') snm++;
            if (!strcmp(snm, "task_threads") && syms[k].n_value) {
                ACE_tt_fn f = (ACE_tt_fn)(uintptr_t)(syms[k].n_value + slide);
                if (f != (ACE_tt_fn)&ACE_task_threads) {
                    ACETrace(@"[bp] 真实task_threads=%p (符号表解析)", (void *)f);
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
                ds.bcr[k] = 0x7ULL;   // E=1, PMC=EL0/EL1, 非链接地址匹配
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
// ═══ v7.13: ctx 关键字段监视器——20ms 采样, 只记录变化 ═══
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
// ═══ v7.39: 方程活体快照仪 ═══
// q4 钩子入口(靶场0xf1ed8)与 canary 方程校验(0xf1ef0-0xf2164)背靠背执行,
// 在 q4 入口按靶场公式(0xf20a0-0xf2164 反汇编逐条对照)求值全部 13 条方程,
// 哪条 FAIL 哪条就是死刑判决——终结"猜方程"时代。写直通, 死也带得走。
static uint32_t ACE_pmix32(uint32_t x) {   // 无尾部 >>17 折叠的 partial_mix(eq3/4 用)
    x ^= x >> 15; x *= 0x1f3d6a71u; x ^= x >> 11; x *= 0x8e4b1395u;
    return x;
}
static void ACE_eq_snapshot(const char *tag) {
    @try {
        if (!g_tgt_base) return;
        uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff698);
        if (ctx < 0x100000000ULL) { ACETrace(@"[eq@%s] ctx未就绪", tag); return; }
        uint64_t S = *(volatile uint64_t *)(g_tgt_base + 0x3ff6a0) ^ 0xb75e8052badb72a6ULL;
        uint32_t a8 = *(volatile uint32_t *)(g_tgt_base + 0x3ff6a8);
        uint32_t ac = *(volatile uint32_t *)(g_tgt_base + 0x3ff6ac);
        uint32_t b0 = *(volatile uint32_t *)(g_tgt_base + 0x3ff6b0);
        uint32_t Slo = (uint32_t)S, Shi = (uint32_t)(S >> 32);
        uint32_t e2 = ACE_mix32(Slo ^ 0xd18ddb25u);
        uint32_t G  = ACE_pmix32(a8 ^ 0x1767cedcu);
        uint32_t e3 = (Slo ^ (G >> 17)) ^ G;
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
    // v7.39: q4 入口 = canary 方程区前一毫米 → 全方程活体快照(判决书)
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
// v7.19: 提前解析靶场基址(pthread_create 拦截在构造器期就要工作, 等不到 install_result_hook)
static int g_ensure_tried = 0;
static void ACE_ensure_tgt_base(void) {
    if (g_tgt_base) return;
    if (g_ensure_tried > 200) return;   // 找不到就别每次 pthread_create 都全量扫描
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
// v7.3: symoff/stroff/indirectsymoff 是文件偏移, 必须按段表换算成运行时地址
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
                        if (si >= st->nsyms) continue;
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
                // v7.40: 加 caller 偏移——区分 q4 两次派发(0x9ee1c/0x9f21c, invoke 都可能是 9f6a0 系)
                uintptr_t ra0 = (uintptr_t)__builtin_return_address(0);
                unsigned long coff = (g_tgt_base && ra0 >= g_tgt_base && ra0 < g_tgt_end)
                                     ? (unsigned long)(ra0 - g_tgt_base) : 0UL;
                ACETrace(@"[disp] +0x%lx caller=+0x%lx", (unsigned long)off, coff);   // v7.11 面包屑: 死前最后几行=凶手
                if (off == 0xef0c8ULL) {                   // 弹窗验卡结果: capture+0x38 → 0
                    volatile int32_t *slot = (volatile int32_t *)((uintptr_t)(__bridge void *)blk + 0x38);
                    if (*slot != 0) {
                        ACETrace(@"[hook] 弹窗验卡结果 %d → 0（强制成功路径）", *slot);
                        *slot = 0; g_rw_dialog++;
                    }
                    g_burst_until = (long long)time(NULL) + 6;   // v7.17: 触发6秒高精度采样
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
// ═══ v7.32: 全员缴械——20 处自毁点全部改哑弹 ═══
// 分类实证(text.bin 全量 106 个 svc):
//  - movz x0,#9 + movz x16,#1 + svc = exit(9), 12 处静态
//  - x16=#0x25(kill) 2 处; 动态 x16 10 处(0x31c14/0xe61c0/0xe6224/0xf2668:
//    x0=状态×9 dispatcher 形态; 0xefe34/0xf1738/0xf1768/0xf9580: x16 从 TLS+0x148
//    读且 x1=#9 双保险形态; 0xd1818/0xd183c: x16=0+1=exit(1))——全部自毁
//  - #0x1f4=getentropy/#6=close/#4=write/#3=read/#0x61=socket/#0x62=connect 良性, 不动
// 每处 svc 后必跟 brk#1 或 movz x0,#9(第二道保险)。补丁: svc→movz x0,#0(假装退出
// 码返回), 后一条→ret(安全检查失败路径变成正常返回)。进程从此打不死。
// 若 vm_protect 失败(签名不允许改 .text) → 日志报 fail=24, 换静态重打包方案。
// ═══ v7.41: 裸 svc 自毁点缴械（正确落点版，非 v7.32 的盲目 ret）═══
// 全部 24 处 kill = 裸 svc #0x80 系统调用(exit/kill)，interpose 拦不住。
// v7.32 曾用 svc→movz x0,#0; ret 盲改，但反汇编实证多数 kill 在【函数中部】，
// 裸 ret 不恢复 sp/x29/x30 → 栈损坏换姿势崩；且 brk+4 常落进下一函数序言或
// __Unwind_Resume。本版落点全部经 capstone 逐字节核验:
//   · 23 处 → b 跳到所在函数【真 epilogue】(ldp/add sp→ret, 帧完整恢复)
//   · 1 处(0xae820 纯 die 桩, 全函数无返回路径) → 原地合成 ldp x29,x30,[sp],#0x10; ret
// 写通道: vm_write(Dobby 同款, 靶场导入表实证本进程代码页可写)。vm_write 被拒
// 则回退 vm_protect(+VM_PROT_COPY 强制 COW 私有副本, 非 v7.32 的 RWX)直写再恢复 RX。
// 每点写前验原指令==svc、写后回读校验, 全失败则日志报 kr0(需转静态重打包)。
static int ACE_write_code(uintptr_t at, const uint32_t *words, unsigned n) {
    mach_msg_type_number_t len = n * 4;
    kern_return_t kr = vm_write(mach_task_self(), (vm_address_t)at,
                                (vm_offset_t)(uintptr_t)words, len);
    if (kr == KERN_SUCCESS) return 0;
    // 回退: vm_protect + VM_PROT_COPY 造可写私有副本 → 直写 → 恢复 RX
    vm_address_t page = (vm_address_t)at & ~(vm_address_t)0x3FFF;
    kern_return_t kp = vm_protect(mach_task_self(), page, 0x4000, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kp != KERN_SUCCESS) return (int)kr;   // 报第一次(vm_write)的 kr
    volatile uint32_t *p = (volatile uint32_t *)at;
    for (unsigned i = 0; i < n; i++) p[i] = words[i];
    vm_protect(mach_task_self(), page, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    return 0;
}
static int ACE_disarm_kills(void) {
    // 23 处: kill偏移 → b epilogue (capstone 已验证编码)
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
        if (*p != SVC) { mism++; continue; }          // 非svc=偏移漂移, 绝不动
        uint32_t w = kpatch[i];
        int r = ACE_write_code(at, &w, 1);
        if (r && !hkr) { kr0 = r; hkr = 1; }
        if (*p != w) { fail++; continue; }            // 回读校验
        sys_icache_invalidate((void *)at, 4);
        ok++;
    }
    // 特殊: 0xae820 纯 die 桩(sub_ae808 无返回路径) → 合成 ldp x29,x30,[sp],#0x10; ret
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
// ═══ v7.37: 复核线程孵化门神 ═══
// 靶场 GOT pthread_create 槽 = base+0x3e87c8 (实证: 孵化桩 0x14fdf4 =
// adrp 0x3e8000 + ldr #0x7c8 + br x16; 同法实证 dispatch_async 槽 0x3e84b8
// 与已改写槽一致, 模型交叉验证)。间接符号表被混淆(radr://), 只能按偏移定位。
// entry==靶场+0xaeda8(复核巨函数) → 拦下假成功; 其余放行(看门狗/校验线程
// 已实证 ctx[0]<0 良性退出, 放行避免行为漂移)。
typedef int (*ACE_pc_fn)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static ACE_pc_fn g_real_pc = NULL;
static int ACE_pc_gate(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *), void *arg) {
    // v7.39: 全量记录每次调用(v7.38 疑点: 序言两个孵化没出现在 gate——要么没走
    // 这个槽, 要么日志被 busy 吞。全记录+去busy闸门, 一次看清)。ASCII 标签防乱码。
    if (g_tgt_base && fn) {
        uintptr_t e = (uintptr_t)fn;
        if (e >= g_tgt_base && e < g_tgt_end) {
            unsigned long off = (unsigned long)(e - g_tgt_base);
            if (off == 0xaeda8UL || off == 0xf26ccUL || off == 0xf4650UL) {
                if (t) *t = (pthread_t)0;
                ACETrace(@"[gate] BLOCK entry=+0x%lx %s", off,
                         off == 0xaeda8UL ? "reval" : (off == 0xf26ccUL ? "watchdog" : "verifier"));
                return 0;
            }
            ACETrace(@"[gate] pass entry=+0x%lx", off);
        } else {
            ACETrace(@"[gate] pass external fn=%p", fn);
        }
    }
    return g_real_pc(t, a, fn, arg);
}
// ═══ v7.40: 通知中心探针 ═══
// 排除法终局: 方程区实测13/13全过(q4入口快照) + 复核线程已拦 + 看门狗/校验零活动
// → 主线程死亡路径只剩安保初始化尾段: defaultCenter → VM解密通知名 →
// postNotificationName:object:(0xf25c0)。observer 在 post 内部【同步】执行
// (游戏/靶场回调)——若 observer 查 config(ctx+0x1196=0, 我们没有真卡配置)后开枪,
// 死亡位置/时序/零日志/零采样痕迹全部吻合。探针在调原实现【之前】落写直通日志:
// 若死在 observer 里, 日志将停在 [notif] post [通知名] caller=+0xf25xx —— 名字+凶手同框。
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
// v7.41: 走廊二分器 —— defaultCenter 在安保初始化尾段(0xf216c)被调, 位置在
// canary 方程区【之后】、postNotification(0xf25c0)【之前】。据 [nc] 行是否出现二分:
//   出现 = 方程区已过, 死亡在 VM解密通知名/postNotification 段;
//   不出现 = 死亡在 q4 epilogue/方程区(0xf1ef0-0xf2164)内。
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
// ═══ v7.44: 观察者注册探针 + 安保通知补发（面板激活链）═══
// 靶场唯一 UI 创建观察者由 sub_11fa5c 注册, invoke=sub_11ffb0=建 UIView 加
// keyWindow(左上角按钮/面板)。它等的通知由安保init尾段 0xf25c0 发出——安保init
// 已被空操作(v7.43) → 通知没人发 → 面板不出。修法: 挂注册API现场捕获通知名,
// 「授权成功」后补发。sub_11ffb0 幂等+内部svc均为getentropy(良性), 补发安全。
#define ACE_OBS_MAX 8
static NSString *g_obs_names[ACE_OBS_MAX];
static int g_obs_n = 0;
static void ACE_obs_capture(NSString *name, const char *api, uintptr_t ra) {
    if (!name || ![name isKindOfClass:[NSString class]]) return;
    @synchronized ([NSMutableArray class]) {
        for (int i = 0; i < g_obs_n; i++)
            if ([g_obs_names[i] isEqualToString:name]) return;
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
            ACETrace(@"[notif-post] 尝试%d: 代发[%@] (激活UI创建链, 观察者幂等)", attempt, names[i]);
            [c postNotificationName:names[i] object:nil];
        }
    } @catch (NSException *e) { ACETrace(@"[notif-post] 异常: %@", e); }
}
// ═══ v7.47: 直调观察者block建面板 + 全门禁诊断 ═══
static void ACE_build_panel_direct(int attempt) {
    @try {
        if (!g_tgt_base) return;
        volatile uint8_t *flag = (volatile uint8_t *)(g_tgt_base + 0x3fc348ULL);
        if (*flag & 1) {
            if (attempt == 1) ACETrace(@"[panel] 幂等标志已置位=面板早已构建, 盲点左上角即可");
            return;
        }
        uintptr_t blk = g_tgt_base + 0x3e9358ULL;
        void (*inv)(id) = (void (*)(id))*(uintptr_t *)(blk + 0x10);
        if (!inv) { ACETrace(@"[panel] 尝试%d: invoke指针为空", attempt); return; }
        // ① 门禁全评估(13方程+时间门, 1=FAIL)
        ACE_eq_snapshot("panel");
        // ② 窗口状态
        @try {
            UIApplication *app = [UIApplication sharedApplication];
            UIWindow *kw = app.keyWindow;
            ACETrace(@"[panel] 尝试%d 窗口: keyWindow=%p windows数=%lu",
                     attempt, (__bridge void *)kw, (unsigned long)[app.windows count]);
        } @catch (NSException *e) {}
        // ③ 冻结喂值 → 直调 → 解冻
        g_freeze_web = 1;
        ACE_web_tick();          // 冻结前最后喂一次, 保证 S 链新鲜且自洽
        usleep(2000);            // 让在途的 web_keeper tick 落地
        if (attempt == 1)
            ACETrace(@"[panel] 尝试%d: 冻结喂值, 直调观察者invoke=%p", attempt, (void *)inv);
        inv(nil);
        g_freeze_web = 0;
        if (*flag & 1)
            ACETrace(@"[panel] ★尝试%d: 面板构建完成! 盲点左上角出面板", attempt);
        else
            ACETrace(@"[panel] 尝试%d: invoke返回但标志未置位(门禁失败, 看[eq@panel]哪条=1)", attempt);
    } @catch (NSException *e) { ACETrace(@"[panel] 异常: %@", e); }
}

static void ACE_schedule_sec_posts(void) {
    dispatch_after(dispatch_time(0, 1000000000LL), dispatch_get_main_queue(), ^{ ACE_post_sec_notif(1); ACE_build_panel_direct(1); });
    dispatch_after(dispatch_time(0, 3000000000LL), dispatch_get_main_queue(), ^{ ACE_post_sec_notif(2); ACE_build_panel_direct(2); });
    dispatch_after(dispatch_time(0, 6000000000LL), dispatch_get_main_queue(), ^{ ACE_post_sec_notif(3); ACE_build_panel_direct(3); });

}
static void ACE_install_notif_probe(void) {
    @try {
        Method m = class_getInstanceMethod([NSNotificationCenter class],
                                           @selector(postNotificationName:object:));
        if (m) g_orig_post2 = (void (*)(id, SEL, NSString *, id))
            method_setImplementation(m, (IMP)ACE_post2);
        // v7.41: defaultCenter 类方法探针(走廊二分)
        Method mdc = class_getClassMethod([NSNotificationCenter class],
                                          @selector(defaultCenter));
        // v7.44: 两个观察者注册API探针(捕获靶场等的通知名, 供补发)
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
// ═══ v7.45: 悬浮球探针 + UI 盘点扫描 ═══
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
        if (st && g_ace_ready && !g_ace_busy) {
            g_ace_busy = 1;
            ACETrace(@"[ball] 门禁结果: 面板标志byte[0]=%d (1=面板应已显示, 0=被静默拒绝)",
                     *(volatile uint8_t *)st);
            g_ace_busy = 0;
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
static void ACE_ui_scan(const char *when) {
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
// ═══ v7.43: 安保init block劫持空操作 ═══
// 死亡链实锤: 输卡密→sub_d27ac真连服务器→TEST123得-404真失败→失败处理器sub_dcf88
// →弹错误UIAlert(completion=安保init block@0x3e9230)→用户点掉→安保init(0xf177c)跑
// →canary区9决策点→dispatcher(0xf2630)→svc exit_group(0xf2668)裸自毁。
// 安保init是全局block, invoke指针存可写__DATA(0x3e9240)。改它=改__DATA一个指针
// (与已成功的dispatch_async槽/pthread_create槽同类, 不碰代码页, iOS18合规)。
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
    uint64_t textsize = 0x3e8000;
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
    // v7.41: 重新启用运行时缴械 —— v7.32 崩溃是【工具用错】(vm_protect 加 RWX 后
    // 直写 file-backed RX 页 → EXC_BAD_ACCESS)。本版改 vm_write(Dobby 同款内核写,
    // 返回 kr 不崩) + vm_protect(+VM_PROT_COPY 造 COW 私有副本)兜底, 落点全部经
    // capstone 核验跳到真 epilogue(帧完整)。全拒才日志 kr0, 不会 v7.32 式闪退。
    // ACE_disarm_kills();   // v7.42: iOS18代码签名监视器封死运行时改码, 永久停用
    g_saved_slot_val = *slot;

    *slot = (void *)ACE_dispatch_async_hook;
    ACETrace(@"结果hook 已安装: 靶场基址=%p __TEXT=0x%llx 槽=%p 原值=%p → %p",
             (void *)base, (unsigned long long)textsize, slot, g_saved_slot_val,
             (void *)ACE_dispatch_async_hook);
             // v7.37: pthread_create GOT 槽改写(偏移实证锚死; dladdr 验证原值确在
    // libsystem_pthread 内才改写, 不符只记日志不动手)
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
        // ═══ v7.43 核心: 劫持安保init block invoke指针(__DATA 0x3e9240) ═══
    // block@0x3e9230 invoke字段=0x3e9240, 运行时(dyld rebase后)=base+0xf177c。
    // 全靶场仅此1处被dispatch(失败处理器弹窗completion), 安保init无其他指针引用,
    // ctx已由验卡函数先calloc → 换空操作安全。写前校验现值防偏移漂移。
    {
        volatile uintptr_t *sinv = (volatile uintptr_t *)(base + 0x3e9240ULL);
        uintptr_t cur = *sinv;
        uintptr_t expect = base + 0xf177cULL;
        if (cur == expect || cur == 0xf177cULL) {
            *sinv = (uintptr_t)(void *)ACE_secinit_noop;
            ACETrace(@"[secinit] 安保init invoke槽已劫持: 0x%lx → %p (自毁触发链掐断)",
                     (unsigned long)cur, (void *)ACE_secinit_noop);
        } else {
            ACETrace(@"[secinit] 槽值0x%lx≠base+0xf177c(0x%lx), 未改(疑偏移漂移)",
                     (unsigned long)cur, (unsigned long)expect);
        }
    }
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

// ══════════════ 第 1 层：只读观测探针（钥匙串 + 弹窗）══════════════
@interface ACELicensePatch : NSObject
@end

@implementation ACELicensePatch

static IMP g_pwGet_imp = NULL;
// v7.7: 假 UDID 注入(identitytoken.v4 读取点只判 length!=0, 无校验)
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
// ══════════════ v7.20 采集器 A: 全量 ctx dump ══════════════
static void ACE_dump_ctx_full(NSString *tag) {
    @try {
        if (!g_tgt_base) { ACETrace(@"[dump] %s: g_tgt_base 未就绪", tag.UTF8String); return; }
        uintptr_t ctx = *(uintptr_t *)(g_tgt_base + 0x3ff698);
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

// ══════════════ v7.20 采集器 B: 活服务器探针 ══════════════
static const char *ACE_SRV_IP = "111.170.155.161";   // 静态解码自 d27ac connect sockaddr
static uint16_t    ACE_SRV_PORT = 9527;
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
        NSString *t = [title isKindOfClass:[NSString class]] ? title : @"";
        NSString *m = [msg isKindOfClass:[NSString class]] ? msg : @"";
        if ([t containsString:@"授权"] || [t containsString:@"到期"] ||
            [m containsString:@"到期"] || [m containsString:@"激活"]) {
            ACE_dump_ctx_full(@"成功弹窗");
        }
        // v7.44: 「授权成功」= 验卡终点, 替空操作的安保init补发通知激活面板UI
        if ([t containsString:@"授权成功"] || [t containsString:@"激活成功"]) {
            ACE_schedule_sec_posts();
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
            g_main_th = mach_thread_self();   // v7.31: 冷冻器排除主线程用
            ACETrace(@"=== v7.47 启动（+门禁诊断+冻结喂值直调建面板）===");
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
                ACE_install_notif_probe();   // v7.40: 通知中心探针(安保尾段传感器)
                ACE_install_ball_probe();    // v7.45: 悬浮球探针(iconOnClick/touches)
            } @catch (NSException *e) { ACETrace(@"探针挂设异常: %@", e); }
            @try { ACE_install_tel_hooks(); } @catch (NSException *e) { ACETrace(@"[tel] 安装异常: %@", e); }
            g_ace_busy = 0;
            dispatch_after(dispatch_time(0, 1000000000), dispatch_get_main_queue(), ^{ ACE_setup_button(); });
            dispatch_after(dispatch_time(0, 8000000000LL), dispatch_get_main_queue(), ^{ ACE_post_sec_notif(0); });
            dispatch_after(dispatch_time(0, 9000000000LL), dispatch_get_main_queue(), ^{ ACE_build_panel_direct(0); });
            
            dispatch_after(dispatch_time(0, 10000000000LL), dispatch_get_main_queue(), ^{ ACE_ui_scan("boot10s"); });
            @try { ACE_start_net_probe(); } @catch (NSException *e) { ACETrace(@"[probe] 启动异常: %@", e); }
        }
    });
}

@end
