
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

// ══════════════ 第 0 层：隐身（对靶场的 dyld/调试探测不可见）══════════════
typedef void (*ACEAddImageFn)(const struct mach_header *mh, intptr_t vmaddr_slide);

static const struct mach_header *ACE_self_header(void) {
    Dl_info info;
    if (dladdr((const void *)&ACE_self_header, &info))
        return (const struct mach_header *)info.dli_fbase;
    return NULL;
}
// 按索引位移把“自己”从镜像编号里抠掉（与落地文件名无关，天然免疫改名）
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
    // 只在我们自己的镜像上报主程序头，不做任何额外查询
    if (mh && mh == ACE_self_header()) g_watch_cb(_dyld_get_image_header(0), slide);
    else g_watch_cb(mh, slide);
}
static void ACE_register_add_image(ACEAddImageFn f) {
    g_watch_cb = f;
    _dyld_register_func_for_add_image(ACE_watch_wrapper);
}
static kern_return_t ACE_task_threads(mach_port_t t, thread_act_array_t *a, mach_msg_type_number_t *c) {
    if (a) *a = NULL; if (c) *c = 0; return KERN_SUCCESS;
}
static kern_return_t ACE_task_set_exception_ports(mach_port_t t, exception_mask_t m,
        exception_handler_t h, exception_behavior_t b, thread_state_flavor_t f) {
    return KERN_SUCCESS;
}
static void ACE_exit(int code) { (void)code; for (;;) sleep(86400); }
static void ACE_abort(void) { for (;;) sleep(86400); }

// ══════════════ 第 0.5 层：观测日志（存内存，悬浮按钮导出）══════════════
static NSMutableArray *g_logbuf = NULL;
static int g_trace_lines = 0;
// 重入闸门：日志自身的 Foundation 调用会再次命中被接管的符号，挡住第二层。
// 绝不能用 __thread——libSystem 初始化最早期访问 TLS 会触发 abort（实测教训）。
static int g_ace_busy = 0;
// 就绪开关：+load 执行前所有探针纯转发、零动作。
static int g_ace_ready = 0;

static void ACETraceLine(NSString *line) {
    if (g_trace_lines > 5000) return; // 总量封顶
    g_trace_lines++;
    @autoreleasepool { NSLog(@"%@", line); }
    @synchronized ([NSMutableArray class]) {
        if (!g_logbuf) g_logbuf = [[NSMutableArray alloc] init];
        [g_logbuf addObject:line];
    }
}
#define ACETrace(fmt, ...) ACETraceLine([NSString stringWithFormat:(@"[ace] " fmt), ##__VA_ARGS__])
static NSString *ACELogDump(void) {
    NSMutableArray *snap = nil;
    @synchronized ([NSMutableArray class]) { snap = [g_logbuf mutableCopy]; }
    if (!snap || ![snap count]) return @"(暂无日志)";
    NSString *head = [NSString stringWithFormat:@"=== ace 日志 · %lu 行 ===\n", (unsigned long)[snap count]];
    return [head stringByAppendingString:[snap componentsJoinedByString:@"\n"]];
}
// 记录闸门：就绪且不重入才记
#define ACE_G(...) do { if (g_ace_ready && !g_ace_busy) { g_ace_busy = 1; @try { ACETrace(__VA_ARGS__); } @catch (NSException *e) {} g_ace_busy = 0; } } while (0)
// 截断对象文本（%@ 不允许带精度）
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

// ══════════════ 第 0.6 层：验卡结果改写（作业主机制）══════════════
// 改写靶场 __la_symbol_ptr 的 _dispatch_async 槽（静态槽位 0x3e84b8，间接符号表实证）。
// 派发时刻识别两个结果 block（invoke=靶场+0xef0c8 / +0xdcf68），把判定 capture
// 改成成功值（+0x38→0 / +0x30→非0）后原样放行。纯数据写，零 .text 修改。
typedef struct {
    uint32_t cmd, cmdsize;
} ACELoadCmdHdr;
typedef struct {
    uint32_t cmd, cmdsize;
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

// 按指令签名识别靶场镜像（文件名无关）；签名不符=版本不同，绝不安装
static int ACE_sig_ok(uintptr_t base) {
    const struct mach_header_64 *h64 = (const struct mach_header_64 *)base;
    if (h64->ncmds == 0 || h64->ncmds > 256) return 0;
    uint64_t textsize = 0;
    ACELoadCmdHdr *c = (ACELoadCmdHdr *)(base + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < h64->ncmds; i++) {
        if (c->cmdsize < 8 || c->cmdsize > 0x100000) return 0;   // 命令流损坏防御
        if (c->cmd == LC_SEGMENT_64) {
            const ACESegCmd64 *s64 = (const ACESegCmd64 *)c;
            if (s64->vmaddr == 0 && s64->vmsize > textsize) textsize = s64->vmsize;
        }
        c = (ACELoadCmdHdr *)((uintptr_t)c + c->cmdsize);
    }
    if (textsize < 0x100000) return 0;   // 防小镜像越界读
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
// 查符号名对应的指针槽（__got=0x6 / __la_symbol_ptr=0x7，走间接符号表）
static void **ACE_find_ptr_slot(const struct mach_header *hdr, const char *want) {
    uintptr_t base = (uintptr_t)hdr;
    const ACESegCmd64 *seg = (const ACESegCmd64 *)(base + sizeof(struct mach_header_64));
    const struct symtab_command *st = NULL;
    const struct dysymtab_command *dy = NULL;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        ACELoadCmdHdr *c = (ACELoadCmdHdr *)seg;
        if (c->cmd == LC_SYMTAB) st = (const struct symtab_command *)c;
        else if (c->cmd == LC_DYSYMTAB) dy = (const struct dysymtab_command *)c;
        seg = (const ACESegCmd64 *)((uintptr_t)c + c->cmdsize);
    }
    if (!st || !dy) return NULL;
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
                    const uint32_t *isyms = (const uint32_t *)(base + dy->indirectsymoff);
                    const ACENlist64 *nl = (const ACENlist64 *)(base + st->symoff);
                    const char *strtab = (const char *)(base + st->stroff);
                    for (size_t j = 0; j < nslots; j++) {
                        uint32_t si = isyms[sec[k].reserved1 + j];
                        if (si & 0xC0000000u) continue;   // INDIRECT_SYMBOL_LOCAL/ABS
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
// 替换体：命中靶场结果 block 就改判定值，然后放行。
// 内部调用 dispatch_async 走【我们自己镜像】的绑定=真 libdispatch，无递归风险。
static void ACE_dispatch_async_hook(dispatch_queue_t q, dispatch_block_t blk) {
    @try {
        if (blk && g_tgt_base) {
            void **hdrp = (void **)(__bridge void *)blk;
            uintptr_t inv = (uintptr_t)hdrp[2];           // block 布局: invoke 在 +16
            if (inv >= g_tgt_base && inv < g_tgt_end) {
                uintptr_t off = inv - g_tgt_base;
                if (off == 0xef0c8ULL) {                   // 弹窗验卡结果: capture+0x38 → 0
                    volatile int32_t *slot = (volatile int32_t *)((uintptr_t)(__bridge void *)blk + 0x38);
                    if (*slot != 0) {
                        ACETrace(@"[hook] 弹窗验卡结果 %d → 0（强制成功路径）", *slot);
                        *slot = 0; g_rw_dialog++;
                    }
                } else if (off == 0xdcf68ULL) {            // 启动复核结果: capture+0x30 → 非0
                    volatile int32_t *slot = (volatile int32_t *)((uintptr_t)(__bridge void *)blk + 0x30);
                    if (*slot == 0) {
ACETrace(@"[hook] 启动复核结果 0 → 1（强制成功路径）");
                        *slot = 1; g_rw_boot++;
                    }
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
                if (s64->vmaddr == 0 && s64->vmsize > 0) { textsize = s64->vmsize; break; }
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
// 只有点在按钮上才拦截触摸，其余位置穿透到下层界面
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
            ACETrace(@"悬浮按钮已显示：点一下=复制全部日志，按住可拖动");
        } @catch (NSException *e) { ACETrace(@"按钮创建失败: %@", e); }
    }
}

// ══════════════ 第 1 层：只读观测探针（钥匙串 + 弹窗，成功证据链）══════════════
@interface ACELicensePatch : NSObject
@end

@implementation ACELicensePatch

static IMP g_pwGet_imp = NULL;
static id ACE_pw_get(id cls, SEL _cmd, id svc, id acct) {
    id r = ((id (*)(id, SEL, id, id))g_pwGet_imp)(cls, _cmd, svc, acct);
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
            ACETrace(@"=== v7.1 启动（隐身层激活中）===");
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
            g_ace_busy = 0;
            // 按钮晚 1 秒再建，避开启动早期最脆弱的阶段
            dispatch_after(dispatch_time(0, 1000000000), dispatch_get_main_queue(), ^{ ACE_setup_button(); });
        }
    });
}

@end
