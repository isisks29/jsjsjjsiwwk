
#define ACE_TRACE          1   // 1=观测探针（本轮用这个）
#define ACE_ENABLE_OBJC_LAYER 0 // 本轮必须为 0：不干扰原始校验流程

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
#import <libkern/OSCacheControl.h>   // sys_icache_invalidate
// csops 是 XNU SPI，不在公开 iOS SDK 头文件里（真机 SDK 云编译需自行声明）
#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS     0
#define CS_OPS_SET_STATUS 1
#endif
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000
#endif
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

// ══════════════ 第 0 层：隐身（按名字过滤模块）════════════════════
typedef void (*ACEAddImageFn)(const struct mach_header *mh, intptr_t vmaddr_slide);

static const struct mach_header *ACE_self_header(void) {
    Dl_info info;
    if (dladdr((const void *)&ACE_self_header, &info))
        return (const struct mach_header *)info.dli_fbase;
    return NULL;
}
// （暂存关键词表，等 gadget 版本再用；本轮不接入任何调用路径）
__attribute__((unused))
static int ACE_stristr(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return hay && !*needle;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i]) {
            char a = p[i], b = needle[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
            i++;
        }
        if (i == nl) return 1;
    }
    return 0;
}
__attribute__((unused))
static int ACE_name_hidden(const char *n) {
    if (!n) return 0;
    static const char *kws[] = { "libacepatch", "bypass", "frida", "cycript", "substrate",
                                 "tweakinject", "liberty", "sileo", "ellekit" };
    for (int k = 0; k < 8; k++)
        if (ACE_stristr(n, kws[k])) return 1;
    return 0;
}
// v3 原样：按索引位移把“自己”从编号里抠掉（与落地文件名无关，天然免疫改名）
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
    // v3 原样：只在我们自己的镜像上报主程序头，不做任何额外查询
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
static void ACE_exit(int code) { for (;;) sleep(86400); }
static void ACE_abort(void) { for (;;) sleep(86400); }

// ══════════════ 第 0.5 层：观测探针（日志存内存）══════════════════
#if ACE_TRACE
static NSMutableArray *g_logbuf = NULL;
static int g_trace_lines = 0;
// 重入闸门：日志自身的 Foundation 调用会再次命中被接管的 strcmp/strstr，挡住第二层。
// 绝不能用 __thread——libSystem 初始化最早期访问 TLS 会触发 _tlvm_bootstrap_error 直接 abort
//（v5.3 崩溃日志实锤）。普通全局变量在该阶段完全安全，代价只是多线程偶发少记一条。
static int g_ace_busy = 0;
// 就绪开关：我们 +load 执行前（Foundation 都还没起来时），所有探针纯转发、零动作。
static int g_ace_ready = 0;

static void ACETraceLine(NSString *line) {
    if (g_trace_lines > 5000) return; // 总量封顶，防噪音撑爆内存
    g_trace_lines++;
    @autoreleasepool { NSLog(@"%@", line); }
    @synchronized ([NSMutableArray class]) {
        if (!g_logbuf) g_logbuf = [[NSMutableArray alloc] init];
        [g_logbuf addObject:line];
    }
}
// 用宏直接拼字面量前缀后走 stringWithFormat:，避免新版 SDK 的 va_list 匹配问题
#define ACETrace(fmt, ...) ACETraceLine([NSString stringWithFormat:(@"[ace] " fmt), ##__VA_ARGS__])
static NSString *ACELogDump(void) {
    NSMutableArray *snap = nil;
    @synchronized ([NSMutableArray class]) { snap = [g_logbuf mutableCopy]; }
    if (!snap || ![snap count]) return @"(暂无日志：探针没记录到任何内容)";
    NSString *head = [NSString stringWithFormat:@"=== ace 探针日志 · %lu 行 ===\n", (unsigned long)[snap count]];
    return [head stringByAppendingString:[snap componentsJoinedByString:@"\n"]];
}
// 供将来的 FridaGadget JS 脚本直写日志（导出符号，JS 用 NativeFunction 调）
__attribute__((visibility("default")))
void ACELogExternal(const char *utf8) {
    if (!g_ace_ready || g_ace_busy) return;
    g_ace_busy = 1;
    @autoreleasepool { ACETraceLine(utf8 ? [NSString stringWithUTF8String:utf8] : @"(null)"); }
    g_ace_busy = 0;
}

// 记录闸门：就绪且不重入才记，记完立刻交还
#define ACE_G(...) do { if (g_ace_ready && !g_ace_busy) { g_ace_busy = 1; @try { ACETrace(__VA_ARGS__); } @catch (NSException *e) {} g_ace_busy = 0; } } while (0)

// 截断对象文本（%@ 不允许带精度，超长截断必须手动做）
static NSString *ACETrimStr(id obj, NSUInteger n) {
    if (!obj) return @"(nil)";
    NSString *s = [obj description];
    if ([s length] > n) s = [s substringToIndex:n];
    return s;
}

#else  // ACE_TRACE=0 时的静默版本
static void ACETraceLine(NSString *line) { (void)line; }
#define ACETrace(fmt, ...) ACETraceLine([NSString stringWithFormat:(@"[ace] " fmt), ##__VA_ARGS__])
#endif // ACE_TRACE

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

// ══════════════ 第 0.6 层：v6.1 定点绕过补丁 ══════════════
// 原理见文件头 v6.0/v6.1 注释（全部实证）。运行期按镜像名找靶场基址，
// 每条补丁先核对 4 字节原指令签名，匹配才写；不匹配只记日志绝不动手。
// 只写 .text 立即数/单指令，不改任何导入符号（避开 v5.4/5.5 自毁触发面）。
#define ACE_FORCE_SUCCESS    1   // 1=主补丁: 结果判定强制成功 (0xef0fc)
#define ACE_FASTFAIL_CONNECT 0   // 1=可选: connect 改 127.0.0.1:1 秒失败 (服务器死时免等超时)

typedef struct { uint32_t off; uint32_t expect; uint32_t patch; const char *what; } ACEPatchEnt;
static const ACEPatchEnt g_ace_patches[] = {
#if ACE_FORCE_SUCCESS
    // ldr w8,[x0,#0x38] (0xB9403808, 文件字节 08 38 40 b9 实锤) → mov w8,#0 (0x52800008)
    { 0xef0fcu, 0xB9403808u, 0x52800008u, "结果判定强制成功(w8=0)" },
#endif
#if ACE_FASTFAIL_CONNECT
    // sockaddr: [sp+0xb00]=0x37250210 (len/family + port BE 0x3725=9527) → port 0x0100(=1)
    { 0xd2884u, 0x72A6E4A8u, 0x72A02008u, "connect 端口 9527→1" },
    // 地址=w1^w2 混淆: w1(0x76284cce)^w2(0xd7b3e6a1)=0x0100007f → w1'=w2^0x0100007f=0xd6b3e6de
    { 0xd288cu, 0x528999C8u, 0x529CDBC8u, "connect IP 低半 4cce→e6de" },
    { 0xd2890u, 0x72AEC508u, 0x72BAD668u, "connect IP 高半 7628→d6b3" },
#endif
};
static uintptr_t ACE_target_base(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "ballsace"))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}
static void ACE_apply_patches(void) {
    uintptr_t base = ACE_target_base();
    if (!base) { ACETrace(@"未找到靶场镜像(名字含 ballsace)，跳过定点补丁"); return; }
    ACETrace(@"靶场基址=%p，定点补丁 %zu 条", (void *)base,
             sizeof(g_ace_patches) / sizeof(g_ace_patches[0]));
    for (size_t k = 0; k < sizeof(g_ace_patches) / sizeof(g_ace_patches[0]); k++) {
        const ACEPatchEnt *p = &g_ace_patches[k];
        volatile uint32_t *slot = (volatile uint32_t *)(base + p->off);
        if (*slot == p->patch) { ACETrace(@"补丁[%s] 已是目标值，跳过", p->what); continue; }
        if (*slot != p->expect) {
            ACETrace(@"补丁[%s] 签名不符: +0x%x 处=0x%08x 期望=0x%08x —— 不动手(靶场版本可能不同)",
                     p->what, p->off, *slot, p->expect);
            continue;
        }
        uintptr_t addr = (uintptr_t)slot;
        vm_prot_t cur = VM_PROT_READ | VM_PROT_EXECUTE;
        mach_port_t objname = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t icnt = VM_REGION_BASIC_INFO_COUNT_64;
        vm_address_t ra = (vm_address_t)addr;
        vm_size_t rsz = 0;
        // 先查当前保护，写完恢复原样，缩小可写窗口（vm_region_64 由 mach/mach.h 保证可见）
        kern_return_t krq = vm_region_64(mach_task_self(), &ra, &rsz, VM_REGION_BASIC_INFO_64,
                                         (vm_region_info_t)&info, &icnt, &objname);
        if (krq == KERN_SUCCESS) cur = info.protection;
        kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)addr, 4, 0,
                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            // 退路：iOS 对已签名镜像 __text 改 RWX 会被 W^X 拒绝(KERN_PROTECTION_FAILURE)。
            // 给进程打上 CS_DEBUGGED 标志(调试态进程允许改写)后重试一次。
            uint32_t flags = 0, mask = 0;
            pid_t pid = getpid();
            if (csops(pid, CS_OPS_STATUS, &flags, 0) == 0) {
                mask = flags | CS_DEBUGGED;
                if (csops(pid, CS_OPS_SET_STATUS, &mask, 0) == 0)
                    kr = vm_protect(mach_task_self(), (vm_address_t)addr, 4, 0,
                                    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
            }
        }
        if (kr != KERN_SUCCESS) { ACETrace(@"补丁[%s] vm_protect 失败 kr=%d", p->what, kr); continue; }
        *slot = p->patch;
        sys_icache_invalidate((void *)addr, 4);
        vm_protect(mach_task_self(), (vm_address_t)addr, 4, 0, cur);   // 恢复原保护(失败也不影响)
        ACETrace(@"补丁[%s] +0x%x: 0x%08x -> 0x%08x 完成", p->what, p->off, p->expect, p->patch);
    }
}

// ══════════════ 第 1 层：授权核心 hook（本轮默认关闭）══════════════
#if ACE_ENABLE_OBJC_LAYER
static IMP ACEReplace(Class cls, SEL sel, IMP newImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (!m) return NULL;
    return method_setImplementation(m, newImp);
}
static BOOL ACEAlwaysYes(id self, SEL _cmd) { return YES; }
static void ACENoop(id self, SEL _cmd, ...) {}
static void ACESetterSwallow(id self, SEL _cmd, ...) {}
#endif

// ══════════════ 屏幕悬浮按钮（仅探针版启用）═══════════════════════
#if ACE_TRACE

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

// 取当前最上面的可用界面来弹提示
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
#endif // ACE_TRACE

@interface ACELicensePatch : NSObject
@end

@implementation ACELicensePatch

// —— 探针用的记录型 hook（只记录+放行）——
#if ACE_TRACE
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
static IMP g_start_imp = NULL;
static void ACE_start_loading(id self, SEL _cmd) {
    id (*msgSendReq)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id req = msgSendReq(self, NSSelectorFromString(@"request"));
    if (g_ace_ready && !g_ace_busy) {
        g_ace_busy = 1;
        ACETrace(@"MITM startLoading req=%@", ACETrimStr(req, 300));
        g_ace_busy = 0;
    }
    ((void (*)(id, SEL))g_start_imp)(self, _cmd);
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
// —— v5.9 关键探针：UIAlertAction 构造点直收 handler block ——
// v5.7/v5.8 实锤：卡密校验不经过 _0x7D3B5E28 的任何 ObjC 方法，广域 ObjC 普查也全空，
// 说明验卡逻辑在「弹窗按钮的 handler block」直链的 C/C++ 函数里。block 的 invoke 指针
// 就在对象头偏移 16 处（isa/flags/reserved 之后），dladdr 换算出靶场镜像内偏移后，
// 直接等于静态文件虚拟地址（dylib 首选地址 0）。日志点名 0xXXXXX 后：
//   python3 ida.py dis 0xXXXXX 80
// 即可看到验卡真身。前面静态已把弹窗构造点收敛到 4 个函数：
//   0xa7860 / 0xa865c / 0xab518 / 0xaeb84（最后一个带输入框=请输入卡密）
struct ACEBlockLiteral {
    Class isa;
    int flags;
    int reserved;
    void *invoke;
    void *descriptor;
};
static IMP g_actionInit_imp = NULL;
static id ACE_action_init(id cls, SEL _cmd, id title, NSInteger style, id handler) {
    if (g_ace_ready && !g_ace_busy && handler) {
        g_ace_busy = 1;
        @try {
#if __has_feature(objc_arc)
            struct ACEBlockLiteral *bl = (__bridge struct ACEBlockLiteral *)handler;
#else
            struct ACEBlockLiteral *bl = (struct ACEBlockLiteral *)(void *)handler;
#endif
            void *inv = bl->invoke;
            Dl_info di; memset(&di, 0, sizeof(di));
            int ok = dladdr(inv, &di);
            unsigned char bytes[64]; memcpy(bytes, inv, 64);
            char hex[3 * 64 + 1]; int hp = 0;
            for (int k = 0; k < 64; k++) hp += sprintf(hex + hp, "%s%02x", (k && k % 4 == 0) ? " " : "", bytes[k]);
            ACETrace(@"Action[%@] style=%ld handler isa=%s flags=0x%x invoke=%p%s%@ fbase=%p -> 靶场内偏移=0x%llx",
                     ACETrimStr(title, 64), (long)style,
                     bl->isa ? class_getName(bl->isa) : "?", bl->flags, inv,
                     ok ? " (" : "", ok ? (di.dli_fname ? di.dli_fname : "?") : "",
                     ok ? (di.dli_fname ? ")" : "") : "", di.dli_fbase,
                     ok ? (unsigned long long)((uintptr_t)inv - (uintptr_t)di.dli_fbase) : 0ULL);
            ACETrace(@"Action[%@] invoke 前64字节: %s", ACETrimStr(title, 64), hex);
        } @catch (NSException *e) {}
        g_ace_busy = 0;
    }
    return ((id (*)(id, SEL, id, NSInteger, id))g_actionInit_imp)(cls, _cmd, title, style, handler);
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

// —— 授权核心 ObjC 探针（v4 已验证 ObjC 换 IMP 可过反篡改检测）——
static IMP g_q4_imp = NULL, g_q5_imp = NULL, g_q17_imp = NULL, g_q19_imp = NULL;
static IMP g_q18_imp = NULL, g_q20_imp = NULL, g_q21_imp = NULL, g_q22_imp = NULL;

// 每次核心方法跑完，把授权对象的当前状态记一行
static void ACE_logState(id self, const char *tag) {
    if (!g_ace_ready || g_ace_busy) return;
    g_ace_busy = 1;
    @autoreleasepool {
        @try {
            static SEL sQ2, sQ13, sQ14, sQ15, sQ1, sQ7;
            if (!sQ2) {
                sQ2  = NSSelectorFromString(@"q2");   sQ13 = NSSelectorFromString(@"q13");
                sQ14 = NSSelectorFromString(@"q14");  sQ15 = NSSelectorFromString(@"q15");
                sQ1  = NSSelectorFromString(@"q1");   sQ7  = NSSelectorFromString(@"q7:");
            }
            BOOL (*getB)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
            double (*getD)(id, SEL) = (double (*)(id, SEL))objc_msgSend;
            long long (*getLL)(id, SEL, id) = (long long (*)(id, SEL, id))objc_msgSend;
            id (*getObj)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            ACETrace(@"%s -> q2=%d q13=%d q14=%.0f q15=%.0f q7:=%lld q1=%@",
                     tag, getB(self, sQ2), getB(self, sQ13), getD(self, sQ14),
                     getD(self, sQ15), getLL(self, sQ7, nil), ACETrimStr(getObj(self, sQ1), 100));
        } @catch (NSException *e) {}
    }
    g_ace_busy = 0;
}
static void ACE_logArg(id o, const char *tag) {
    if (!g_ace_ready || g_ace_busy) return;
    g_ace_busy = 1;
    ACETrace(@"%s 入参=%@", tag, ACETrimStr(o, 200));
    g_ace_busy = 0;
}
static void ACE_q4(id self, SEL _cmd)  { ((void(*)(id,SEL))g_q4_imp)(self,_cmd);  ACE_logState(self, "q4"); }
static void ACE_q5(id self, SEL _cmd)  { ((void(*)(id,SEL))g_q5_imp)(self,_cmd);  ACE_logState(self, "q5"); }
static void ACE_q17(id self, SEL _cmd) { ((void(*)(id,SEL))g_q17_imp)(self,_cmd); ACE_logState(self, "q17"); }
static void ACE_q19(id self, SEL _cmd) { ((void(*)(id,SEL))g_q19_imp)(self,_cmd); ACE_logState(self, "q19"); }
static void ACE_q18(id self, SEL _cmd, id o) { ACE_logArg(o, "q18:"); ((void(*)(id,SEL,id))g_q18_imp)(self,_cmd,o); ACE_logState(self, "q18:"); }
static void ACE_q20(id self, SEL _cmd, id o) { ACE_logArg(o, "q20:"); ((void(*)(id,SEL,id))g_q20_imp)(self,_cmd,o); ACE_logState(self, "q20:"); }
static void ACE_q21(id self, SEL _cmd, id o) { ACE_logArg(o, "q21:"); ((void(*)(id,SEL,id))g_q21_imp)(self,_cmd,o); ACE_logState(self, "q21:"); }
static void ACE_q22(id self, SEL _cmd, id o) { ACE_logArg(o, "q22:"); ((void(*)(id,SEL,id))g_q22_imp)(self,_cmd,o); ACE_logState(self, "q22:"); }

// —— v5.7 全方法普查：按类型编码套通用记录壳，返回值一律原样透传 ——
static BOOL ACE_isSpecial(SEL sel) {
    static const char *sp[] = {"q4","q5","q17","q19","q18:","q20:","q21:","q22:"};
    const char *n = sel_getName(sel);
    for (int k = 0; k < 8; k++) if (!strcmp(n, sp[k])) return YES;
    return NO;
}
static NSMutableArray *g_sweep_hold = NULL;
static void ACE_holdBlock(id obj) { // 壳 block 必须永久持有，否则 IMP 变悬空指针
    if (!g_sweep_hold) g_sweep_hold = [[NSMutableArray alloc] init];
    [g_sweep_hold addObject:obj];
}
static IMP ACE_makeWrap(IMP orig, NSString *sn, const char *enc) {
    // —— 无返回值 ——
    if (!strcmp(enc, "v@:")) {
        void (^b)(id, SEL) = ^(id s, SEL c) {
            ((void (*)(id, SEL))orig)(s, c);
            ACE_G(@"跟踪·%@()", sn);
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "v@:@")) {
        void (^b)(id, SEL, id) = ^(id s, SEL c, id a) {
            ((void (*)(id, SEL, id))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%@)", sn, ACETrimStr(a, 120));
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "v@:c")) {
        void (^b)(id, SEL, char) = ^(id s, SEL c, char a) {
            ((void (*)(id, SEL, char))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%d)", sn, (int)a);
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "v@:i")) {
        void (^b)(id, SEL, int) = ^(id s, SEL c, int a) {
            ((void (*)(id, SEL, int))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%d)", sn, a);
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "v@:q")) {
        void (^b)(id, SEL, long long) = ^(id s, SEL c, long long a) {
            ((void (*)(id, SEL, long long))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%lld)", sn, a);
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "v@:Q")) {
        void (^b)(id, SEL, unsigned long long) = ^(id s, SEL c, unsigned long long a) {
            ((void (*)(id, SEL, unsigned long long))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%llu)", sn, a);
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "v@:d")) {
        void (^b)(id, SEL, double) = ^(id s, SEL c, double a) {
            ((void (*)(id, SEL, double))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%f)", sn, a);
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    // —— 有返回值：原值透传，多记一行 ——
    if (!strcmp(enc, "c@:") || !strcmp(enc, "B@:")) {
        char (^b)(id, SEL) = ^char(id s, SEL c) {
            char r = ((char (*)(id, SEL))orig)(s, c);
            ACE_G(@"跟踪·%@()=%d", sn, (int)r);
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "c@:@") || !strcmp(enc, "B@:@")) {
        char (^b)(id, SEL, id) = ^char(id s, SEL c, id a) {
            char r = ((char (*)(id, SEL, id))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%@)=%d", sn, ACETrimStr(a, 120), (int)r);
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "i@:")) {
        int (^b)(id, SEL) = ^int(id s, SEL c) {
            int r = ((int (*)(id, SEL))orig)(s, c);
            ACE_G(@"跟踪·%@()=%d", sn, r);
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "q@:")) {
        long long (^b)(id, SEL) = ^long long(id s, SEL c) {
            long long r = ((long long (*)(id, SEL))orig)(s, c);
            ACE_G(@"跟踪·%@()=%lld", sn, r);
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "q@:@")) {
        long long (^b)(id, SEL, id) = ^long long(id s, SEL c, id a) {
            long long r = ((long long (*)(id, SEL, id))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%@)=%lld", sn, ACETrimStr(a, 120), r);
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "d@:")) {
        double (^b)(id, SEL) = ^double(id s, SEL c) {
            double r = ((double (*)(id, SEL))orig)(s, c);
            ACE_G(@"跟踪·%@()=%f", sn, r);
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "i@:@")) {
        int (^b)(id, SEL, id) = ^int(id s, SEL c, id a) {
            int r = ((int (*)(id, SEL, id))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%@)=%d", sn, ACETrimStr(a, 120), r);
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "d@:@")) {
        double (^b)(id, SEL, id) = ^double(id s, SEL c, id a) {
            double r = ((double (*)(id, SEL, id))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%@)=%f", sn, ACETrimStr(a, 120), r);
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "@@:")) {
        id (^b)(id, SEL) = ^id(id s, SEL c) {
            id r = ((id (*)(id, SEL))orig)(s, c);
            ACE_G(@"跟踪·%@()=%@", sn, ACETrimStr(r, 120));
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    if (!strcmp(enc, "@@:@")) {
        id (^b)(id, SEL, id) = ^id(id s, SEL c, id a) {
            id r = ((id (*)(id, SEL, id))orig)(s, c, a);
            ACE_G(@"跟踪·%@(%@)=%@", sn, ACETrimStr(a, 120), ACETrimStr(r, 120));
            return r;
        };
        ACE_holdBlock(b); return imp_implementationWithBlock(b);
    }
    return NULL; // 没见过的编码：宁可跳过也不瞎包
}
// v5.7/v5.8 普查：列出授权核心全部方法/成员并套壳。此处日志必须用 ACETrace——
// 普查跑在 +load 保护区（busy=1）里，ACE_G 会被闸门吞掉（v5.7 的坑）。
static void ACE_sweepCore(Class core) {
    Class sup = class_getSuperclass(core);
    ACETrace(@"核心父类: %s", sup ? class_getName(sup) : "?");
    const char *cn = class_getName(core);
    unsigned int ic = 0;
    Ivar *ivs = class_copyIvarList(core, &ic);
    for (unsigned int k = 0; k < ic; k++)
        ACETrace(@"成员 %u/%u: %s [%s]", k + 1, ic, ivar_getName(ivs[k]) ?: "?", ivar_getTypeEncoding(ivs[k]) ?: "?");
    free(ivs);
    unsigned int mc = 0;
    Method *ms = class_copyMethodList(core, &mc);
        int swept = 0, skipped = 0;
    for (unsigned int k = 0; k < mc; k++) {
        SEL sel = method_getName(ms[k]);
        const char *enc = method_getTypeEncoding(ms[k]) ?: "?";
        NSString *sn = NSStringFromSelector(sel);
        ACETrace(@"实例方法 %u/%u: %@ [%s]", k + 1, mc, sn, enc);
        if (ACE_isSpecial(sel)) continue;
        NSString *tag = [NSString stringWithFormat:@"%s·%@", cn, sn];
        IMP imp = ACE_makeWrap(method_getImplementation(ms[k]), tag, enc);
        if (imp) { method_setImplementation(ms[k], imp); swept++; }
        else { skipped++; }
    }
    free(ms);
    unsigned int cmc = 0;
    Method *cms = class_copyMethodList(object_getClass(core), &cmc);
    for (unsigned int k = 0; k < cmc; k++) {
        SEL sel = method_getName(cms[k]);
        const char *enc = method_getTypeEncoding(cms[k]) ?: "?";
        NSString *sn = NSStringFromSelector(sel);
        ACETrace(@"类方法 %u/%u: %@ [%s]", k + 1, cmc, sn, enc);
        NSString *tag = [NSString stringWithFormat:@"类·%@", sn];
        IMP imp = ACE_makeWrap(method_getImplementation(cms[k]), tag, enc);
        if (imp) method_setImplementation(cms[k], imp);
    }
    free(cms);
    ACETrace(@"普查完成: 实例包 %d / 跳过 %d / 类方法 %d", swept, skipped, cmc);
}
// v5.8 广域普查：给一个类里「恰好一个对象参数」的方法（编码 x@:@）套记录壳。
// 收卡密/回调类方法都是这个形状；drawRect:/坐标类参数编码不符自动跳过，不产逐帧噪音。
static int ACE_sweepOneArgMethodsIn(Class c) {
    const char *nm = class_getName(c);
    int w = 0;
    Class targets[2] = { c, object_getClass(c) };
    for (int t = 0; t < 2; t++) {
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(targets[t], &mc);
        for (unsigned int k = 0; k < mc; k++) {
            SEL sel = method_getName(ms[k]);
            const char *enc = method_getTypeEncoding(ms[k]);
            if (!enc || enc[3] != '@' || enc[4] != '\0') continue;   // 只要 "x@:@"
            if (!strchr("vciqB@", enc[0])) continue;                 // 返回值认得清才包
            if (t == 0 && ACE_isSpecial(sel) && strstr(nm, "7D3B5E28")) continue; // 核心 8 个专用壳不叠加
            NSString *tag = [NSString stringWithFormat:@"%s·%@", nm, NSStringFromSelector(sel)];
            IMP imp = ACE_makeWrap(method_getImplementation(ms[k]), tag, enc);
            if (imp) { method_setImplementation(ms[k], imp); w++; }
        }
        free(ms);
    }
    if (w) ACETrace(@"广域: %s 包 %d", nm, w);
    return w;
}
static void ACE_wideSweepClasses(void) {
    unsigned int n = 0;
    Class *list = objc_copyClassList(&n);
    int hit = 0, tot = 0;
    for (unsigned int i = 0; i < n; i++) {
        const char *nm = class_getName(list[i]);
        if (!nm || !strstr(nm, "_0x")) continue;                 // 靶场类全是 _0x 开头
        char *img = class_getImageName(list[i]);                  // 归属镜像确认，避免误包游戏/系统类
        BOOL mine = (img != NULL) && (strstr(img, "ballsace") != NULL);
        free(img);
        if (!mine) continue;
        hit++;
        tot += ACE_sweepOneArgMethodsIn(list[i]);
    }
    free(list);
    ACETrace(@"广域普查完成: 靶场类 %d 个 / 方法共包 %d 个", hit, tot);
}
#endif

+ (void)load {
#if ACE_TRACE
    // 此刻 Foundation 必定已就绪（加载顺序保证），从这一刻起探针开始记录
    g_ace_ready = 1;
#endif
    dispatch_async(dispatch_get_main_queue(), ^{
#if ACE_TRACE
        @autoreleasepool {
            g_ace_busy = 1;
            ACETrace(@"=== 探针启动（隐身层激活中）===");
            @try { ACE_apply_patches(); } @catch (NSException *e) { ACETrace(@"定点补丁异常: %@", e); }
            @try {
                Class kc = NSClassFromString(@"_0xD5A13E79");
                if (kc) {
                    Method m1 = class_getClassMethod(kc, NSSelectorFromString(@"passwordForService:account:"));
                    if (m1) g_pwGet_imp = method_setImplementation(m1, (IMP)ACE_pw_get);
                    Method m2 = class_getClassMethod(kc, NSSelectorFromString(@"setPassword:forService:account:"));
                    if (m2) g_pwSet_imp = method_setImplementation(m2, (IMP)ACE_pw_set);
                    ACETrace(@"SAMKeychain 探针已挂 (get=%p set=%p)", (void*)g_pwGet_imp, (void*)g_pwSet_imp);
                }
                Class mitm = NSClassFromString(@"_0xE4A91C73");
                if (mitm) {
                    Method m3 = class_getInstanceMethod(mitm, NSSelectorFromString(@"startLoading"));
                    if (m3) g_start_imp = method_setImplementation(m3, (IMP)ACE_start_loading);
                    ACETrace(@"MITM 探针已挂");
                }
                Class alert = NSClassFromString(@"UIAlertController");
                if (alert) {
                    Method m4 = class_getClassMethod(alert, NSSelectorFromString(@"alertControllerWithTitle:message:preferredStyle:"));
                    if (m4) g_alert_imp = method_setImplementation(m4, (IMP)ACE_alert_init);
                    Method m5 = class_getInstanceMethod(alert, NSSelectorFromString(@"addAction:"));
                    if (m5) g_addAct_imp = method_setImplementation(m5, (IMP)ACE_addAct);
                    Class act = NSClassFromString(@"UIAlertAction");
                    if (act) {
                        Method m6 = class_getClassMethod(act, NSSelectorFromString(@"actionWithTitle:style:handler:"));
                        if (m6) g_actionInit_imp = method_setImplementation(m6, (IMP)ACE_action_init);
                        ACETrace(@"UIAlertAction 构造探针已挂 %s", g_actionInit_imp ? "✓" : "✗");
                    }
                    ACETrace(@"Alert 探针已挂（含按钮）");
                }
                Class core = NSClassFromString(@"_0x7D3B5E28");
                if (core) {
                    struct { const char *sel; IMP imp; IMP *save; } hs[] = {
                        {"q4",   (IMP)ACE_q4,  &g_q4_imp},  {"q5",   (IMP)ACE_q5,  &g_q5_imp},
                        {"q17",  (IMP)ACE_q17, &g_q17_imp}, {"q19",  (IMP)ACE_q19, &g_q19_imp},
                        {"q18:", (IMP)ACE_q18, &g_q18_imp}, {"q20:", (IMP)ACE_q20, &g_q20_imp},
                        {"q21:", (IMP)ACE_q21, &g_q21_imp}, {"q22:", (IMP)ACE_q22, &g_q22_imp},
                    };
                    int hooked = 0;
                    for (int k = 0; k < 8; k++) {
                        Method m = class_getInstanceMethod(core, NSSelectorFromString([NSString stringWithUTF8String:hs[k].sel]));
                        if (m) { *hs[k].save = method_setImplementation(m, hs[k].imp); hooked++; }
                    }
                    ACETrace(@"授权核心探针已挂 %d/8", hooked);
                    ACE_sweepCore(core);
                } else {
                    ACETrace(@"授权核心类缺失！IPA 内 dylib 与 GitHub 版不一致");
                }
                ACE_wideSweepClasses();
            } @catch (NSException *e) { ACETrace(@"探针挂设异常: %@", e); }
            g_ace_busy = 0;
            // 按钮晚 1 秒再建，避开启动早期最脆弱的阶段
            dispatch_after(dispatch_time(0, 1000000000), dispatch_get_main_queue(), ^{ ACE_setup_button(); });
        }
#endif
#if ACE_ENABLE_OBJC_LAYER
        @try {
            Class core = NSClassFromString(@"_0x7D3B5E28");
            if (!core) return;
            ACEReplace(core, NSSelectorFromString(@"q2"),  (IMP)ACEAlwaysYes);
            ACEReplace(core, NSSelectorFromString(@"q13"), (IMP)ACEAlwaysYes);
            ACEReplace(core, NSSelectorFromString(@"setQ2:"),  (IMP)ACESetterSwallow);
            ACEReplace(core, NSSelectorFromString(@"setQ13:"), (IMP)ACESetterSwallow);
            for (NSString *s in @[@"q5", @"q17", @"q18:", @"q20:", @"q21:", @"q22:"])
                ACEReplace(core, NSSelectorFromString(s), (IMP)ACENoop);
            Class mitm = NSClassFromString(@"_0xE4A91C73");
            if (mitm) [NSURLProtocol unregisterClass:mitm];
            ACETrace(@"完整补丁生效");
        } @catch (NSException *e) { ACETrace(@"补丁异常: %@", e); }
#endif
    });
}

@end
