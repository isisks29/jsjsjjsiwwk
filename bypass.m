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
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

// ══════════════ 第 0 层：隐身（保持不变）══════════════════════════
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

// 判断内存块像不像可打印文本（过滤系统级海量比对噪音）
static BOOL ACELooksText(const void *p, size_t n) {
    if (!p || n < 6) return NO;
    const unsigned char *b = p; int run = 0;
    for (size_t i = 0; i < n && i < 512; i++) {
        unsigned char c = b[i];
        if (c == 0) { if (run >= 6) return YES; run = 0; }
        else if (c >= 0x20 && c < 0x7f) run++;
        else run = 0;
    }
    return run >= 6;
}
static const char *ACE_hex(const unsigned char *d, int n) {
    static char buf[130]; buf[0] = 0;
    int k = 0;
    for (int i = 0; i < n && k < 120; i++) k += sprintf(buf + k, "%02x", d[i]);
    return buf;
}
// 截断对象文本（%@ 不允许带精度，超长截断必须手动做）
static NSString *ACETrimStr(id obj, NSUInteger n) {
    if (!obj) return @"(nil)";
    NSString *s = [obj description];
    if ([s length] > n) s = [s substringToIndex:n];
    return s;
}

// —— 探针 interpose：只记录、原样放行，不改变任何行为 ——
static void ACE_SHA256_wrap(const void *data, CC_LONG len, unsigned char *md) {
    CC_SHA256(data, len, md);
    if (len <= 1024)
        ACETrace(@"SHA256 in(len=%u)[%.256s] digest=%s", len, (const char *)data, ACE_hex(md, 32));
}
static int ACE_memcmp_wrap(const void *a, const void *b, size_t n) {
    int r = memcmp(a, b, n);
    if (n >= 16 && (ACELooksText(a, n) || ACELooksText(b, n)))
        ACETrace(@"memcmp n=%zu A=[%.48s] B=[%.48s] equal=%d", n, (const char *)a, (const char *)b, r == 0);
    return r;
}
static int ACE_strcmp_wrap(const char *a, const char *b) {
    int r = strcmp(a, b);
    if (a && b && (strlen(a) >= 8 || strlen(b) >= 8))
        ACETrace(@"strcmp A=[%.64s] B=[%.64s] eq=%d", a, b, r == 0);
    return r;
}
static int ACE_strncmp_wrap(const char *a, const char *b, size_t n) {
    int r = strncmp(a, b, n);
    if (a && b && n >= 6 && (strlen(a) >= 8 || strlen(b) >= 8))
        ACETrace(@"strncmp n=%zu A=[%.64s] B=[%.64s]", n, a, b);
    return r;
}
static char *ACE_strstr_wrap(const char *hay, const char *needle) {
    char *r = strstr(hay, needle);
    if (needle && hay && strlen(needle) >= 4)
        ACETrace(@"strstr needle=[%.64s] hit=%d hay=[%.96s]", needle, r != NULL, hay);
    return r;
}
static OSStatus ACE_SecItemCopyMatching_wrap(const CFDictionaryRef query, CFTypeRef *result) {
    OSStatus s = SecItemCopyMatching(query, result);
    @autoreleasepool {
        NSString *qd = (__bridge_transfer NSString *)CFCopyDescription((const void *)query);
        ACETrace(@"SecItemCopyMatching status=%d query=%@", (int)s, ACETrimStr(qd, 300));
        if (s == 0 && result && *result) {
            NSString *rd = (__bridge_transfer NSString *)CFCopyDescription(*result);
            ACETrace(@"  -> item=%@", ACETrimStr(rd, 300));
        }
    }
    return s;
}
static FILE *ACE_fopen_wrap(const char *path, const char *mode) {
    FILE *f = fopen(path, mode);
    if (path && strncmp(path, "/System/", 8) && strncmp(path, "/usr/lib", 8))
        ACETrace(@"fopen [%.128s] mode=[%.8s] ok=%d", path, mode ?: "", f != NULL);
    return f;
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
#if ACE_TRACE
ACE_INTERPOSE(ACE_SHA256_wrap,          CC_SHA256)
ACE_INTERPOSE(ACE_memcmp_wrap,          memcmp)
ACE_INTERPOSE(ACE_strcmp_wrap,          strcmp)
ACE_INTERPOSE(ACE_strncmp_wrap,         strncmp)
ACE_INTERPOSE(ACE_strstr_wrap,          strstr)
ACE_INTERPOSE(ACE_SecItemCopyMatching_wrap, SecItemCopyMatching)
ACE_INTERPOSE(ACE_fopen_wrap,           fopen)
#endif

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
    ACETrace(@"Keychain GET svc=%@ acct=%@ -> %@", svc, acct, r ?: @"(nil)");
    return r;
}
static IMP g_pwSet_imp = NULL;
static BOOL ACE_pw_set(id cls, SEL _cmd, id pw, id svc, id acct) {
    BOOL r = ((BOOL (*)(id, SEL, id, id, id))g_pwSet_imp)(cls, _cmd, pw, svc, acct);
    ACETrace(@"Keychain SET svc=%@ acct=%@ pw=%@ ok=%d", svc, acct, ACETrimStr(pw, 64), r);
    return r;
}
static IMP g_start_imp = NULL;
static void ACE_start_loading(id self, SEL _cmd) {
    id (*msgSendReq)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id req = msgSendReq(self, NSSelectorFromString(@"request"));
    ACETrace(@"MITM startLoading req=%@", req);
    ((void (*)(id, SEL))g_start_imp)(self, _cmd);
}
static IMP g_alert_imp = NULL;
static id ACE_alert_init(id cls, SEL _cmd, id title, id msg, NSInteger style) {
    ACETrace(@"UIAlert title=[%@] msg=[%@]", title, msg);
    return ((id (*)(id, SEL, id, id, NSInteger))g_alert_imp)(cls, _cmd, title, msg, style);
}
#endif

+ (void)load {
    dispatch_async(dispatch_get_main_queue(), ^{
#if ACE_TRACE
        @autoreleasepool {
            ACETrace(@"=== 探针启动（隐身层激活中）===");
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
                    ACETrace(@"Alert 探针已挂");
                }
            } @catch (NSException *e) { ACETrace(@"探针挂设异常: %@", e); }
            ACE_setup_button();
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
