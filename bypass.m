










#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import <libkern/OSCacheControl.h>

#pragma mark - 前置函数声明 【修复隐式声明报错】
void ace_activate_and_build(void);
void ace_show_diag(void);

#pragma mark - 自检条状态
static NSMutableString *g_status = nil;
static void st(NSString *line) {
    if (!g_status) g_status = [NSMutableString string];
    [g_status appendFormat:@"%@\n", line];
    NSLog(@"[ACE] %@", line);
}
NSString *ace_status(void) { return g_status ? [g_status copy] : @""; }

#pragma mark - 靶场定位（构建函数 prologue 指纹）
static uintptr_t ace_base(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h) continue;
        uintptr_t base = (uintptr_t)h;
        uint32_t p0 = *(volatile uint32_t *)(base + 0x109020);
        uint32_t p1 = *(volatile uint32_t *)(base + 0x109134);
        if (p0 == 0xD10543FF && p1 == 0x54006621) return base;
    }
    return 0;
}

#pragma mark - 补丁表（你的综合表 + 新增 Phase2）
typedef struct { uint32_t off; uint8_t expect[4]; uint8_t repl[4]; } patch_t;

static const patch_t kPatches[] = {
    /* ---- 0x109020 构建函数 Phase1（你的表原有） ---- */
    {0x109068, {0x88,0x6c,0x00,0x34}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109134, {0x21,0x66,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x1091d4, {0x21,0x61,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109288, {0x81,0x5b,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x1092e0, {0xc3,0x58,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109308, {0x88,0x57,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109374, {0x28,0x54,0x00,0x34}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x10937c, {0xe8,0x53,0x00,0x34}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x10938c, {0x6e,0x53,0x00,0xb4}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x1093e4, {0xa1,0x50,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x10941c, {0xe1,0x4e,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109458, {0x01,0x4d,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x1094b0, {0x41,0x4a,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109574, {0x21,0x44,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */

    /* ---- 0x109020 构建函数 Phase2（v3 新增，让面板真正走到 addSubview） ---- */
    {0x109804, {0xc8,0x2e,0x00,0x34}, {0x1f,0x20,0x03,0xd5}}, /* NOP 入口守卫 */
    {0x1098d4, {0x41,0x28,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x10996c, {0x81,0x23,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109a34, {0x41,0x1d,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109a94, {0x43,0x1a,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP 时间窗 */
    {0x109aa0, {0xe8,0x19,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP 时间窗 */
    {0x109b44, {0xc8,0x14,0x00,0x34}, {0x1f,0x20,0x03,0xd5}}, /* NOP 对象字段 */
    {0x109b4c, {0x88,0x14,0x00,0x34}, {0x1f,0x20,0x03,0xd5}}, /* NOP 对象字段 */
    {0x109b5c, {0x01,0x14,0x00,0xb4}, {0x1f,0x20,0x03,0xd5}}, /* NOP 对象字段 */
    {0x109ba4, {0xc1,0x11,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109bfc, {0x01,0x0f,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109c6c, {0x81,0x0b,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109cd4, {0x41,0x08,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109d48, {0xa1,0x04,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */

    /* ---- 以下为你的综合表原样保留（其余函数防篡改） ---- */
    {0x4e38, {0x88,0x0a,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x4ea4, {0x29,0x07,0x00,0x34}, {0x1f,0x20,0x03,0xd5}},
    {0x4eac, {0xe9,0x06,0x00,0x34}, {0x1f,0x20,0x03,0xd5}},
    {0x4ebc, {0x6e,0x06,0x00,0xb4}, {0x1f,0x20,0x03,0xd5}},
    {0x4ee4, {0x21,0x05,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x4f0c, {0xe1,0x03,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x4f2c, {0xe1,0x02,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x4f4c, {0xe1,0x01,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0xfadbc, {0xe8,0x13,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0xfae28, {0x89,0x10,0x00,0x34}, {0x1f,0x20,0x03,0xd5}},
    {0xfae30, {0x49,0x10,0x00,0x34}, {0x1f,0x20,0x03,0xd5}},
    {0xfae40, {0xce,0x0f,0x00,0xb4}, {0x1f,0x20,0x03,0xd5}},
    {0xfae68, {0x61,0x0e,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0xfae90, {0x21,0x0d,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0xfaeb0, {0x21,0x0c,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0xfaed0, {0x21,0x0b,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0xfaf08, {0x61,0x09,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0xfaf18, {0xe8,0x08,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0xfaf3c, {0x23,0x07,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x10b020, {0x48,0x06,0x00,0x34}, {0x1f,0x20,0x03,0xd5}},
    {0x10b08c, {0xa9,0x03,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x10b094, {0x69,0x02,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x10b0a4, {0xee,0x02,0x00,0xb4}, {0x1f,0x20,0x03,0xd5}},
    {0x10b0cc, {0x21,0x01,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x10b0f4, {0xe1,0x00,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x10b114, {0xe1,0xff,0xff,0x53}, {0x1f,0x20,0x03,0xd5}},
    {0x10b134, {0xe1,0xfe,0xff,0x53}, {0x1f,0x20,0x03,0xd5}},
    {0x10b198, {0x88,0x0a,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    /* 0x4f84: b.eq 0x4fd8 -> b 0x4fd8 (强制走已激活路径) */
    {0x4f84, {0xa0,0x02,0x00,0x54}, {0x04,0x00,0x00,0x14}},
};
static const int kPatchCount = sizeof(kPatches)/sizeof(kPatches[0]);

static int patch_checks(uintptr_t base) {
    if (!base) { st(@"PATCH: 未定位到 ace 靶场 (base=0)"); return -1; }
    st([NSString stringWithFormat:@"PATCH: base=0x%llx", (unsigned long long)base]);

    uintptr_t lo = base + kPatches[0].off, hi = base + kPatches[0].off;
    for (int i = 1; i < kPatchCount; i++) {
        uintptr_t a = base + kPatches[i].off;
        if (a < lo) lo = a;
        if (a > hi) hi = a;
    }
    vm_size_t pg = vm_page_size;
    vm_address_t p0 = lo & ~(pg - 1);
    vm_address_t p1 = (hi + pg - 1) & ~(pg - 1);

    kern_return_t kr = vm_protect(mach_task_self(), p0, p1 - p0, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) { st([NSString stringWithFormat:@"PATCH: vm_protect 失败 err=%d", kr]); return -2; }

    int done = 0, mismatch = 0;
    for (int i = 0; i < kPatchCount; i++) {
        volatile uint8_t *p = (volatile uint8_t *)(base + kPatches[i].off);
        // 预期编码校验，防 slide/版本不对时误伤
        if (memcmp((void *)p, kPatches[i].expect, 4) != 0) { mismatch++; continue; }
        memcpy((void *)p, kPatches[i].repl, 4);
        done++;
    }
    sys_icache_invalidate((void *)p0, p1 - p0);
    vm_protect(mach_task_self(), p0, p1 - p0, 0, VM_PROT_READ | VM_PROT_EXECUTE);

    st([NSString stringWithFormat:@"PATCH: 成功 %d/%d，编码不符 %d", done, kPatchCount, mismatch]);
    return done;
}

#pragma mark - 对象预分配（Phase2 走通后 0x3d6ed0 会被解引用，必须有效）
static void setup_object(uintptr_t base) {
    if (!base) return;
    uint64_t *slot = (uint64_t *)(base + 0x3d6ed0);
    void *obj = calloc(1, 0x1200);
    if (!obj) { st(@"OBJ: calloc 失败"); return; }
    *(int32_t *)obj = -1;                                   // 贴合原自初始化 [obj+0]=-1
    *(uint64_t *)((uint8_t *)obj + 0x119a) = 0xC6A4A7935BD1E995ull; // magic
    *slot = (uint64_t)obj;
    st([NSString stringWithFormat:@"OBJ: 0x3d6ed0 <- 0x%llx", (unsigned long long)obj]);
}

#pragma mark - 三件套 hook（弹窗抑制，全部用 C 函数 IMP，避免 block 的 ARC retain 崩溃）
// 崩溃根因（crash log）：imp_implementationWithBlock 的 block 被当 IMP 时，
// ARC 会对参数做 objc_retain，而目标是 present 一个垃圾 vc(0x1) → objc_retain_x19 崩。
// C 函数 IMP 不会产生这类 retain；并对无效 vc 直接跳过，全程不崩。

// 1) 钥匙串判定入口：+[_0xD5A13E79 passwordForService:account:] 恒返回 @"A"
static id hook_passwordForService(id __unsafe_unretained self, SEL _cmd,
                                  id __unsafe_unretained svc, id __unsafe_unretained acct) {
    return @"A";
}

// 2) setupUI 空转
static void hook_setupUI(id __unsafe_unretained self, SEL _cmd) { }

// 3) presentViewController 拦截（UIAlertController 吞掉，其余转发；无效 vc 跳过）
static void (*g_orig_present)(id, SEL, id, BOOL, id);
static void hook_present(id __unsafe_unretained self, SEL _cmd,
                         id __unsafe_unretained vc, BOOL animated,
                         id __unsafe_unretained completion) {
    // 垃圾/空指针 vc：直接忽略，避免对无效指针发消息或转发导致崩
    if ((uintptr_t)vc < 0x1000) { return; }
    @try {
        if ([(NSObject *)vc isKindOfClass:[UIAlertController class]]) {
            if (completion) { void (^cb)(void) = completion; cb(); }
            return;
        }
    } @catch (NSException *e) { NSLog(@"[ACE] present catch: %@", e); }
    if (g_orig_present) g_orig_present(self, _cmd, vc, animated, completion);
}

static void install_popup_hooks(void) {
    Class keychain = NSClassFromString(@"_0xD5A13E79");
    if (!keychain) {
        unsigned n = 0; Class *cs = objc_copyClassList(&n);
        for (unsigned i = 0; i < n; i++)
            if (class_getClassMethod(cs[i], sel_registerName("passwordForService:account:")))
            { keychain = cs[i]; break; }
        free(cs);
    }
    if (keychain) {
        Method m = class_getClassMethod(keychain, sel_registerName("passwordForService:account:"));
        if (m) method_setImplementation(m, (IMP)hook_passwordForService);
        st(@"HOOK: passwordForService -> @\"A\" OK");
    } else st(@"HOOK: 未找到钥匙串类");

    unsigned n = 0; Class *cs = objc_copyClassList(&n);
    for (unsigned i = 0; i < n; i++) {
        Method m = class_getInstanceMethod(cs[i], sel_registerName("setupUI"));
        if (m) method_setImplementation(m, (IMP)hook_setupUI);
    }
    free(cs);
    st(@"HOOK: setupUI 空转 OK");

    Method pm = class_getInstanceMethod([UIViewController class],
                                        sel_registerName("presentViewController:animated:completion:"));
    if (pm) {
        g_orig_present = (void (*)(id, SEL, id, BOOL, id))method_getImplementation(pm);
        method_setImplementation(pm, (IMP)hook_present);
        st(@"HOOK: presentViewController 拦截 OK");
    } else st(@"HOOK: 未找到 presentViewController");
}

#pragma mark - 自检条 + 激活按钮（自动上屏，无需手动调用、不依赖日志）
static UIWindow *ace_window(void) {
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        if (@available(iOS 13.0, *)) {
            NSArray *scenes = app.connectedScenes.allObjects;
            for (id sc in scenes) {
                if ([sc isKindOfClass:[UIWindowScene class]]) {
                    NSArray<UIWindow *> *ws = ((UIWindowScene *)sc).windows;
                    if (ws.count > 0) {
                        return ws.firstObject;
                    }
                }
            }
        }
        // 旧iOS兜底，抑制废弃警告
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (app.windows.count > 0) return app.windows.firstObject;
        if (app.keyWindow) return app.keyWindow;
#pragma clang diagnostic pop
    } @catch (NSException *e) { }
    return nil;
}

@interface _AceDiagHost : NSObject @end
@implementation _AceDiagHost
- (void)tapActivate { ace_activate_and_build(); }
@end
static _AceDiagHost *g_diagHost = nil;

// 激活 + 构建（点按钮触发：写门卫字 → hook/对象/补丁 → 调 0x109020）
void ace_activate_and_build(void) {
    @try {
        st(@"ACT: 开始");
        uintptr_t base = ace_base();
        if (!base) { st(@"ACT: 未定位 ace 靶场"); return; }
        st([NSString stringWithFormat:@"ACT: base=0x%llx", (unsigned long long)base]);

        // 写门卫字（gate 区 0x3d6ed8..0x3d6ee8），让校验异或差=0
        *(volatile uint64_t *)(base + 0x3d6ed8) = 0xb75e8052babd72a7ULL;
        *(volatile uint32_t *)(base + 0x3d6ee0) = 0xbb3dc5bf;
        *(volatile uint32_t *)(base + 0x3d6ee4) = 0x856ac387;
        *(volatile uint32_t *)(base + 0x3d6ee8) = 0x7863ab97;
        st(@"ACT: 门卫字已写 (0x3d6ed8..0x3d6ee8)");

        install_popup_hooks();          // 弹窗三件套
        setup_object(base);             // 对象预分配（0x3d6ed0）
        int r = patch_checks(base);     // 全部补丁
        st([NSString stringWithFormat:@"ACT: 补丁=%d", r]);

        // 调面板构建函数（主线程，addSubview 需要）
        ((void (*)(void))(base + 0x109020))();
        st(@"ACT: 0x109020 调用完成");
    } @catch (NSException *e) {
        st([NSString stringWithFormat:@"ACT 异常: %@", e]);
    }
    ace_show_diag();   // 刷新自检条
}

void ace_show_diag(void) {
    @try {
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                UIWindow *win = ace_window();
                if (!win) { st(@"DIAG: 无 window"); return; }
                UIView *box = [win viewWithTag:0xACE1];
                if (!box) {
                    box = [[UIView alloc] initWithFrame:CGRectMake(8, 100, win.bounds.size.width - 16, 260)];
                    box.tag = 0xACE1;
                    box.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.72];
                    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(8, 8, box.bounds.size.width - 16, box.bounds.size.height - 56)];
                    lbl.tag = 0xACE0; lbl.numberOfLines = 0;
                    lbl.font = [UIFont systemFontOfSize:10];
                    lbl.textColor = [UIColor greenColor];
                    [box addSubview:lbl];
                    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
                    btn.frame = CGRectMake(8, box.bounds.size.height - 44, box.bounds.size.width - 16, 36);
                    btn.backgroundColor = [UIColor greenColor];
                    [btn setTitle:@"激活 (ace_activate + 0x109020)" forState:UIControlStateNormal];
                    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                    if (!g_diagHost) g_diagHost = [_AceDiagHost new];
                    [btn addTarget:g_diagHost action:@selector(tapActivate)
                          forControlEvents:UIControlEventTouchUpInside];
                    [box addSubview:btn];
                    [win addSubview:box];
                    [win bringSubviewToFront:box];
                }
                UILabel *lbl = [box viewWithTag:0xACE0];
                lbl.text = ace_status();
                st(@"DIAG: 自检条已上屏");
            } @catch (NSException *e) { NSLog(@"[ACE] DIAG err: %@", e); }
        });
    } @catch (NSException *e) { NSLog(@"[ACE] DIAG dispatch err: %@", e); }
}

// constructor 里自动启动：后台轮询等 UI 就绪，拿到 window 即上屏自检条
static void ace_diag_auto(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        for (int i = 0; i < 120; i++) {   // 最多等 60s
            @autoreleasepool {
                if (ace_window()) { ace_show_diag(); break; }
            }
            usleep(500000);
        }
    });
}

#pragma mark - 对外入口
int ace_activate(void) {
    install_popup_hooks();
    uintptr_t base = ace_base();
    setup_object(base);
    int r = patch_checks(base);
    st([NSString stringWithFormat:@"ACE: 全部完成，补丁=%d", r]);
    return r;
}

__attribute__((constructor))
static void bypass_init(void) {
    st(@"INIT: dylib 载入");
    install_popup_hooks();
    ace_diag_auto();   // 自动等 window 上屏自检条（含激活按钮）
}
