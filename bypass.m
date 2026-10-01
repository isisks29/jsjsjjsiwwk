










#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import <libkern/OSCacheControl.h>

#pragma mark - 前置C函数声明（修复隐式声明报错）
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

#pragma mark - 补丁表
typedef struct { uint32_t off; uint8_t expect[4]; uint8_t repl[4]; } patch_t;

static const patch_t kPatches[] = {
    /* ---- 0x109020 构建函数 Phase1 ---- */
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
    {0x1094b0, {0x41,0x4b,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */
    {0x109574, {0x81,0x46,0x00,0x54}, {0x1f,0x20,0x03,0xd5}}, /* NOP */

    /* ---- 0x109020 Phase2 新增 ---- */
    {0x109804, {0xc8,0x27,0x00,0x34}, {0x1f,0x20,0x03,0xd5}},
    {0x1098d4, {0x41,0x22,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x10996c, {0x81,0x1e,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x109a34, {0x41,0x19,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x109a94, {0x43,0x1a,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x109aa0, {0xe8,0x19,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x109b44, {0x28,0x14,0x00,0x34}, {0x1f,0x20,0x03,0xd5}},
    {0x109b4c, {0xe8,0x13,0x00,0x34}, {0x1f,0x20,0x03,0xd5}},
    {0x109b5c, {0x6e,0x13,0x00,0xb4}, {0x1f,0x20,0x03,0xd5}},
    {0x109ba4, {0xc1,0x11,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x109bfc, {0x01,0x0f,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x109c6c, {0x41,0x0d,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x109cd4, {0x81,0x0b,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},
    {0x109d48, {0xc1,0x08,0x00,0x54}, {0x1f,0x20,0x03,0xd5}},

    /* 原有其余补丁，示例一条，把你完整178条粘贴在这里 */
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
        if (memcmp((void *)p, kPatches[i].expect, 4) != 0) { mismatch++; continue; }
        memcpy((void *)p, kPatches[i].repl, 4);
        done++;
    }
    sys_icache_invalidate((void *)p0, p1 - p0);
    vm_protect(mach_task_self(), p0, p1 - p0, 0, VM_PROT_READ | VM_PROT_EXECUTE);

    st([NSString stringWithFormat:@"PATCH: 成功 %d/%d，编码不符 %d", done, kPatchCount, mismatch]);
    return done;
}

#pragma mark - 对象预分配
static void setup_object(uintptr_t base) {
    if (!base) return;
    uint64_t *slot = (uint64_t *)(base + 0x3d6ed0);
    void *obj = calloc(1, 0x1200);
    if (!obj) { st(@"OBJ: calloc 失败"); return; }
    *(int32_t*)obj = -1;
    *(uint64_t *)((uint8_t*)obj + 0x119a) = 0xC6A4A7935BD1E995ull;
    *slot = (uint64_t)obj;
    st([NSString stringWithFormat:@"OBJ: 0x3d6ed0 <- 0x%llx", (unsigned long long)obj]);
}

#pragma mark - 三件套 hook C IMP
static id hook_passwordForService(id __unsafe_unretained self, SEL _cmd,
                                  id __unsafe_unretained svc, id __unsafe_unretained acct) {
    return @"A";
}

static void hook_setupUI(id __unsafe_unretained self, SEL _cmd) { }

static void (*g_orig_present)(id, SEL, id, BOOL, id);
static void hook_present(id __unsafe_unretained self, SEL _cmd,
                         id __unsafe_unretained vc, BOOL animated,
                         id __unsafe_unretained completion) {
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

#pragma mark - Window 获取
static UIWindow *ace_window(void) {
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        if (@available(iOS 13.0, *)) {
            for (UIScene *sc in app.connectedScenes) {
                if ([sc isKindOfClass:[UIWindowScene class]]) {
                    UIWindowScene *ws = (UIWindowScene *)sc;
                    if (ws.windows.count) return ws.windows.firstObject;
                }
            }
        }
        return nil;
    } @catch(NSException *){}
    return nil;
}

#pragma mark - 自检条、激活按钮
@interface _AceDiagHost : NSObject @end
@implementation _AceDiagHost
- (void)tapActivate {
    ace_activate_and_build();
}
@end
static _AceDiagHost *g_diagHost = nil;

void ace_show_diag(void) {
    @try {
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                UIWindow *win = ace_window();
                if (!win) { st(@"DIAG: 无有效window"); return; }
                UIView *box = [win viewWithTag:0xACE1];
                if (!box) {
                    box = [[UIView alloc] initWithFrame:CGRectMake(8,80,win.bounds.size.width-16,260)];
                    box.tag = 0xACE1;
                    box.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.72];
                    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(8,8,box.bounds.size.width-16,box.bounds.size.height-56)];
                    lbl.tag = 0xACE0;
                    lbl.numberOfLines = 0;
                    lbl.font = [UIFont systemFontOfSize:10];
                    lbl.textColor = [UIColor greenColor];
                    [box addSubview:lbl];

                    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
                    btn.frame = CGRectMake(8, box.bounds.size.height-44, box.bounds.size.width-16,36);
                    btn.backgroundColor = [UIColor systemGreenColor];
                    [btn setTitle:@"点我激活(补丁+写gate+调用0x109020)" forState:UIControlStateNormal];
                    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                    if (!g_diagHost) g_diagHost = [_AceDiagHost new];
                    [btn addTarget:g_diagHost action:@selector(tapActivate) forControlEvents:UIControlEventTouchUpInside];
                    [box addSubview:btn];
                    [win addSubview:box];
                    [win bringSubviewToFront:box];
                }
                UILabel *lbl = [box viewWithTag:0xACE0];
                lbl.text = ace_status();
                st(@"DIAG:自检条已渲染");
            } @catch (NSException *e) { NSLog(@"[ACE] DIAG err:%@",e); }
        });
    } @catch(NSException *e) { NSLog(@"[ACE] dispatch err:%@",e); }
}

void ace_activate_and_build(void) {
    @try {
        st(@"ACT:开始激活流程");
        uintptr_t base = ace_base();
        if (!base) { st(@"ACT:找不到靶场dylib"); return; }
        st([NSString stringWithFormat:@"ACT: base=0x%llx",(unsigned long long)base]);

        //写入gate门卫常量
        *(volatile uint64_t *)(base + 0x3d6ed8) = 0xb75e8052babd72a7ULL;
        *(volatile uint32_t *)(base + 0x3d6ee0) = 0xbb3dc5bfU;
        *(volatile uint32_t *)(base + 0x3d6ee4) = 0x856ac387U;
        *(volatile uint32_t *)(base + 0x3d6ee8) = 0x7863ab97U;
        st(@"ACT:门卫gate已写入");

        install_popup_hooks();
        setup_object(base);
        int r = patch_checks(base);
        st([NSString stringWithFormat:@"ACT:patch返回=%d",r]);

        //主线程调用构建函数
        dispatch_async(dispatch_get_main_queue(),^{
            ((void (*)(void))(base + 0x109020))();
            st(@"ACT:0x109020构建函数执行完毕");
            ace_show_diag();
        });
    } @catch (NSException *e) {
        st([NSString stringWithFormat:@"ACT异常:%@",e]);
    }
    ace_show_diag();
}

static void ace_diag_auto(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{
        for(int i=0;i<120;i++){
            @autoreleasepool {
                if(ace_window()){
                    ace_show_diag();
                    break;
                }
            }
            usleep(500000);
        }
    });
}

int ace_activate(void) {
    install_popup_hooks();
    uintptr_t base = ace_base();
    setup_object(base);
    int r = patch_checks(base);
    st([NSString stringWithFormat:@"ACE对外入口完成，patch=%d",r]);
    return r;
}

__attribute__((constructor))
static void bypass_init(void) {
    st(@"INIT:dylib已载入");
    install_popup_hooks();
    ace_diag_auto();
}
