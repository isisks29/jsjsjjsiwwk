








#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import <libkern/OSCacheControl.h>

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

#pragma mark - 28 处校验分支（offset + 预期编码，双重校验防误伤）
typedef struct { uint32_t off; uint32_t expect; } Patch;
static const Patch kPatch[] = {
    {0x109068, 0x34006C88},                            // 入口守卫 cbz g1
    {0x109134, 0x54006621},{0x1091D4,0x54006121},{0x109288,0x54005B81},
    {0x1092E0, 0x540058C3},{0x109308,0x54005788},      // Phase1 时间窗
    {0x109374, 0x34005428},{0x10937C,0x340053E8},{0x10938C,0xB400536E}, // 对象字段
    {0x1093E4, 0x540050A1},{0x10941C,0x54004EE1},{0x109458,0x54004D01},
    {0x1094B0, 0x54004A41},{0x109574,0x54004421},
    {0x109804, 0x34002EC8},                            // Phase2 入口守卫
    {0x1098D4, 0x54002841},{0x10996C,0x54002381},{0x109A34,0x54001D41},
    {0x109A94, 0x54001A43},{0x109AA0,0x540019E8},      // Phase2 时间窗
    {0x109B44, 0x340014C8},{0x109B4C,0x34001488},{0x109B5C,0xB4001401}, // 对象字段
    {0x109BA4, 0x540011C1},{0x109BFC,0x54000F01},{0x109C6C,0x54000B81},
    {0x109CD4, 0x54000841},{0x109D48,0x540004A1},
};
static const int kPatchCount = sizeof(kPatch)/sizeof(kPatch[0]);
static const uint32_t kNOP = 0xD503201F;

// 保留（不 NOP）：0x109058(panel已显示标志) / 0x109768(cbz x21 面板对象) / 0x1097fc(cbz x0 构建结果)

static int patch_checks(uintptr_t base) {
    if (!base) { st(@"PATCH: 未定位到 ace 靶场 (base=0)"); return -1; }
    st([NSString stringWithFormat:@"PATCH: base=0x%llx", (unsigned long long)base]);

    uintptr_t lo = base + kPatch[0].off, hi = base + kPatch[0].off;
    for (int i = 1; i < kPatchCount; i++) {
        uintptr_t a = base + kPatch[i].off;
        if (a < lo) lo = a;
        if (a > hi) hi = a;
    }
    vm_size_t pg = vm_page_size;
    vm_address_t p0 = lo & ~(pg - 1);
    vm_address_t p1 = (hi + pg - 1) & ~(pg - 1);

    kern_return_t kr = vm_protect(mach_task_self(), p0, p1 - p0, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        st([NSString stringWithFormat:@"PATCH: vm_protect(W+RX) 失败 err=%d", kr]);
        return -2;
    }

    int done = 0, mismatch = 0;
    for (int i = 0; i < kPatchCount; i++) {
        volatile uint32_t *p = (volatile uint32_t *)(base + kPatch[i].off);
        uint32_t cur = *p;
        if (cur != kPatch[i].expect) {            // 编码不符则跳过（防 slide/版本不对时误伤）
            mismatch++;
            continue;
        }
        *p = kNOP;
        done++;
    }

    sys_icache_invalidate((void *)p0, p1 - p0);
    vm_protect(mach_task_self(), p0, p1 - p0, 0, VM_PROT_READ | VM_PROT_EXECUTE);

    st([NSString stringWithFormat:@"PATCH: 成功 %d/%d 处，编码不符 %d 处", done, kPatchCount, mismatch]);
    return done;
}

#pragma mark - 对象预分配（关键：修掉垃圾指针解引用闪退）
static void setup_object(uintptr_t base) {
    if (!base) return;
    // 目标在 0x109318 / 0x109aac 两处把 [0x3d6ed0] 当指针解引用，文件初值是非零垃圾 → 崩。
    // 写一个预分配的有效内存，让其走"有效对象"路径；对象校验已 NOP，字段值无需精确。
    uint64_t *slot = (uint64_t *)(base + 0x3d6ed0);
    void *obj = calloc(1, 0x1200);
    if (!obj) { st(@"OBJ: calloc 失败"); return; }
    // 尽量贴合目标自初始化的关键字段（原自初始化写 [obj+0]=-1、[obj+0x119a]=magic）
    *(int32_t *)obj = -1;
    *(uint64_t *)((uint8_t *)obj + 0x119a) = 0xC6A4A7935BD1E995ull;
    *slot = (uint64_t)obj;
    st([NSString stringWithFormat:@"OBJ: 0x3d6ed0 <- 0x%llx (预分配 0x1200)", (unsigned long long)obj]);
}

#pragma mark - 三件套 hook（弹窗抑制）
static void (*g_orig_present)(id, SEL, id, BOOL, id);

static void install_popup_hooks(void) {
    // 1) 钥匙串判定入口：+[_0xD5A13E79 passwordForService:account:] 恒返回 @"A"
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
        if (m) method_setImplementation(m, imp_implementationWithBlock(
            ^id(id s, SEL c, id svc, id acct) { return @"A"; }));
        st(@"HOOK: passwordForService -> @\"A\" OK");
    } else st(@"HOOK: 未找到钥匙串类");

    // 2) setupUI 空转
    unsigned n = 0; Class *cs = objc_copyClassList(&n);
    for (unsigned i = 0; i < n; i++) {
        Method m = class_getInstanceMethod(cs[i], sel_registerName("setupUI"));
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s) { }));
    }
    free(cs);
    st(@"HOOK: setupUI 空转 OK");

    // 3) 拦截 UIAlertController
    Method pm = class_getInstanceMethod([UIViewController class],
                                        sel_registerName("presentViewController:animated:completion:"));
    if (pm) {
        g_orig_present = (void (*)(id, SEL, id, BOOL, id))method_getImplementation(pm);
        method_setImplementation(pm, imp_implementationWithBlock(
            ^void(id self, SEL c, id vc, BOOL anim, id comp) {
                if ([vc isKindOfClass:[UIAlertController class]]) {
                    if (comp) { void (^cb)(void) = comp; cb(); }
                    return;
                }
                g_orig_present(self, c, vc, anim, comp);
            }));
        st(@"HOOK: presentViewController 拦截 OK");
    } else st(@"HOOK: 未找到 presentViewController");
}

#pragma mark - 自检条（上屏，可选项）
void ace_show_diag(void) {
    @try {
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                UIWindow *win = nil;
                if (@available(iOS 13.0, *)) {
                    UIWindowScene *sc = (UIWindowScene *)[[[UIApplication sharedApplication].connectedScenes allObjects] firstObject];
                    win = sc.windows.firstObject;
                }
                if (!win) win = [UIApplication sharedApplication].windows.firstObject;
                if (!win) { st(@"DIAG: 无可用 window，跳过上屏"); return; }

                UILabel *lbl = [win viewWithTag:0xACE0];
                if (!lbl) {
                    lbl = [[UILabel alloc] initWithFrame:CGRectMake(8, 80, win.bounds.size.width - 16, 0)];
                    lbl.tag = 0xACE0;
                    lbl.numberOfLines = 0;
                    lbl.font = [UIFont systemFontOfSize:11];
                    lbl.textColor = [UIColor greenColor];
                    lbl.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.65];
                    lbl.textAlignment = NSTextAlignmentLeft;
                    [win addSubview:lbl];
                }
                lbl.text = ace_status();
                [lbl sizeToFit];
                st(@"DIAG: 自检条已上屏");
            } @catch (NSException *e) { NSLog(@"[ACE] DIAG err: %@", e); }
        });
    } @catch (NSException *e) { NSLog(@"[ACE] DIAG dispatch err: %@", e); }
}

#pragma mark - 对外入口
// 返回：>=0 打补丁成功数（期望 28）；-1 未找到靶场；-2 vm_protect 失败
int ace_activate(void) {
    install_popup_hooks();
    uintptr_t base = ace_base();
    setup_object(base);                 // 先修对象指针，再打补丁
    int r = patch_checks(base);
    st([NSString stringWithFormat:@"ACE: 全部完成，补丁=%d，状态串见上", r]);
    return r;
}

// 注入时先装弹窗 hook（不写门卫字、不打代码补丁）
__attribute__((constructor))
static void bypass_init(void) {
    st(@"INIT: dylib 载入");
    install_popup_hooks();
}
