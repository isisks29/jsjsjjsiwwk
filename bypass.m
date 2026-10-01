#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <mach/mach.h>

// ================= 目标常量（文件 vmaddr） =================
static const uintptr_t kBuildFnFile     = 0x109020;
static const uintptr_t kSessionBaseFile = 0x3ff000;
static const uintptr_t kOffVerifyResult = 0x658;
static const uintptr_t kOffSessionObj   = 0x698;

#define GATE0 0xb75e8052babd72a7ULL
#define W20 0x8e4b1395u
#define W21 0x1f3d6a71u
#define W22 0xd18ddb25u
#define W24 0x1767cedcu
#define W25 0x5d41c293u

static const uintptr_t kGateBaseFile = 0x3f7000;
static const uintptr_t kOffGate0 = 0x568;
static const uintptr_t kOffG1    = 0x6a4;
static const uintptr_t kOffG2    = 0x6c0;
static const uintptr_t kOffG3    = 0x6fc;
static const uintptr_t kOffObjPtr= 0x258;

// ================= 运行时基址 =================
static uintptr_t g_targetBase = 0;

static uintptr_t findTargetBase(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name, "ace") || strstr(name, "ballsace")))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}
static inline void *va(uintptr_t f) { return (void *)(g_targetBase + f); }
static inline void w64(uintptr_t f, uint64_t v) { *(volatile uint64_t *)va(f) = v; }
static inline void w32(uintptr_t f, uint32_t v) { *(volatile uint32_t *)va(f) = v; }
static inline uint64_t r64(uintptr_t f) { return *(volatile uint64_t *)va(f); }
static inline uint32_t r32(uintptr_t f) { return *(volatile uint32_t *)va(f); }

// ================= 1) 抑制卡密弹窗（三件套） =================
static id hookPassword(id self, SEL _cmd, id svc, id acct) { return @"A"; }
static void hookSetup(id self, SEL _cmd) {}
static IMP g_origPresent = NULL;
static void hookPresent(id self, SEL _cmd, UIViewController *vc, BOOL anim, void (^comp)(void)) {
    if ([vc isKindOfClass:[UIAlertController class]]) { if (comp) comp(); return; }
    ((void (*)(id, SEL, UIViewController *, BOOL, void (^)(void)))g_origPresent)(self, _cmd, vc, anim, comp);
}
static void installHooks(void) {
    Class kc = objc_getClass("_0xD5A13E79");
    Method mp = kc ? class_getClassMethod(kc, sel_registerName("passwordForService:account:")) : NULL;
    if (mp) method_setImplementation(mp, (IMP)hookPassword);

    Method ms = NULL;
    Class pop = objc_getClass("_0x6D1C8F45");
    if (pop) ms = class_getInstanceMethod(pop, sel_registerName("setupUI"));
    if (ms) method_setImplementation(ms, (IMP)hookSetup);   // 吞面板时注释此行

    g_origPresent = class_getMethodImplementation([UIViewController class],
        sel_registerName("presentViewController:animated:completion:"));
    if (g_origPresent)
        method_setImplementation(class_getInstanceMethod([UIViewController class],
            sel_registerName("presentViewController:animated:completion:")), (IMP)hookPresent);
}

// ================= 2) 门卫块哈希链（照抄反汇编） =================
static void writeGateBlock(uintptr_t base, uint64_t seed) {
    uint64_t x26 = seed ^ GATE0;
    uint32_t w8 = (uint32_t)(x26 >> 32), w26 = (uint32_t)x26;
    uint32_t w11 = (w26 ^ W22) ^ w8;
    w11 ^= w11>>15; w11 *= W21; w11 ^= w11>>11; w11 *= W20; w11 ^= w11>>17;
    w32(base+0x08, w11);
    uint32_t w9 = w11 ^ W24;
    w9 ^= w9>>15; w9 *= W21; w9 ^= w9>>11; w9 *= W20;
    w9 = ((uint32_t)x26 ^ (w9>>17)) ^ w9;
    w32(base+0x0c, w9);
    uint32_t w10 = w9 ^ W25;
    w10 ^= w10>>15; w10 *= W21; w10 ^= w10>>11; w10 *= W20;
    w8 = w8 ^ (w10>>17) ^ w10;
    w32(base+0x10, w8);
}
static void* buildSessionObj(void) {
    void *obj = calloc(1, 0x1200);
    uint64_t b0 = 0x123456789abcdef0ULL, b8 = 0xfedcba9876543210ULL;
    uint32_t b16 = 0x11223344, b24 = 0x55667788, b32 = 0x99aabbcc;
    uint64_t *buf = (uint64_t *)((uintptr_t)obj + 0x119a);
    buf[0]=b0; buf[1]=b8; buf[2]=b16; buf[3]=b24; buf[4]=b32;
    uint32_t w = ((uint32_t)(b8>>32) ^ (uint32_t)b8);
    w *= 0x45d9f3b7u; w ^= b16; w *= W20; w ^= b24; w *= W21; w ^= b32; w ^= w>>16;
    buf[5]=w;
    *(volatile uint32_t*)((uintptr_t)obj + 0x0)  = ((uint32_t)(b0>>0x13)) ^ (b32 ^ 0x5f8a16e3u);
    *(volatile uint64_t*)((uintptr_t)obj + 0x78) = (b0 ^ b8) ^ 0xa5c3e1f7b6d2489aULL;
    *(volatile uint32_t*)((uintptr_t)obj + 0x8e) = ((uint32_t)(b0>>7)) ^ (b16 ^ 0x4a9b5206u);
    *(volatile uint32_t*)((uintptr_t)obj + 0x92) = ((uint32_t)(b0>>0xd)) ^ (b24 ^ 0x8c1a73e5u);
    return obj;
}
static void armFull(void) {
    if (!g_targetBase) return;
    @try {
        uintptr_t g = kSessionBaseFile;
        w64(g+0x6a0, GATE0); writeGateBlock(g+0x6a0, GATE0);
        w64(g+0x680, GATE0); writeGateBlock(g+0x680, GATE0);
        w32(0x3fb000+0x98c, 0);
        w32(0x3fb000+0x990, 1);
        w32(0x3fb000+0x998, 0);
        void *obj = buildSessionObj();
        w64(g+0x698, (uintptr_t)obj);
        NSLog(@"[ARM] armed obj=%p", obj);
    } @catch (NSException *e) { NSLog(@"[ARM] exc: %@", e); }
}

// ================= 3) 主动调用构建函数 =================
typedef void (*buildFn)(void);
static void callBuild(void) {
    if (!g_targetBase) return;
    buildFn fn = (buildFn)va(kBuildFnFile);
    if (fn) fn();
}

// ================= 4) 悬浮球 + Metal/ImGui 菜单探针 =================
static UIButton *ball = nil;
static volatile int g_menuFlips = 0;
typedef void *(*msgGetter)(id, SEL);

@interface BallTarget : NSObject
@property(nonatomic,strong) UILabel *bar;
@end
@implementation BallTarget
// 在视图树中找 Metal 菜单控制器实例（持有 _0xE4C8719B 取 ImGui 状态类）
- (id)findMenuIn:(UIView *)v {
    Class a = objc_getClass("_0x1E6B7A93");
    Class b = objc_getClass("_0xB1D7F3A9");
    if (!v) return nil;
    id nr = v.nextResponder;
    if (a && (object_getClass(v)==a || (nr && object_getClass(nr)==a))) return v;
    if (b && (object_getClass(v)==b || (nr && object_getClass(nr)==b))) return v;
    for (UIView *s in v.subviews) { id r = [self findMenuIn:s]; if (r) return r; }
    return nil;
}
- (void)probe {
    uintptr_t obj = r64(kSessionBaseFile + kOffSessionObj);
    uint32_t v  = r32(kSessionBaseFile + kOffVerifyResult);
    uintptr_t g = kSessionBaseFile;

    id menu = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        id m = [self findMenuIn:w];
        if (!m && w.rootViewController) m = [self findMenuIn:w.rootViewController.view];
        if (m) { menu = m; break; }
    }
#pragma clang diagnostic pop

    NSString *line2;
    if (menu) {
        void *st = NULL;
        @try {
            msgGetter get = (msgGetter)objc_msgSend;
            st = get(menu, sel_registerName("_0xE4C8719B"));
        } @catch (NSException *e) { NSLog(@"[P] getter exc %@", e); }
        if (st) {
            uint8_t f0 = *(volatile uint8_t *)st;
            *(volatile uint8_t *)st = 1;          // 置菜单显示开关
            g_menuFlips++;
            line2 = [NSString stringWithFormat:@"MENU=%p flag0=%u→1 x%d", menu, f0, g_menuFlips];
        } else {
            line2 = [NSString stringWithFormat:@"MENU=%p st=0", menu];
        }
        NSLog(@"[PROBE] MENU=%@ st=%p", NSStringFromClass(object_getClass(menu)), st);
    } else {
        line2 = @"menu=NOT-FOUND";
    }
    self.bar.text = [NSString stringWithFormat:@"658=%u obj=%p\n%@", v, (void*)obj, line2];
}
- (void)tap {
    @try {
        armFull();
        callBuild();
        [self probe];
    } @catch (NSException *e) { NSLog(@"[BALL] exc: %@", e); }
}
@end

static void spawnBall(void) {
    @try {
        for (int i = 0; i < 100; i++) {
            @autoreleasepool {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
                UIWindow *win = UIApplication.sharedApplication.keyWindow;
#pragma clang diagnostic pop
                if (win) {
                    BallTarget *tgt = [BallTarget new];
                    ball = [UIButton buttonWithType:UIButtonTypeSystem];
                    ball.frame = CGRectMake(20, 120, 170, 64);
                    ball.backgroundColor = [UIColor colorWithRed:0.1 green:0.6 blue:1.0 alpha:0.85];
                    ball.layer.cornerRadius = 12;
                    UILabel *bar = [[UILabel alloc] initWithFrame:ball.bounds];
                    bar.textColor = [UIColor whiteColor];
                    bar.font = [UIFont systemFontOfSize:11];
                    bar.numberOfLines = 0;
                    bar.text = @"—";
                    tgt.bar = bar;
                    [ball addSubview:bar];
                    [ball addTarget:tgt action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
                    [win addSubview:ball];
                    [tgt probe];
                    for (int k = 0; k < 6; k++) {
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)((2+k*2)*NSEC_PER_SEC)),
                                       dispatch_get_main_queue(), ^{ [tgt probe]; });
                    }
                    return;
                }
            }
            usleep(300000);
        }
    } @catch (NSException *e) { NSLog(@"[BALL] spawn exc: %@", e); }
}

__attribute__((constructor))
static void initBy(void) {
    @autoreleasepool {
        g_targetBase = findTargetBase();
        NSLog(@"[BY] base = %p", (void *)g_targetBase);
        installHooks();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ spawnBall(); });
    }
}
