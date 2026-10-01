#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <mach/mach.h>

// ================= 目标常量（文件 vmaddr） =================
static const uintptr_t kBuildFnFile      = 0x109020;
static const uintptr_t kIconOnClickFile  = 0x111bd8;
static const uintptr_t kSessionBaseFile  = 0x3ff000;
static const uintptr_t kOffActFlag       = 0x6a8;
static const uintptr_t kOffSessionSeed   = 0x6a0;
static const uintptr_t kOffVerifyResult  = 0x658;
static const uintptr_t kOffSessionObj    = 0x698;

#define GATE0 0xb75e8052babd72a7ULL
#define G1    0xbb3dc5bfULL
#define G2    0x856ac387ULL
#define G3    0x7863ab97ULL

static const uintptr_t kGateBaseFile    = 0x3f7000;
static const uintptr_t kOffGate0        = 0x568;
static const uintptr_t kOffG1           = 0x6a4;
static const uintptr_t kOffG2           = 0x6c0;
static const uintptr_t kOffG3           = 0x6fc;
static const uintptr_t kOffObjPtr       = 0x258;

// ================= 运行时基址 =================
static uintptr_t g_targetBase = 0;

static uintptr_t findTargetBase(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "ace") || strstr(name, "ballsace")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    return 0;
}

static inline void *va(uintptr_t fileAddr) {
    return (void *)(g_targetBase + fileAddr);
}

static inline void w64(uintptr_t fileAddr, uint64_t v) {
    *(volatile uint64_t *)va(fileAddr) = v;
}
static inline void w32(uintptr_t fileAddr, uint32_t v) {
    *(volatile uint32_t *)va(fileAddr) = v;
}
static inline uint64_t r64(uintptr_t fileAddr) {
    return *(volatile uint64_t *)va(fileAddr);
}
static inline uint32_t r32(uintptr_t fileAddr) {
    return *(volatile uint32_t *)va(fileAddr);
}

// ================= 1) 三件套：抑制卡密弹窗 =================
static id (*origPassword)(id, SEL, id, id);
static id hookPassword(id self, SEL _cmd, id svc, id acct) {
    return @"A";
}

static void (*origSetup)(id, SEL);
static void hookSetup(id self, SEL _cmd) {}

static IMP g_origPresent = NULL;
static void hookPresent(id self, SEL _cmd, UIViewController *vc, BOOL anim, void (^comp)(void)) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        if (comp) comp();
        return;
    }
    ((void (*)(id, SEL, UIViewController *, BOOL, void (^)(void)))g_origPresent)(self, _cmd, vc, anim, comp);
}

static void installHooks(void) {
    Class keychain = objc_getClass("_0xD5A13E79");
    Method mPass = keychain ? class_getClassMethod(keychain, sel_registerName("passwordForService:account:")) : NULL;
    if (mPass) {
        origPassword = (id(*)(id,SEL,id,id))method_getImplementation(mPass);
        method_setImplementation(mPass, (IMP)hookPassword);
    }

    Method mSetup = NULL;
    Class popup = objc_getClass("_0x6D1C8F45");
    if (popup) mSetup = class_getInstanceMethod(popup, sel_registerName("setupUI"));
    if (mSetup) {
        origSetup = (void(*)(id,SEL))method_getImplementation(mSetup);
        method_setImplementation(mSetup, (IMP)hookSetup);
    }

    g_origPresent = class_getMethodImplementation([UIViewController class],
                                                   sel_registerName("presentViewController:animated:completion:"));
    if (g_origPresent) {
        Method mPres = class_getInstanceMethod([UIViewController class],
                                               sel_registerName("presentViewController:animated:completion:"));
        method_setImplementation(mPres, (IMP)hookPresent);
    }
}

// ================= 2) 写门卫 + 会话状态 + 验证成功锁存 =================
static void writeGateWords(void) {
    w32(kSessionBaseFile + kOffVerifyResult, 1);
    w64(kGateBaseFile + kOffGate0, GATE0);
    w64(kGateBaseFile + kOffG1,    G1);
    w64(kGateBaseFile + kOffG2,    G2);
    w64(kGateBaseFile + kOffG3,    G3);
    w64(kGateBaseFile + kOffObjPtr, 0);
}

static void logSessionState(void) {
    if (!g_targetBase) return;
    uintptr_t obj = r64(kSessionBaseFile + kOffSessionObj);
    NSLog(@"[DBG] verifyLatch(0x658)=%u  sessionObj(0x698)=%p  actFlag(0x6a8)=%u",
          (unsigned)r32(kSessionBaseFile + kOffVerifyResult),
          (void *)obj,
          (unsigned)r32(kSessionBaseFile + kOffActFlag));
    if (obj) {
        NSLog(@"[DBG] obj +0x78=%llx +0x8e=%u +0x92=%u +0x119a=%llx",
              *(volatile uint64_t *)(obj+0x78),
              *(volatile uint32_t *)(obj+0x8e),
              *(volatile uint32_t *)(obj+0x92),
              *(volatile uint64_t *)(obj+0x119a));
    }
}

// ================= 3) 完整自洽武装 =================
#define W20 0x8e4b1395u
#define W21 0x1f3d6a71u
#define W22 0xd18ddb25u
#define W24 0x1767cedcu
#define W25 0x5d41c293u

static void writeGateBlock(uintptr_t base, uint64_t seed) {
    uint64_t x26 = seed ^ GATE0;
    uint32_t w8  = (uint32_t)(x26 >> 32);
    uint32_t w26 = (uint32_t)x26;
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
    buf[0] = b0; buf[1] = b8; buf[2] = b16; buf[3] = b24; buf[4] = b32;
    uint32_t w = ((uint32_t)(b8>>32) ^ (uint32_t)b8);
    w *= 0x45d9f3b7u; w ^= b16; w *= W20; w ^= b24; w *= W21; w ^= b32; w ^= w>>16;
    buf[5] = w;
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
        NSLog(@"[ARM] gates+expiry+session armed obj=%p", obj);
    } @catch (NSException *e) { NSLog(@"[ARM] exc: %@", e); }
}

// ================= 4) 主动调用构建函数 =================
typedef void (*buildFn)(void);
static void callBuild(void) {
    if (!g_targetBase) return;
    buildFn fn = (buildFn)va(kBuildFnFile);
    if (fn) fn();
}

// ================= 3b) iconOnClick hook =================
static void (*origIconClick)(id, SEL);
static void hookIconClick(id self, SEL _cmd);
static void installIconHook(void) {
    Class menu = objc_getClass("_0xD4E9A3C7");
    Method m = menu ? class_getInstanceMethod(menu, sel_registerName("iconOnClick")) : NULL;
    if (m) {
        origIconClick = (void(*)(id,SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)hookIconClick);
        NSLog(@"[ICON] iconOnClick hooked (orig @%p)", origIconClick);
    }
}

static UIButton *ball = nil;
static volatile int g_iconTapCount = 0;
static void hookIconClick(id self, SEL _cmd) {
    g_iconTapCount++;
    @try { armFull(); }
    @catch (NSException *e) { NSLog(@"[ICON] arm exc: %@", e); }
    if (origIconClick) origIconClick(self, _cmd);
}

@interface BallTarget : NSObject
@property(nonatomic,strong) UILabel *bar;
@end
@implementation BallTarget
- (UIView *)scanIconIn:(UIView *)v {
    if (!v) return nil;
    Class iconCls = objc_getClass("_0xD4E9A3C7");
    if (iconCls && object_getClass(v) == iconCls) return v;
    if ([v isKindOfClass:iconCls]) return v;
    for (UIView *s in v.subviews) {
        UIView *r = [self scanIconIn:s];
        if (r) return r;
    }
    return nil;
}
- (void)probe {
    uintptr_t obj = r64(kSessionBaseFile + kOffSessionObj);
    uint32_t v = (uint32_t)r32(kSessionBaseFile + kOffVerifyResult);
    uint32_t a = (uint32_t)r32(kSessionBaseFile + kOffActFlag);

    UIView *icon = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        UIView *r = [self scanIconIn:w];
        if (r) { icon = r; break; }
    }
#pragma clang diagnostic pop

    NSString *line2;
    if (icon) {
        BOOL hidden = icon.hidden;
        CGFloat alpha = icon.alpha;
        NSString *superName = icon.superview ? NSStringFromClass(object_getClass(icon.superview)) : @"nil";
        // 移除CGRect，不再判断屏幕相交，简化
        line2 = [NSString stringWithFormat:@"iconExist YES h=%d α=%.2f sv=%@", hidden, alpha, superName];
        if (!hidden && alpha > 0.05)
            line2 = [line2 stringByAppendingString:@" VISIBLE"];
        else
            line2 = [line2 stringByAppendingString:@" INVIS"];
    } else {
        line2 = @"icon=NOT‑FOUND";
    }
    self.bar.text = [NSString stringWithFormat:@"658=%u obj=%p\n%@ tap=%d", v, (void*)obj, line2, g_iconTapCount];

    NSLog(@"[PROBE] 658=%u act=%u sessionObj=%p", v, a, (void*)obj);
    if (icon) {
        NSLog(@"[PROBE] ICON=%@ hidden=%d alpha=%.2f superview=%@ win=%p",
              NSStringFromClass(object_getClass(icon)), icon.hidden, icon.alpha,
              NSStringFromClass(object_getClass(icon.superview)), (__bridge void*)icon.window);

        Class iconCls = objc_getClass("_0xD4E9A3C7");
        id iconObj = icon;
        if (icon.hidden || icon.alpha < 0.05) {
            @try {
                if ([iconObj isKindOfClass:iconCls] && [iconObj respondsToSelector:@selector(iconOnClick)]) {
                    [iconObj performSelector:@selector(iconOnClick)];
                }
            } @catch (NSException *e) {
                NSLog(@"[PROBE] prog-icon exc: %@", e);
            }
        }
    }
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
                    ball.frame = CGRectMake(20, 120, 150, 72);
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

                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{
                        [tgt probe];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                                       dispatch_get_main_queue(), ^{ [tgt probe]; });
                    });
                    return;
                }
            }
            usleep(300000);
        }
    } @catch (NSException *e) {
        NSLog(@"[BALL] spawn exc: %@", e);
    }
}

__attribute__((constructor))
static void initBy(void) {
    @autoreleasepool {
        g_targetBase = findTargetBase();
        NSLog(@"[BY] target base = %p", (void *)g_targetBase);
        installHooks();
        installIconHook();

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ logSessionState(); });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            spawnBall();
        });
    }
}
