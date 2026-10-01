












#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <mach/mach.h>

// ================= 目标常量（文件 vmaddr） =================
// 构建函数入口（其内部 14 处防篡改校验全过才会 addSubview: 挂面板）
static const uintptr_t kBuildFnFile      = 0x109020;
// 第二面板入口：_0xD4E9A3C7 -iconOnClick（“点击左上角”→ 面板，Metal）
static const uintptr_t kIconOnClickFile  = 0x111bd8;
// iconOnClick 第一道守卫：BSS 布尔激活标志（0 → 直接 return，面板不显）
// 会话对象种子区（__bss 0x3ff000+）：0x6a0(qword 会话密钥) / 0x6a8·0x6ac·0x6b0(w32 校验字)
static const uintptr_t kSessionBaseFile  = 0x3ff000;
static const uintptr_t kOffActFlag       = 0x6a8;
static const uintptr_t kOffSessionSeed   = 0x6a0;
// 卡密验证成功锁存（0x4ed74 写；0=失败 1=成功）——控制“显示成功”与后续路径
static const uintptr_t kOffVerifyResult  = 0x658;
// 会话对象（0x4e98/0x290bc 惰性创建，验证成功后填充字段）——面板校验对象
static const uintptr_t kOffSessionObj    = 0x698;

// 门卫字（你逆推的正确值，运行时写入 BSS 全局）
#define GATE0 0xb75e8052babd72a7ULL
#define G1    0xbb3dc5bfULL
#define G2    0x856ac387ULL
#define G3    0x7863ab97ULL

// 构建链读取的 __DATA,__bss 全局（文件 vmaddr 0x3f7000+）。
// 反汇编确认构建链这些 offset 都做“读全局→解密→比较→bail”：
//   0x258 0x568 0x580 0x594 0x5b0 0x5cc 0x6a4 0x6c0 0x670 0x688 0x6fc
// 建议（务必用运行期实测核对）：
//   gate0 → 0x568    （与共用链门卫字一致）
//   g1    → 0x6a4
//   g2    → 0x6c0
//   g3    → 0x6fc
//   对象指针 → 0x258 （写 0 → 自初始化，放行 bail7~14）
static const uintptr_t kGateBaseFile    = 0x3f7000;
static const uintptr_t kOffGate0        = 0x568;
static const uintptr_t kOffG1           = 0x6a4;
static const uintptr_t kOffG2           = 0x6c0;
static const uintptr_t kOffG3           = 0x6fc;
static const uintptr_t kOffObjPtr       = 0x258;

// ================= 运行时基址 =================
static uintptr_t g_targetBase = 0;

// 通过 dyld 镜像列表找靶场 dylib 基址（arm64：运行期地址 = imagebase + 文件vmaddr）
static uintptr_t findTargetBase(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        // 安装名/文件名含 ace 或 ballsace 即命中；必要时改成你实测到的名字
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

// ================= 1) 三件套：抑制卡密弹窗 =================
// +[_0xD5A13E79 passwordForService:account:] → 恒 @"A"
static id (*origPassword)(id, SEL, id, id);
static id hookPassword(id self, SEL _cmd, id svc, id acct) {
    return @"A";
}

// setupUI 空转（注意：若发现面板也被吞掉，说明菜单与弹窗共用此构建，
// 应去掉本 hook，改为只拦 UIAlertController——见第 3 步）
static void (*origSetup)(id, SEL);
static void hookSetup(id self, SEL _cmd) {}

// UIViewController presentViewController:animated:completion: —— 全局拦 UIAlertController
static IMP g_origPresent = NULL;
static void hookPresent(id self, SEL _cmd, UIViewController *vc, BOOL anim, void (^comp)(void)) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        if (comp) comp();
        return;
    }
    ((void (*)(id, SEL, UIViewController *, BOOL, void (^)(void)))g_origPresent)(self, _cmd, vc, anim, comp);
}

static void installHooks(void) {
    // 1) 钥匙串查询
    Class keychain = objc_getClass("_0xD5A13E79");
    Method mPass = keychain ? class_getClassMethod(keychain, sel_registerName("passwordForService:account:")) : NULL;
    if (mPass) {
        origPassword = (id(*)(id,SEL,id,id))method_getImplementation(mPass);
        method_setImplementation(mPass, (IMP)hookPassword);
    }
    // 2) setupUI 空转（若吞面板则改为不装）
    Method mSetup = NULL;
    Class popup = objc_getClass("_0x6D1C8F45"); // 或你实测的弹窗类
    if (popup) mSetup = class_getInstanceMethod(popup, sel_registerName("setupUI"));
    if (mSetup) {
        origSetup = (void(*)(id,SEL))method_getImplementation(mSetup);
        method_setImplementation(mSetup, (IMP)hookSetup);
    }
    // 3) 全局拦 UIAlertController
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
    // 验证成功锁存：置 1 → “显示成功”那层门打开
    w32(kSessionBaseFile + kOffVerifyResult, 1);
    w64(kGateBaseFile + kOffGate0, GATE0);
    w64(kGateBaseFile + kOffG1,    G1);
    w64(kGateBaseFile + kOffG2,    G2);
    w64(kGateBaseFile + kOffG3,    G3);
    w64(kGateBaseFile + kOffObjPtr, 0);   // 关键：写 0 → 构建函数自初始化对象
}

// 运行时诊断：打印会话对象字段，判断面板被哪层门卡住
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

// ================= 3) 完整自洽武装（无卡密，纯逆向公式复现） =================
#define W20 0x8e4b1395u
#define W21 0x1f3d6a71u
#define W22 0xd18ddb25u
#define W24 0x1767cedcu
#define W25 0x5d41c293u

// 复现“门卫块”哈希链（来自 iconOnClick 0x111c38..0x111cdc）：seed → 写出 3 个 w32
static void writeGateBlock(uintptr_t base, uint64_t seed) {
    uint64_t x26 = seed ^ GATE0;
    uint32_t w8  = (uint32_t)(x26 >> 32);
    uint32_t w26 = (uint32_t)x26;
    uint32_t w11 = (w26 ^ W22) ^ w8;
    w11 ^= w11>>15; w11 *= W21; w11 ^= w11>>11; w11 *= W20; w11 ^= w11>>17;
    w32(base+0x08, w11);                       // [seed+8] 非零门
    uint32_t w9 = w11 ^ W24;
    w9 ^= w9>>15; w9 *= W21; w9 ^= w9>>11; w9 *= W20;
    w9 = ((uint32_t)x26 ^ (w9>>17)) ^ w9;
    w32(base+0x0c, w9);                        // [seed+0xc]
    uint32_t w10 = w9 ^ W25;
    w10 ^= w10>>15; w10 *= W21; w10 ^= w10>>11; w10 *= W20;
    w8 = w8 ^ (w10>>17) ^ w10;
    w32(base+0x10, w8);                        // [seed+0x10]
}

// 会话对象自洽填充（复现 iconOnClick 0x111dc4..0x111e88）：自选载荷→算校验和→写字段
static void* buildSessionObj(void) {
    void *obj = calloc(1, 0x1200);             // 足够大（含 +0x119a 载荷区）
    uint64_t b0 = 0x123456789abcdef0ULL, b8 = 0xfedcba9876543210ULL;
    uint32_t b16 = 0x11223344, b24 = 0x55667788, b32 = 0x99aabbcc;
    uint64_t *buf = (uint64_t *)((uintptr_t)obj + 0x119a);
    buf[0] = b0; buf[1] = b8; buf[2] = b16; buf[3] = b24; buf[4] = b32;
    uint32_t w = ((uint32_t)(b8>>32) ^ (uint32_t)b8);
    w *= 0x45d9f3b7u; w ^= b16; w *= W20; w ^= b24; w *= W21; w ^= b32; w ^= w>>16;
    buf[5] = w;                                 // b40 校验和
    *(volatile uint32_t*)((uintptr_t)obj + 0x0)  = ((uint32_t)(b0>>0x13)) ^ (b32 ^ 0x5f8a16e3u);
    *(volatile uint64_t*)((uintptr_t)obj + 0x78) = (b0 ^ b8) ^ 0xa5c3e1f7b6d2489aULL;
    *(volatile uint32_t*)((uintptr_t)obj + 0x8e) = ((uint32_t)(b0>>7)) ^ (b16 ^ 0x4a9b5206u);
    *(volatile uint32_t*)((uintptr_t)obj + 0x92) = ((uint32_t)(b0>>0xd)) ^ (b24 ^ 0x8c1a73e5u);
    return obj;
}

static void armFull(void) {
    if (!g_targetBase) return;
    @try {
        uintptr_t g = kSessionBaseFile;         // 0x3ff000
        // 门卫块 A（seed 0x6a0）与 C（seed 0x680=GATE0 → 过期项 x23=0）
        w64(g+0x6a0, GATE0); writeGateBlock(g+0x6a0, GATE0);
        w64(g+0x680, GATE0); writeGateBlock(g+0x680, GATE0);
        // 过期(天卡/周卡)绕过：时间项归零，x23=0 → 恒在有效窗
        w32(0x3fb000+0x98c, 0);
        w32(0x3fb000+0x990, 1);
        w32(0x3fb000+0x998, 0);                 // 必须 != -1
        // 会话对象
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
    if (fn) fn();   // 内部14处校验全过才会 addSubview: 挂载 Metal 面板
}

// ================= 3b) 第二面板：iconOnClick（点左上角） =================
// hook 真实 iconOnClick：先武装，再放行原实现 → 点击即出面板（实现见第4节）
static void (*origIconClick)(id, SEL);          // 前向声明
static void hookIconClick(id, SEL);             // 前向声明
static void installIconHook(void) {
    Class menu = objc_getClass("_0xD4E9A3C7");
    Method m = menu ? class_getInstanceMethod(menu, sel_registerName("iconOnClick")) : NULL;
    if (m) {
        origIconClick = (void(*)(id,SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)hookIconClick);
        NSLog(@"[ICON] iconOnClick hooked (orig @%p)", origIconClick);
    }
}

// ================= 4) 悬浮球 + 屏上动态分析台 =================
static UIButton *ball = nil;
static volatile int g_iconTapCount = 0;      // iconOnClick hook 命中计数
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
// 递归扫描视图树，找图标类实例（_0xD4E9A3C7：图标控制器/视图）
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
    // 1) 会话/门卫状态
    uintptr_t obj = r64(kSessionBaseFile + kOffSessionObj);
    uint32_t v = (uint32_t)r32(kSessionBaseFile + kOffVerifyResult);
    uint32_t a = (uint32_t)r32(kSessionBaseFile + kOffActFlag);
    // 2) 图标定位
    UIView *icon = nil;
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        UIView *r = [self scanIconIn:w];
        if (r) { icon = r; break; }
    }
    CGRect f = icon ? icon.frame : CGRectZero;
    NSString *line2;
    if (icon) {
        BOOL hidden = icon.hidden;
        CGFloat alpha = icon.alpha;
        NSString *superName = icon.superview ? NSStringFromClass(object_getClass(icon.superview)) : @"nil";
        line2 = [NSString stringWithFormat:@"iconF(%.0f,%.0f %.0fx%.0f) h=%d α=%.2f sv=%@",
                 f.origin.x, f.origin.y, f.size.width, f.size.height, hidden, alpha, superName];
        if (!hidden && alpha > 0.05 && CGRectIntersectsRect(f, icon.window.bounds))
            line2 = [line2 stringByAppendingString:@" VISIBLE"];
        else
            line2 = [line2 stringByAppendingString:@" INVIS"];
    } else {
        line2 = @"icon=NOT-FOUND";
    }
    self.bar.text = [NSString stringWithFormat:@"658=%u obj=%p\n%@ tap=%d", v, (void*)obj, line2, g_iconTapCount];
    // 详细打点（一次性）
    NSLog(@"[PROBE] 658=%u act=%u sessionObj=%p", v, a, (void*)obj);
    if (icon) {
        NSLog(@"[PROBE] ICON=%@ at (%.0f,%.0f) hidden=%d alpha=%.2f superview=%@ win=%p",
              NSStringFromClass(object_getClass(icon)), f.origin.x, f.origin.y, icon.hidden, icon.alpha,
              NSStringFromClass(object_getClass(icon.superview)), (void*)icon.window);
        // 若不可见，尝试程序化触发（=模拟点左上角）
        if (icon.hidden || icon.alpha < 0.05) {
            @try { if ([icon respondsToSelector:@selector(iconOnClick)]) [icon iconOnClick]; }
            @catch (NSException *e) { NSLog(@"[PROBE] prog-icon exc: %@", e); }
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
        for (int i = 0; i < 100; i++) {            // 轮询等 keyWindow 最多 30s
            @autoreleasepool {
                UIWindow *win = UIApplication.sharedApplication.keyWindow;
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
                    // 动态分析：每 2s 自动刷新图标/会话状态
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{
                        [tgt probe];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                                       dispatch_get_main_queue(), ^{ [tgt probe]; });
                    });
                    return;
                }
            }
            usleep(300000);                        // 300ms
        }
    } @catch (NSException *e) {
        NSLog(@"[BALL] spawn exc: %@", e);
    }
}

// ================= 构造入口 =================
__attribute__((constructor))
static void initBy(void) {
    @autoreleasepool {
        g_targetBase = findTargetBase();
        NSLog(@"[BY] target base = %p", (void *)g_targetBase);
        installHooks();
        installIconHook();    // 第二面板：点左上角即出 Metal 菜单
        // 启动 5s 后打印会话状态基线
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ logSessionState(); });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            spawnBall();
        });
    }
}
