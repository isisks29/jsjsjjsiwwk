// ============================================================
//  ace 靶场卡密验证绕过 dylib · v11（全局闸门 murmur 校验伪造）
//  目标：ace-第四课-授权靶场.dylib
//
//  根本原因（逆向确认）：
//    面板是 Metal 绘制（drawInMTKView: @0x7f5d4），不是 UIView。
//    每帧检查 0x3d6ee0/ee4/ee8 的 murmur 校验链，失败则跳过绘制。
//    0x3d6ee0==0 时直接 cbz 跳过。
//    悬浮球创建（0x109038 函数）也有同样校验。
//
//  v11：读 0x3d6ed8，用靶场相同的 murmur 算法计算正确的
//        ee0/ee4/ee8，写入 __common 段（可读写，无需 mprotect）。
//        这样 drawInMTKView 每帧通过 → 面板绘制；
//        初始化函数通过 → 悬浮球创建。
// ============================================================
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <stdint.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>

static void NoopVoid(id self, SEL _cmd, ...) { return; }
static BOOL ReturnYES(id self, SEL _cmd, ...) { return YES; }
static BOOL ReturnNO(id self, SEL _cmd, ...) { return NO; }

static NSString *FakePassword(id self, SEL _cmd, NSString *service, NSString *account) {
    return @"ACTIVATED_V11";
}

static void WriteActivationKeychain(void) {
    Class keychain = objc_getClass("_0xD5A13E79");
    if (!keychain) keychain = NSClassFromString(@"SAMKeychain");
    if (!keychain) return;
    NSString *service = @"com.apple.LSDocumentRegistry";
    NSString *account = @"com.apple.identitytoken.v4";
    NSString *password = @"ACTIVATED_BY_BYPASS_V11";
    SEL sel1 = NSSelectorFromString(@"setPassword:forService:account:error:");
    SEL sel2 = NSSelectorFromString(@"setPassword:forService:account:");
    if ([keychain respondsToSelector:sel1]) {
        NSError *err = nil;
        ((void(*)(id,SEL,id,id,id,id*))objc_msgSend)(keychain,sel1,password,service,account,&err);
    } else if ([keychain respondsToSelector:sel2]) {
        ((void(*)(id,SEL,id,id,id))objc_msgSend)(keychain,sel2,password,service,account);
    }
}

static UIWindow *GetCurrentKeyWindow(void) {
    UIApplication *app = [UIApplication sharedApplication];
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *scene in app.connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *win in scene.windows) {
                    if (win.isKeyWindow) return win;
                }
            }
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return app.keyWindow;
#pragma clang diagnostic pop
}

// ---------- 核心：伪造 murmur 全局闸门 ----------
// 从 drawInMTKView: @0x7f5d4 还原的校验算法
#define MURMUR_C1 0x1f3d6a71U
#define MURMUR_C2 0x8e4b1395U

static uintptr_t GetAceDylibBase(void) {
    // 通过靶场类的方法实现地址反查 image 基址
    Class panelCls = objc_getClass("_0xB1D7F3A9");
    if (!panelCls) return 0;
    Method m = class_getInstanceMethod(panelCls, @selector(m0));
    if (!m) m = class_getInstanceMethod(panelCls, NSSelectorFromString(@"m0"));
    if (!m) return 0;
    IMP imp = method_getImplementation(m);
    Dl_info info;
    if (dladdr(imp, &info) == 0) return 0;
    return (uintptr_t)info.dli_fbase;
}

static void ForgeGlobalGate(void) {
    uintptr_t base = GetAceDylibBase();
    if (!base) return;
    // 静态基址 0x100000000，全局变量运行时地址 = base + 偏移
    // 0x3d6ed8/ee0/ee4/ee8 是 __common 段偏移
    uintptr_t addr_ed8 = base + 0x3d6ed8;
    uintptr_t addr_ee0 = base + 0x3d6ee0;
    uintptr_t addr_ee4 = base + 0x3d6ee4;
    uintptr_t addr_ee8 = base + 0x3d6ee8;

    uint64_t ed8 = *(volatile uint64_t *)addr_ed8;
    // 第2关：x22 = ed8 ^ 0xb75e8052babd72a6
    uint64_t x22 = ed8 ^ 0xb75e8052babd72a6ULL;
    uint32_t x22_lo = (uint32_t)x22;
    uint32_t x22_hi = (uint32_t)(x22 >> 32);

    // ee0 = murmur(x22_lo ^ 0xd18ddb25 ^ x22_hi)
    uint32_t ee0 = x22_lo ^ 0xd18ddb25U;
    ee0 ^= x22_hi;
    ee0 ^= ee0 >> 15;
    ee0 *= MURMUR_C1;
    ee0 ^= ee0 >> 11;
    ee0 *= MURMUR_C2;
    ee0 ^= ee0 >> 17;

    // ee4 = murmur2(ee0, x22)
    uint32_t w9 = ee0 ^ 0x1767cedcU;
    w9 ^= w9 >> 15;
    w9 *= MURMUR_C1;
    w9 ^= w9 >> 11;
    w9 *= MURMUR_C2;
    uint32_t w12 = ((uint32_t)(x22 >> 17)) ^ w9;
    w9 = w12 ^ w9;
    uint32_t ee4 = w9;

    // ee8 = murmur3(ee4, x22_hi)
    uint32_t w10 = ee4 ^ 0x5d41c293U;
    w10 ^= w10 >> 15;
    w10 *= MURMUR_C1;
    w10 ^= w10 >> 11;
    w10 *= MURMUR_C2;
    uint32_t w8 = x22_hi ^ (w10 >> 17);
    w8 ^= w10;
    uint32_t ee8 = w8;

    // 写入（__common 段可读写）
    *(volatile uint32_t *)addr_ee0 = ee0;
    *(volatile uint32_t *)addr_ee4 = ee4;
    *(volatile uint32_t *)addr_ee8 = ee8;
}

// ---------- 菜单显示开关（4 类 getter 首字节=1） ----------
static NSMutableDictionary *orig_getters = nil;
static id Hook_menuStateGetter(id self, SEL _cmd) {
    NSString *key = NSStringFromClass([self class]);
    IMP orig = (IMP)[orig_getters[key] pointerValue];
    id obj = ((id(*)(id,SEL))orig)(self, _cmd);
    if (obj) *((uint8_t *)(__bridge void *)obj) = 1;
    return obj;
}
static void HookMenuGetters(void) {
    orig_getters = [NSMutableDictionary dictionary];
    NSArray *classNames = @[@"_0xD4E9A3C7", @"_0xB1D7F3A9", @"_0x1E6B7A93", @"_0xC8E2A541"];
    SEL sel = NSSelectorFromString(@"_0xE4C8719B");
    for (NSString *cn in classNames) {
        const char *cstr = [cn UTF8String];
        Class cls = objc_getClass(cstr);
        if (!cls) continue;
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP orig = method_getImplementation(m);
            orig_getters[cn] = [NSValue valueWithPointer:orig];
            method_setImplementation(m, (IMP)Hook_menuStateGetter);
        }
    }
}

// ---------- 卡密弹窗抑制 ----------
static IMP orig_cardInit = NULL;
static UIView *Hook_cardInit(id self, SEL _cmd, CGRect frame) {
    UIView *v = ((UIView*(*)(id,SEL,CGRect))orig_cardInit)(self,_cmd,frame);
    if (v) {
        v.hidden = YES;
        v.alpha = 0;
        v.userInteractionEnabled = NO;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.3*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ [v removeFromSuperview]; });
    }
    return v;
}

// ---------- 弹窗兜底 ----------
static BOOL IsCardErrorMsg(NSString *msg) {
    if (!msg || ![msg isKindOfClass:[NSString class]]) return NO;
    NSArray *kws = @[@"不存在",@"失败",@"错误",@"无效",@"过期",@"已使用",
                     @"not exist",@"invalid",@"failed",@"error"];
    for (NSString *kw in kws) {
        if ([msg rangeOfString:kw options:NSCaseInsensitiveSearch].location != NSNotFound)
            return YES;
    }
    return NO;
}
static UIAlertController *(*orig_alertCtrl)(id,SEL,NSString*,NSString*,UIAlertControllerStyle);
static UIAlertController *Hook_alertCtrl(id self, SEL _cmd, NSString *title,
                                          NSString *message, UIAlertControllerStyle style) {
    if (IsCardErrorMsg(message) || IsCardErrorMsg(title)) {
        WriteActivationKeychain();
        UIAlertController *ac = orig_alertCtrl(self,_cmd,@"激活成功",@"功能已解锁",style);
        [ac addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction*a){ [ac dismissViewControllerAnimated:YES completion:nil]; }]];
        return ac;
    }
    return orig_alertCtrl(self,_cmd,title,message,style);
}
static IMP orig_addAction = NULL;
static void Hook_addAction(id self, SEL _cmd, UIAlertAction *action) {
    if (action && [action.title isEqualToString:@"重试"]) return;
    ((void(*)(id,SEL,id))orig_addAction)(self,_cmd,action);
}

// ---------- 工具 ----------
static void SwizzleOnAllClasses(NSArray<NSString*> *selectors, IMP imp, BOOL instance) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return;
    __unsafe_unretained Class *buf = (__unsafe_unretained Class*)malloc(sizeof(Class)*count);
    objc_getClassList(buf, count);
    for (NSString *sn in selectors) {
        SEL sel = NSSelectorFromString(sn);
        for (int i = 0; i < count; i++) {
            Class cls = buf[i];
            if (!cls) continue;
            Method m = instance ? class_getInstanceMethod(cls,sel) : class_getClassMethod(cls,sel);
            if (m) method_setImplementation(m, imp);
        }
    }
    free(buf);
}

__attribute__((constructor))
static void BypassV11Init(void) {
    // ★ 核心：伪造全局闸门 murmur 校验（让 Metal 面板绘制通过）
    ForgeGlobalGate();

    WriteActivationKeychain();

    // 状态伪造
    SwizzleOnAllClasses(@[@"isProtectionActive"], (IMP)ReturnYES, YES);
    SwizzleOnAllClasses(@[@"isShuttingDown"], (IMP)ReturnNO, YES);
    SwizzleOnAllClasses(@[@"setIsProtectionActive:"], (IMP)NoopVoid, YES);

    // 保护抑制
    SwizzleOnAllClasses(@[
        @"forceExitWithReason:",@"cleanupAndExit:",@"cleanupSensitiveData",
        @"showBanAlertWithReason:",@"showServerClosedAlert:",
        @"showVersionUpdateAlert:",@"showServerMessage:",@"stopProtection",
    ], (IMP)NoopVoid, YES);
    SwizzleOnAllClasses(@[
        @"startHeartbeatTimer",@"performHeartbeat",@"checkHeartbeatHealth",
    ], (IMP)NoopVoid, YES);
    SwizzleOnAllClasses(@[
        @"isJailbroken",@"detectInjectedLibraries",@"detectTweakInject",
        @"detectSuspiciousFrameworks",@"performFullDetection",
    ], (IMP)ReturnNO, YES);
    SwizzleOnAllClasses(@[@"passwordForService:account:"], (IMP)FakePassword, YES);
    SwizzleOnAllClasses(@[@"passwordForService:account:error:"], (IMP)FakePassword, YES);
    SwizzleOnAllClasses(@[@"q17"], (IMP)NoopVoid, YES);

    // 菜单显示开关
    HookMenuGetters();

    // 卡密弹窗抑制
    Class cardCls = objc_getClass("_0x37C8E2B6");
    if (cardCls) {
        Method m = class_getInstanceMethod(cardCls, @selector(initWithFrame:));
        if (m) {
            orig_cardInit = method_getImplementation(m);
            method_setImplementation(m, (IMP)Hook_cardInit);
        }
    }

    // 弹窗兜底
    Class ac = objc_getClass("UIAlertController");
    if (ac) {
        Method m1 = class_getClassMethod(ac, @selector(alertControllerWithTitle:message:preferredStyle:));
        if (m1) {
            orig_alertCtrl = (void*)method_getImplementation(m1);
            method_setImplementation(m1, (IMP)Hook_alertCtrl);
        }
        Method m2 = class_getInstanceMethod(ac, @selector(addAction:));
        if (m2) {
            orig_addAction = method_getImplementation(m2);
            method_setImplementation(m2, (IMP)Hook_addAction);
        }
    }

    // 延迟再次伪造（防止保护代码在 constructor 之后重置全局变量）
    for (int delay = 1; delay <= 10; delay += 2) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(delay*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ ForgeGlobalGate(); });
    }
}
