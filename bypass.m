// ============================================================
//  ace 靶场卡密验证绕过 dylib · v8（防崩溃版：用真实面板实例，禁止裸创建）
//  目标：ace-第四课-授权靶场.dylib
//
//  v7 崩溃源：ForceShowPanel 主动 [[_0xB1D7F3A9 alloc] initWithFrame:]
//            裸创建面板 → 缺游戏上下文 → 崩
//  v8 原则：
//    · 只用真实创建的面板实例（主视图流程里 0x1097a0 创建，肯定执行）
//    · 不主动 alloc 任何靶场类
//    · getter hook 收窄到菜单相关两个类
//    · 加回卡密弹窗抑制（v4 验证过稳定）
// ============================================================
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <stdint.h>

static void NoopVoid(id self, SEL _cmd, ...) { return; }
static BOOL ReturnYES(id self, SEL _cmd, ...) { return YES; }
static BOOL ReturnNO(id self, SEL _cmd, ...) { return NO; }

static NSString *FakePassword(id self, SEL _cmd, NSString *service, NSString *account) {
    return @"ACTIVATED_V8";
}

static void WriteActivationKeychain(void) {
    Class keychain = objc_getClass("_0xD5A13E79");
    if (!keychain) keychain = NSClassFromString(@"SAMKeychain");
    if (!keychain) return;
    NSString *service = @"com.apple.LSDocumentRegistry";
    NSString *account = @"com.apple.identitytoken.v4";
    NSString *password = @"ACTIVATED_BY_BYPASS_V8";
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

// 真实面板实例（hook 捕获，绝不裸创建）
static __strong UIView *g_panel = nil;

// ---------- 通道A：捕获真实面板实例（只保存+轻量显示，不操作内部） ----------
static IMP orig_panelInit = NULL;
static UIView *Hook_panelInit(id self, SEL _cmd, CGRect frame) {
    UIView *v = ((UIView*(*)(id,SEL,CGRect))orig_panelInit)(self,_cmd,frame);
    if (v) g_panel = v;   // 仅保存引用
    return v;
}

// ---------- 通道B：菜单显示开关（hook 全部 4 个靶场类的 _0xE4C8719B） ----------
// 主视图 _0x1E6B7A93 触摸处理 updateIOWithTouches 读它首字节，
// 首字节=0 会跳过触摸处理（点左上角无反应）——必须全部强制=1
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
        Class cls = objc_getClass(cn);
        if (!cls) continue;
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP orig = method_getImplementation(m);
            orig_getters[cn] = [NSValue valueWithPointer:orig];
            method_setImplementation(m, (IMP)Hook_menuStateGetter);
        }
    }
}

// ---------- 通道C：把真实面板加入窗口并显示（不裸创建） ----------
static void ForceShowPanel(void) {
    UIWindow *win = GetCurrentKeyWindow();
    if (!win) return;
    UIView *panel = g_panel;
    Class panelCls = objc_getClass("_0xB1D7F3A9");
    // 1) 先找窗口树里已有的面板
    if (!panel && panelCls) {
        NSMutableArray *stack = [NSMutableArray arrayWithObject:win];
        while (stack.count > 0) {
            UIView *cur = stack.lastObject;
            [stack removeLastObject];
            if ([cur isKindOfClass:panelCls]) { panel = cur; break; }
            [stack addObjectsFromArray:cur.subviews];
        }
    }
    if (!panel) return;   // 面板未创建 → 什么都不做（不裸创建，防崩）
    // 2) 若无 superview，加入 keyWindow
    if (!panel.superview) {
        panel.frame = win.bounds;
        [win addSubview:panel];
    }
    // 3) 强制显示
    panel.hidden = NO;
    panel.alpha = 1;
    panel.userInteractionEnabled = YES;
    [panel.superview bringSubviewToFront:panel];
}

// ---------- 通道D：卡密弹窗抑制（v4 验证过稳定） ----------
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

// ---------- 通道E：弹窗兜底 ----------
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
static void BypassV8Init(void) {
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

    // 通道B：菜单显示开关（收窄到两个类）
    HookMenuGetters();

    // 通道A：捕获真实面板实例
    Class panelCls = objc_getClass("_0xB1D7F3A9");
    if (panelCls) {
        Method m = class_getInstanceMethod(panelCls, @selector(initWithFrame:));
        if (m) {
            orig_panelInit = method_getImplementation(m);
            method_setImplementation(m, (IMP)Hook_panelInit);
        }
    }

    // 通道D：卡密弹窗抑制
    Class cardCls = objc_getClass("_0x37C8E2B6");
    if (cardCls) {
        Method m = class_getInstanceMethod(cardCls, @selector(initWithFrame:));
        if (m) {
            orig_cardInit = method_getImplementation(m);
            method_setImplementation(m, (IMP)Hook_cardInit);
        }
    }

    // 通道E：弹窗兜底
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

    // 通道C：多轮延迟把真实面板加入窗口并显示（绝不裸创建）
    for (int delay = 2; delay <= 14; delay += 2) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(delay*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ ForceShowPanel(); });
    }
}
