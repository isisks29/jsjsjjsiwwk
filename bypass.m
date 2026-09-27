// ============================================================
//  ace 靶场卡密验证绕过 dylib · v7（纯ObjC层并联，不碰全局内存）
//  目标：ace-第四课-授权靶场.dylib
//
//  v6 闪退原因：写 0x3d6ed8/ee4/ee8 破坏反篡改 murmur 校验 → 崩。
//  v7 彻底放弃写全局内存，全部走 ObjC 层并联电路：
//    A. hook 面板 _0xB1D7F3A9 initWithFrame: → 保存实例 + 强制显示
//    B. hook _0xE4C8719B getter → 首字节=1（菜单显示开关）
//    C. 延迟遍历窗口 → 找到面板强制显示提到最上层；找不到则主动创建+addSubview
//    D. 弹窗抑制 + 状态伪造 + 保护抑制
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
    return @"ACTIVATED_V7";
}

static void WriteActivationKeychain(void) {
    Class keychain = objc_getClass("_0xD5A13E79");
    if (!keychain) keychain = NSClassFromString(@"SAMKeychain");
    if (!keychain) return;
    NSString *service = @"com.apple.LSDocumentRegistry";
    NSString *account = @"com.apple.identitytoken.v4";
    NSString *password = @"ACTIVATED_BY_BYPASS_V7";
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

// 全局保存面板实例（hook 创建时捕获）
static __strong UIView *g_panel = nil;

// ---------- 通道A：hook 面板创建，保存实例+强制显示 ----------
static IMP orig_panelInit = NULL;
static UIView *Hook_panelInit(id self, SEL _cmd, CGRect frame) {
    UIView *v = ((UIView*(*)(id,SEL,CGRect))orig_panelInit)(self,_cmd,frame);
    if (v) {
        g_panel = v;   // 保存强引用，防止被释放
        v.hidden = NO;
        v.alpha = 1;
        v.userInteractionEnabled = YES;
    }
    return v;
}

// ---------- 通道B：菜单显示开关 ----------
static NSMutableDictionary *orig_getters = nil;
static id Hook_menuStateGetter(id self, SEL _cmd) {
    NSString *key = NSStringFromClass([self class]);
    IMP orig = (IMP)[orig_getters[key] pointerValue];
    id obj = ((id(*)(id,SEL))orig)(self, _cmd);
    if (obj) {
        *((uint8_t *)(__bridge void *)obj) = 1;
    }
    return obj;
}
static void HookMenuStateGetters(void) {
    orig_getters = [NSMutableDictionary dictionary];
    SEL sel = NSSelectorFromString(@"_0xE4C8719B");
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return;
    __unsafe_unretained Class *buf = (__unsafe_unretained Class*)malloc(sizeof(Class)*count);
    objc_getClassList(buf, count);
    for (int i = 0; i < count; i++) {
        Class cls = buf[i];
        if (!cls) continue;
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP orig = method_getImplementation(m);
            orig_getters[NSStringFromClass(cls)] = [NSValue valueWithPointer:orig];
            method_setImplementation(m, (IMP)Hook_menuStateGetter);
        }
    }
    free(buf);
}

// ---------- 通道C：遍历窗口找面板；找不到则主动创建+addSubview ----------
static void ForceShowPanel(void) {
    UIWindow *win = GetCurrentKeyWindow();
    if (!win) return;
    Class panelCls = objc_getClass("_0xB1D7F3A9");
    __block UIView *found = nil;
    // 1) 先在窗口树里找面板
    NSMutableArray *allWindows = [NSMutableArray array];
    [allWindows addObject:win];
    if (win.windowScene) [allWindows addObjectsFromArray:win.windowScene.windows];
    for (UIWindow *w in allWindows) {
        NSMutableArray *stack = [NSMutableArray arrayWithObject:w];
        while (stack.count > 0) {
            UIView *cur = stack.lastObject;
            [stack removeLastObject];
            if (panelCls && [cur isKindOfClass:panelCls]) { found = cur; break; }
            [stack addObjectsFromArray:cur.subviews];
        }
        if (found) break;
    }
    // 2) 若没找到但 hook 捕获过实例，用它
    if (!found && g_panel && [g_panel isKindOfClass:panelCls]) found = g_panel;
    // 3) 仍没有 → 主动创建面板并加进 window
    if (!found && panelCls) {
        UIView *nv = [(UIView*)[panelCls alloc] initWithFrame:win.bounds];
        if (nv) { found = nv; [win addSubview:nv]; }
    }
    // 4) 强制显示
    if (found) {
        found.hidden = NO;
        found.alpha = 1;
        found.userInteractionEnabled = YES;
        if (found.superview) [found.superview bringSubviewToFront:found];
    }
}

// ---------- 通道D：弹窗兜底 ----------
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
static void BypassV7Init(void) {
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

    // 通道B：菜单显示开关
    HookMenuStateGetters();

    // 通道A：hook 面板创建
    Class panelCls = objc_getClass("_0xB1D7F3A9");
    if (panelCls) {
        Method m = class_getInstanceMethod(panelCls, @selector(initWithFrame:));
        if (m) {
            orig_panelInit = method_getImplementation(m);
            method_setImplementation(m, (IMP)Hook_panelInit);
        }
    }

    // 通道D：弹窗兜底
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

    // 通道C：多轮延迟强制显示面板（覆盖不同初始化时机）
    for (int delay = 2; delay <= 14; delay += 2) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(delay*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ ForceShowPanel(); });
    }
}
