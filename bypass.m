// ============================================================
//  ace 靶场卡密验证绕过 dylib · v5
//  目标：ace-第四课-授权靶场.dylib
//
//  v5 核心突破（逆向 iconOnClick 确认）：
//    菜单显示开关 = _0xE4C8719B getter 返回对象的第一个字节
//    iconOnClick 有十几道前置校验（反篡改murmur/时间戳/全局标志），
//    外部调用大概率失败 → 直接 hook getter 强制首字节=1
//
//  五层防护：
//    1. 抑制卡密弹窗 _0x37C8E2B6 initWithFrame: → 隐藏+移除
//    2. 强制菜单显示：hook _0xE4C8719B getter → 首字节=1
//    3. 状态伪造：isProtectionActive→YES，keychain→非空
//    4. 保护抑制：心跳/自杀/检测→noop/NO
//    5. UI兜底：alertController 拦截错误弹窗→"激活成功"+确定按钮
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
    return @"ACTIVATED_V5";
}

static void WriteActivationKeychain(void) {
    Class keychain = objc_getClass("_0xD5A13E79");
    if (!keychain) keychain = NSClassFromString(@"SAMKeychain");
    if (!keychain) return;
    NSString *service = @"com.apple.LSDocumentRegistry";
    NSString *account = @"com.apple.identitytoken.v4";
    NSString *password = @"ACTIVATED_BY_BYPASS_V5";
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

// ---------- 第1层：抑制卡密弹窗 ----------
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

// ---------- 第2层：强制菜单显示（核心突破） ----------
// hook _0xE4C8719B getter，返回对象首字节恒=1（菜单显示）
static NSMutableDictionary *orig_getters = nil;
static id Hook_menuStateGetter(id self, SEL _cmd) {
    NSString *key = NSStringFromClass([self class]);
    IMP orig = (IMP)[orig_getters[key] pointerValue];
    id obj = ((id(*)(id,SEL))orig)(self, _cmd);
    if (obj) {
        // 原代码 iconOnClick 直接读写返回对象的第一个字节作为菜单开关
        void *ptr = (__bridge void *)obj;
        *((uint8_t *)ptr) = 1;
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

// ---------- 第5层：UI 兜底 ----------
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
        // 添加确定按钮（覆盖原来的"重试"）
        [ac addAction:[UIAlertAction actionWithTitle:@"确定"
                                                style:UIAlertActionStyleDefault
                                              handler:^(UIAlertAction *a){
            [ac dismissViewControllerAnimated:YES completion:nil];
        }]];
        return ac;
    }
    return orig_alertCtrl(self,_cmd,title,message,style);
}

// hook addAction: 过滤掉"重试"按钮
static IMP orig_addAction = NULL;
static void Hook_addAction(id self, SEL _cmd, UIAlertAction *action) {
    if (action && [action.title isEqualToString:@"重试"]) {
        return; // 丢弃重试按钮
    }
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
static void BypassV5Init(void) {
    WriteActivationKeychain();

    // 第3层：状态伪造
    SwizzleOnAllClasses(@[@"isProtectionActive"], (IMP)ReturnYES, YES);
    SwizzleOnAllClasses(@[@"isShuttingDown"], (IMP)ReturnNO, YES);
    SwizzleOnAllClasses(@[@"setIsProtectionActive:"], (IMP)NoopVoid, YES);

    // 第4层：保护抑制
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

    // keychain 判活
    SwizzleOnAllClasses(@[@"passwordForService:account:"], (IMP)FakePassword, YES);
    SwizzleOnAllClasses(@[@"passwordForService:account:error:"], (IMP)FakePassword, YES);
    SwizzleOnAllClasses(@[@"q17"], (IMP)NoopVoid, YES);

    // 第1层：抑制卡密弹窗
    Class cardCls = objc_getClass("_0x37C8E2B6");
    if (cardCls) {
        Method m = class_getInstanceMethod(cardCls, @selector(initWithFrame:));
        if (m) {
            orig_cardInit = method_getImplementation(m);
            method_setImplementation(m, (IMP)Hook_cardInit);
        }
    }

    // 第2层：强制菜单显示（核心）
    HookMenuStateGetters();

    // 第5层：UI 兜底
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

    // 延迟确保菜单渲染
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(),^{
        // 菜单已通过 getter hook 强制显示，这里确保悬浮球在最上层
        Class floatCls = objc_getClass("_0xD4E9A3C7");
        UIWindow *win = GetCurrentKeyWindow();
        if (floatCls && win) {
            NSMutableArray *stack = [NSMutableArray arrayWithObject:win];
            while (stack.count > 0) {
                UIView *cur = stack.lastObject;
                [stack removeLastObject];
                if ([cur isKindOfClass:floatCls]) {
                    cur.hidden = NO;
                    cur.alpha = 1;
                    [cur.superview bringSubviewToFront:cur];
                    break;
                }
                [stack addObjectsFromArray:cur.subviews];
            }
        }
    });
}
