// ============================================================
//  ace 靶场卡密验证绕过 dylib · v6（并联电路，多通道同时触发）
//  目标：ace-第四课-授权靶场.dylib
//
//  根因（本轮逆向确认）：
//    面板创建在主视图 initWithFrame:::: 里：
//      0x109744: x26 = &0x3d6ee0  (全局 int)
//      0x109800: ldr w8,[x26]
//      0x109804: cbz w8 -> 跳过"把面板加入屏幕"的后续流程
//    0x3d6ee0 是保护校验全局哈希标志（__common 段），初始=0，
//    只有激活通过才非零。ObjC 层 hook 全部绕不过它。
//
//  并联电路（任一条通→面板显现）：
//    A. 运行时写 0x3d6ee0 非零（打开面板创建的门）【核心】
//    B. hook _0xE4C8719B getter → 首字节=1（菜单显示开关）
//    C. hook 面板/悬浮球 initWithFrame → 强制显示+加入keyWindow
//    D. 延迟遍历窗口 → 找到面板/悬浮球强制显示提到最上层
//    E. 弹窗抑制 + 状态伪造 + 保护抑制（保留）
// ============================================================
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <stdint.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static void NoopVoid(id self, SEL _cmd, ...) { return; }
static BOOL ReturnYES(id self, SEL _cmd, ...) { return YES; }
static BOOL ReturnNO(id self, SEL _cmd, ...) { return NO; }

// ---------- 通道A（核心）：运行时写全局激活标志 ----------
// 找到 ace dylib 里虚拟地址 va 对应的运行时内存地址，并把 0x3d6ee0 写非零
static void PatchActivationFlags(void) {
    uintptr_t targets[] = {0x3d6ee0, 0x3d6ed8, 0x3d6ee4, 0x3d6ee8};
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *hdr = (const struct mach_header_64*)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        uintptr_t slide = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
        const struct load_command *lc = (const struct load_command*)((char*)hdr + sizeof(struct mach_header_64));
        for (uint32_t k = 0; k < hdr->ncmds; k++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64*)lc;
                uintptr_t seg_start = slide + seg->vmaddr;
                uintptr_t seg_end = seg_start + seg->vmsize;
                for (int t = 0; t < 4; t++) {
                    uintptr_t va = targets[t];
                    if (seg_start <= slide + va && slide + va < seg_end) {
                        uint32_t *p = (uint32_t*)(slide + va);
                        *p = 1; // 写非零，打开面板创建的门
                    }
                }
            }
            lc = (const struct load_command*)((char*)lc + lc->cmdsize);
        }
    }
}

static NSString *FakePassword(id self, SEL _cmd, NSString *service, NSString *account) {
    return @"ACTIVATED_V6";
}

static void WriteActivationKeychain(void) {
    Class keychain = objc_getClass("_0xD5A13E79");
    if (!keychain) keychain = NSClassFromString(@"SAMKeychain");
    if (!keychain) return;
    NSString *service = @"com.apple.LSDocumentRegistry";
    NSString *account = @"com.apple.identitytoken.v4";
    NSString *password = @"ACTIVATED_BY_BYPASS_V6";
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

// ---------- 通道B：菜单显示开关（_0xE4C8719B 首字节=1） ----------
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

// ---------- 通道C：hook 面板/悬浮球创建后强制显示 ----------
static IMP orig_panelInit = NULL;
static UIView *Hook_panelInit(id self, SEL _cmd, CGRect frame) {
    UIView *v = ((UIView*(*)(id,SEL,CGRect))orig_panelInit)(self,_cmd,frame);
    if (v) {
        v.hidden = NO;
        v.alpha = 1;
        v.userInteractionEnabled = YES;
    }
    return v;
}

// ---------- 通道D：延迟遍历窗口强制显示面板/悬浮球 ----------
static void ForceShowPanel(void) {
    UIWindow *win = GetCurrentKeyWindow();
    if (!win) return;
    Class panelCls = objc_getClass("_0xB1D7F3A9");
    Class floatCls = objc_getClass("_0xD4E9A3C7");
    if (!panelCls && !floatCls) return;
    NSMutableArray *allWindows = [NSMutableArray array];
    [allWindows addObject:win];
    if (win.windowScene) [allWindows addObjectsFromArray:win.windowScene.windows];
    __block UIView *panel = nil, *ball = nil;
    for (UIWindow *w in allWindows) {
        NSMutableArray *stack = [NSMutableArray arrayWithObject:w];
        while (stack.count > 0) {
            UIView *cur = stack.lastObject;
            [stack removeLastObject];
            if (!panel && panelCls && [cur isKindOfClass:panelCls]) panel = cur;
            if (!ball && floatCls && [cur isKindOfClass:floatCls]) ball = cur;
            if (panel && ball) break;
            [stack addObjectsFromArray:cur.subviews];
        }
    }
    if (panel) {
        panel.hidden = NO;
        panel.alpha = 1;
        [panel.superview bringSubviewToFront:panel];
    }
    if (ball) {
        ball.hidden = NO;
        ball.alpha = 1;
        [ball.superview bringSubviewToFront:ball];
    }
}

// ---------- 通道E：UI 兜底 ----------
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
static void BypassV6Init(void) {
    // 通道A（核心，最先）：写全局激活标志 → 面板创建的门打开
    PatchActivationFlags();
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

    // 通道C：hook 面板 initWithFrame 强制显示
    Class panelCls = objc_getClass("_0xB1D7F3A9");
    if (panelCls) {
        Method m = class_getInstanceMethod(panelCls, @selector(initWithFrame:));
        if (m) {
            orig_panelInit = method_getImplementation(m);
            method_setImplementation(m, (IMP)Hook_panelInit);
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

    // 通道D：延迟强制显示（多轮，覆盖不同初始化时机）
    for (int delay = 2; delay <= 12; delay += 2) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(delay*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ ForceShowPanel(); });
    }
}
