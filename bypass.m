// ============================================================
//  ace 靶场卡密验证绕过 dylib · v2（真实版：心跳/RSA/自杀保护）
//  依据：老师 blue.dylib（同系列已生效作业）+ knmdbpjwfw（老师 ace 靶场）
//  真实 ace 版保护架构：
//    _0xA7F3B2E9.sharedInstance 保护管理器
//      ├─ startHeartbeatTimer / performHeartbeat / checkHeartbeatHealth  心跳
//      ├─ isProtectionActive / isShuttingDown                           状态
//      └─ forceExitWithReason / cleanupAndExit / showBanAlertWithReason
//           showServerClosedAlert / showVersionUpdateAlert / showServerMessage  失败自杀
//    NetworkManager postEncryptedToPath:params:completion: 加密网络
//    RSA Sigalg Verify（SecKeyCreateWithData）验签
//    isJailbroken / detectInjectedLibraries / detectTweakInject / detectSuspiciousFrameworks  防注入检测
//  绕过策略（全部按 selector 枚举类，版本不同也不怕；保留原启动流程，只压制后果）：
//    isProtectionActive -> YES    检测类 -> NO    自杀/弹窗 -> no-op    心跳 -> no-op
//    另保留 v1 的 keychain/q17 钩子（兼容仓库简化版）
// ============================================================
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

// ---------- 通用替换实现 ----------
static void NoopVoid(id self, SEL _cmd, ...) { return; }
static BOOL ReturnYES(id self, SEL _cmd, ...) { return YES; }
static BOOL ReturnNO(id self, SEL _cmd, ...) { return NO; }
static id ReturnNil(id self, SEL _cmd, ...) { return nil; }

// keychain 判活（仓库简化版）
static NSString *FakePassword(id self, SEL _cmd, NSString *service, NSString *account) {
    return @"ACTIVATED_BY_DOUBAO_BYPASS_V2";
}

// NetworkManager 加密网络：伪造成功回调（result, error 形态）
static void FakeNetworkPost(id self, SEL _cmd, id path, id params, id completion) {
    if (!completion) return;
    id fake = @{
        @"status" : @"open",
        @"code"   : @1,
        @"result" : @1,
        @"data"   : @{ @"status" : @"open" }
    };
    void (^blk)(id, id) = completion;
    blk(fake, nil);
}

// ---------- 工具：枚举全部类并按 selector 换实现 ----------
static void SwizzleOnAllClasses(NSArray<NSString *> *selectors, IMP imp, BOOL instanceMethod) {
    int count = objc_getClassList(NULL, 0);
    Class *buf = (Class *)malloc(sizeof(Class) * (count > 0 ? count : 1));
    objc_getClassList(buf, count);
    for (NSString *selName in selectors) {
        SEL sel = NSSelectorFromString(selName);
        for (int i = 0; i < count; i++) {
            Class cls = buf[i];
            if (!cls) continue;
            Method m = instanceMethod ? class_getInstanceMethod(cls, sel)
                                      : class_getClassMethod(cls, sel);
            if (m) method_setImplementation(m, imp);
        }
    }
    free(buf);
}

__attribute__((constructor))
static void BypassV2Init(void) {
    // 1) 保护状态：永远激活、永不关闭
    SwizzleOnAllClasses(@[@"isProtectionActive"], (IMP)ReturnYES, YES);
    SwizzleOnAllClasses(@[@"isShuttingDown"], (IMP)ReturnNO, YES);
    SwizzleOnAllClasses(@[@"setIsProtectionActive:"], (IMP)NoopVoid, YES);

    // 2) 自杀/封禁/弹窗：全部静默（保留启动流程，仅压制后果）
    SwizzleOnAllClasses(@[
        @"forceExitWithReason:",
        @"cleanupAndExit:",
        @"cleanupSensitiveData",
        @"showBanAlertWithReason:",
        @"showServerClosedAlert:",
        @"showVersionUpdateAlert:",
        @"showServerMessage:",
        @"stopProtection",
    ], (IMP)NoopVoid, YES);

    // 3) 心跳：不联网、不计数、不触发失败退出
    SwizzleOnAllClasses(@[
        @"startHeartbeatTimer",
        @"performHeartbeat",
        @"checkHeartbeatHealth",
    ], (IMP)NoopVoid, YES);

    // 4) 防注入/越狱检测：全部返回 NO
    SwizzleOnAllClasses(@[
        @"isJailbroken",
        @"detectInjectedLibraries",
        @"detectTweakInject",
        @"detectSuspiciousFrameworks",
        @"performFullDetection",
    ], (IMP)ReturnNO, YES);

    // 5) NetworkManager 加密网络：伪造成功
    SwizzleOnAllClasses(@[@"postEncryptedToPath:params:completion:"], (IMP)FakeNetworkPost, YES);

    // 6) keychain 判活（兼容仓库简化版 ace）
    SwizzleOnAllClasses(@[@"passwordForService:account:"], (IMP)FakePassword, YES);
    SwizzleOnAllClasses(@[@"q17"], (IMP)NoopVoid, YES);
}
