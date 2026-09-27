// ============================================================
//  ace 靶场卡密验证绕过 dylib · v3（UI 拦截 + 状态伪造 + 网络兜底）
//  目标文件：ace-第四课-授权靶场.dylib（仓库靶场本身）
//
//  真实链路（逆向确认）：
//    卡密弹窗 _0x37C8E2B6 (textField)
//      → 提交：构造 {device_model, system_version, resolution, udid,
//                  device_name, version, encrypted_key}
//      → HTTP POST 到加密 URL（服务器校验）
//      → 响应 AES 加密 {encrypted_data, iv}，解密后判活
//      → 失败：alertController 弹"卡密不存在"
//      → 成功：写 keychain(service=com.apple.LSDocumentRegistry,
//                         account=com.apple.identitytoken.v4)
//              + 记录激活时间 + isProtectionActive=YES
//
//  v3 策略（多层兜底，不依赖服务器响应格式）：
//    第1层 UI 拦截：alertController 检测到"不存在/失败/错误/无效"→
//                   替换为"激活成功"，同时写 keychain 模拟成功
//    第2层 状态伪造：isProtectionActive→YES，keychain 读→非空
//    第3层 网络兜底：NSURLSession 拦截卡密请求→直接成功回调
//    第4层 保护抑制：心跳/自杀/检测→noop/NO
// ============================================================
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>

// ---------- 通用替换 ----------
static void NoopVoid(id self, SEL _cmd, ...) { return; }
static BOOL ReturnYES(id self, SEL _cmd, ...) { return YES; }
static BOOL ReturnNO(id self, SEL _cmd, ...) { return NO; }

// keychain 判活：永远非空（兼容 q4 判活）
static NSString *FakePassword(id self, SEL _cmd, NSString *service, NSString *account) {
    return @"ACTIVATED_V3";
}

// 写 keychain 模拟成功激活
static void WriteActivationKeychain(void) {
    Class keychain = objc_getClass("_0xD5A13E79");
    if (!keychain) keychain = NSClassFromString(@"SAMKeychain");
    if (!keychain) return;
    NSString *service = @"com.apple.LSDocumentRegistry";
    NSString *account = @"com.apple.identitytoken.v4";
    NSString *password = @"ACTIVATED_BY_BYPASS_V3";
    // 尝试带 error 和不带 error 两种签名
    SEL sel1 = NSSelectorFromString(@"setPassword:forService:account:error:");
    SEL sel2 = NSSelectorFromString(@"setPassword:forService:account:");
    if ([keychain respondsToSelector:sel1]) {
        NSError *err = nil;
        ((void(*)(id,SEL,id,id,id,id*))objc_msgSend)(keychain, sel1, password, service, account, &err);
    } else if ([keychain respondsToSelector:sel2]) {
        ((void(*)(id,SEL,id,id,id))objc_msgSend)(keychain, sel2, password, service, account);
    }
}

// 判断是否是卡密错误弹窗
static BOOL IsCardErrorMsg(NSString *msg) {
    if (!msg || ![msg isKindOfClass:[NSString class]]) return NO;
    NSArray *keywords = @[@"不存在",@"失败",@"错误",@"无效",@"过期",@"已使用",
                          @"卡密",@"激活",@"not exist",@"invalid",@"failed",@"error"];
    for (NSString *kw in keywords) {
        if ([msg rangeOfString:kw options:NSCaseInsensitiveSearch].location != NSNotFound)
            return YES;
    }
    return NO;
}

// 隐藏卡密输入弹窗（激活成功后调用）
static void HideCardDialog(void) {
    Class cardCls = objc_getClass("_0x37C8E2B6");
    if (!cardCls) return;
    // 遍历 keyWindow 的子视图，找到卡密弹窗并隐藏
    UIWindow *win = [[UIApplication sharedApplication] keyWindow];
    if (!win) return;
    for (UIView *v in [win subviews]) {
        if ([v isKindOfClass:cardCls]) {
            v.hidden = YES;
            [v removeFromSuperview];
        }
    }
}

// ---------- 第1层：UI 拦截 ----------
static UIAlertController *(*orig_alertCtrl)(id, SEL, NSString*, NSString*, UIAlertControllerStyle);
static UIAlertController *Hook_alertCtrl(id self, SEL _cmd, NSString *title,
                                          NSString *message, UIAlertControllerStyle style) {
    if (IsCardErrorMsg(message) || IsCardErrorMsg(title)) {
        WriteActivationKeychain();
        HideCardDialog();
        UIAlertController *ac = orig_alertCtrl(self, _cmd, @"激活成功", @"卡密验证通过，功能已解锁", style);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [ac dismissViewControllerAnimated:YES completion:nil];
        });
        return ac;
    }
    return orig_alertCtrl(self, _cmd, title, message, style);
}

// initWithTitle:message: 兜底（某些版本用这个初始化）
static id (*orig_alertInit)(id, SEL, NSString*, NSString*);
static id Hook_alertInit(id self, SEL _cmd, NSString *title, NSString *message) {
    if (IsCardErrorMsg(message) || IsCardErrorMsg(title)) {
        WriteActivationKeychain();
        HideCardDialog();
        return orig_alertInit(self, _cmd, @"激活成功", @"卡密验证通过，功能已解锁");
    }
    return orig_alertInit(self, _cmd, title, message);
}

// ---------- 第3层：网络兜底（拦截卡密请求直接成功） ----------
static NSURLSessionDataTask *(*orig_dataTaskWithRequest)(id, SEL, NSURLRequest*, void(^)(NSData*, NSURLResponse*, NSError*));
static NSURLSessionDataTask *Hook_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req,
                                                       void(^completion)(NSData*, NSURLResponse*, NSError*)) {
    // 检测是否是卡密校验请求（请求体包含 encrypted_key）
    BOOL isCardRequest = NO;
    NSData *body = req.HTTPBody;
    if (body) {
        NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (bodyStr && [bodyStr rangeOfString:@"encrypted_key"].location != NSNotFound) {
            isCardRequest = YES;
        }
    }
    if (!isCardRequest) {
        return orig_dataTaskWithRequest(self, _cmd, req, completion);
    }
    // 卡密请求：直接模拟成功
    WriteActivationKeychain();
    // 构造伪造的成功响应
    NSDictionary *fakeResp = @{@"status": @"open", @"code": @1, @"data": @{@"status": @"open"}};
    NSData *respData = [NSJSONSerialization dataWithJSONObject:fakeResp options:0 error:nil];
    NSHTTPURLResponse *httpResp = [[NSHTTPURLResponse alloc] initWithURL:req.URL
                                                              statusCode:200
                                                             HTTPVersion:@"HTTP/1.1"
                                                            headerFields:@{@"Content-Type":@"application/json"}];
    if (completion) completion(respData, httpResp, nil);
    // 返回一个 dummy task
    return [[NSURLSessionDataTask alloc] init];
}

// ---------- 工具：枚举全部类按 selector 换实现 ----------
static void SwizzleOnAllClasses(NSArray<NSString*> *selectors, IMP imp, BOOL instance) {
    int count = objc_getClassList(NULL, 0);
    Class *buf = malloc(sizeof(Class) * (count > 0 ? count : 1));
    objc_getClassList(buf, count);
    for (NSString *sn in selectors) {
        SEL sel = NSSelectorFromString(sn);
        for (int i = 0; i < count; i++) {
            Class cls = buf[i];
            if (!cls) continue;
            Method m = instance ? class_getInstanceMethod(cls, sel) : class_getClassMethod(cls, sel);
            if (m) method_setImplementation(m, imp);
        }
    }
    free(buf);
}

__attribute__((constructor))
static void BypassV3Init(void) {
    // 第2层：状态伪造
    SwizzleOnAllClasses(@[@"isProtectionActive"], (IMP)ReturnYES, YES);
    SwizzleOnAllClasses(@[@"isShuttingDown"], (IMP)ReturnNO, YES);
    SwizzleOnAllClasses(@[@"setIsProtectionActive:"], (IMP)NoopVoid, YES);

    // 第4层：保护抑制
    SwizzleOnAllClasses(@[
        @"forceExitWithReason:", @"cleanupAndExit:", @"cleanupSensitiveData",
        @"showBanAlertWithReason:", @"showServerClosedAlert:",
        @"showVersionUpdateAlert:", @"showServerMessage:", @"stopProtection",
    ], (IMP)NoopVoid, YES);
    SwizzleOnAllClasses(@[
        @"startHeartbeatTimer", @"performHeartbeat", @"checkHeartbeatHealth",
    ], (IMP)NoopVoid, YES);
    SwizzleOnAllClasses(@[
        @"isJailbroken", @"detectInjectedLibraries", @"detectTweakInject",
        @"detectSuspiciousFrameworks", @"performFullDetection",
    ], (IMP)ReturnNO, YES);

    // keychain 判活（q4 读取时永远非空）
    SwizzleOnAllClasses(@[@"passwordForService:account:"], (IMP)FakePassword, YES);
    SwizzleOnAllClasses(@[@"passwordForService:account:error:"], (IMP)FakePassword, YES);
    SwizzleOnAllClasses(@[@"q17"], (IMP)NoopVoid, YES);

    // 第1层：UI 拦截（两种 alert 创建方式都 hook）
    Class ac = objc_getClass("UIAlertController");
    if (ac) {
        Method m1 = class_getClassMethod(ac, @selector(alertControllerWithTitle:message:preferredStyle:));
        if (m1) {
            orig_alertCtrl = (void*)method_getImplementation(m1);
            method_setImplementation(m1, (IMP)Hook_alertCtrl);
        }
        Method m2 = class_getInstanceMethod(ac, @selector(initWithTitle:message:));
        if (m2) {
            orig_alertInit = (void*)method_getImplementation(m2);
            method_setImplementation(m2, (IMP)Hook_alertInit);
        }
    }

    // 第3层：网络兜底
    Class session = objc_getClass("NSURLSession");
    if (session) {
        Method m = class_getInstanceMethod(session, @selector(dataTaskWithRequest:completionHandler:));
        if (m) {
            orig_dataTaskWithRequest = (void*)method_getImplementation(m);
            method_setImplementation(m, (IMP)Hook_dataTaskWithRequest);
        }
    }

    // 启动时预写 keychain（防止首次启动就弹卡密框）
    WriteActivationKeychain();
}
