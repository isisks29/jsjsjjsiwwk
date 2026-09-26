#import <Foundation/Foundation.h>
#import <objc/message.h>

static void attempt_unlock(void)
{
    @try {
        Class cls = NSClassFromString(@"CK_R_aX1ny_FloatBall");
        if (!cls) return;

        // 提前写好靶场的 bypass 开关（无害，很多版本需要）
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        [ud setObject:@"1" forKey:@"twbypass_activation_v1"];
        [ud setObject:@"1" forKey:@"twbypass_session_v1"];
        [ud synchronize];

        SEL sInstall  = NSSelectorFromString(@"Ra_x1nY_Install");
        SEL sBuiltin  = NSSelectorFromString(@"Ra_x1nY_InstallBuiltin");
        SEL sShared   = NSSelectorFromString(@"sharedInstance");
        SEL sSharedAlt= NSSelectorFromString(@"shared");

        // 1) 类方法
        if ([cls respondsToSelector:sInstall]) {
            ((void (*)(id, SEL))objc_msgSend)(cls, sInstall);
        } else if ([cls respondsToSelector:sBuiltin]) {
            ((void (*)(id, SEL))objc_msgSend)(cls, sBuiltin);
        }
        // 2) 类方法没有 → 单例实例方法
        id inst = nil;
        if ([cls respondsToSelector:sShared]) {
            inst = ((id (*)(id, SEL))objc_msgSend)(cls, sShared);
        } else if ([cls respondsToSelector:sSharedAlt]) {
            inst = ((id (*)(id, SEL))objc_msgSend)(cls, sSharedAlt);
        }
        if (inst) {
            if ([inst respondsToSelector:sInstall]) {
                ((void (*)(id, SEL))objc_msgSend)(inst, sInstall);
            } else if ([inst respondsToSelector:sBuiltin]) {
                ((void (*)(id, SEL))objc_msgSend)(inst, sBuiltin);
            }
        }
    } @catch (NSException *e) {
        // 吞掉异常，绝不闪退
    }
}

__attribute__((constructor))
static void bypass_init(void)
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ attempt_unlock(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ attempt_unlock(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ attempt_unlock(); });
}
