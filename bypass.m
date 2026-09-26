/*
 * bypass.c — 授权靶场 dylib 非侵入式解锁（借鉴 KamiGate 的解锁机制，去掉卡密门槛）
 *
 * 原理：同学 KamiGate 的解锁本质 = 动态找到目标菜单类 CK_R_aX1ny_FloatBall，
 *       调用其 Ra_x1nY_Install 方法让菜单直接可用。完全不修改目标 dylib 的
 *       代码字节，所以不会触发目标的自校验/反篡改（这是你之前文件补丁/运行时
 *       补丁都闪退的原因）。
 *
 * 本版本去掉了 KamiGate 的"卡密"门槛（那套是版本绑定的，测试版1输卡密才报
 * error）。直接调 install，类方法找不到就回退到单例实例方法。
 *
 * 编译（GitHub Actions / macOS）：
 *   xcrun --sdk iphoneos clang -arch arm64 -dynamiclib \
 *         -framework Foundation -o bypass.dylib bypass.c
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dispatch/dispatch.h>
#include <objc/message.h>

static void try_install_menu(void) {
    Class cls = NSClassFromString(@"CK_R_aX1ny_FloatBall");
    if (!cls) {
        NSLog(@"[bypass] menu class CK_R_aX1ny_FloatBall not found");
        return;
    }
    SEL selInstall     = NSSelectorFromString(@"Ra_x1nY_Install");
    SEL selInstallB    = NSSelectorFromString(@"Ra_x1nY_InstallBuiltin");
    SEL selShared      = NSSelectorFromString(@"sharedInstance");
    SEL selSharedAlt   = NSSelectorFromString(@"shared");

    /* 1) 先按类方法调（同学 KamiGate 就是类方法调用，测试版2可用） */
    BOOL didClass = NO;
    if ([cls respondsToSelector:selInstall]) {
        NSLog(@"[bypass] calling +[CK_R_aX1ny_FloatBall Ra_x1nY_Install]");
        ((void (*)(id, SEL))objc_msgSend)(cls, selInstall);
        didClass = YES;
    } else if ([cls respondsToSelector:selInstallB]) {
        NSLog(@"[bypass] calling +[CK_R_aX1ny_FloatBall Ra_x1nY_InstallBuiltin]");
        ((void (*)(id, SEL))objc_msgSend)(cls, selInstallB);
        didClass = YES;
    }

    /* 2) 类方法不可用时，尝试拿单例实例再调实例方法 */
    id inst = nil;
    if ([cls respondsToSelector:selShared]) {
        inst = ((id (*)(id, SEL))objc_msgSend)(cls, selShared);
    } else if ([cls respondsToSelector:selSharedAlt]) {
        inst = ((id (*)(id, SEL))objc_msgSend)(cls, selSharedAlt);
    }

    if (inst) {
        if ([inst respondsToSelector:selInstall]) {
            NSLog(@"[bypass] calling -[CK_R_aX1ny_FloatBall Ra_x1nY_Install] (instance)");
            ((void (*)(id, SEL))objc_msgSend)(inst, selInstall);
            didClass = YES;
        } else if ([inst respondsToSelector:selInstallB]) {
            NSLog(@"[bypass] calling -[CK_R_aX1ny_FloatBall Ra_x1nY_InstallBuiltin] (instance)");
            ((void (*)(id, SEL))objc_msgSend)(inst, selInstallB);
            didClass = YES;
        }
    }

    NSLog(@"[bypass] unlock done, class-call=%d", (int)didClass);
}

static void run_unlock(void) {
    try_install_menu();
}

/* 目标镜像后加载时兜底 */
static void on_add_image(const struct mach_header *h, intptr_t slide) {
    (void)h; (void)slide;
    run_unlock();
}

__attribute__((constructor))
static void bypass_init(void) {
    run_unlock();
    _dyld_register_func_for_add_image(on_add_image);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        run_unlock();
    });
}
