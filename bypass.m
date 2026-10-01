











#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach/mach_time.h>

#pragma mark - 靶场镜像定位

static uintptr_t gAce = 0;   // 靶场 dylib 的加载基址（其 vmaddr 从 0 开始）

static void locateAce(void) {
    if (gAce) return;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (!n) continue;
        // 兼容注入后可能被改名的情况
        if (strstr(n, "ace-") || strstr(n, "ace_") ||
            strstr(n, "\xe7\xac\xac\xe5\x9b\x9b\xe8\xaf\xbe") ||   // "第四课"
            strstr(n, "\xe9\x9d\xb6\xe5\x9c\xba")) {              // "靶场"
            gAce = (uintptr_t)_dyld_get_image_header(i);
            break;
        }
    }
}

#pragma mark - a. 抑制卡密弹窗

static IMP gOrigPresent = NULL;

static void hooked_present(id self, SEL _cmd, UIViewController *vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *ac = (UIAlertController *)vc;
        NSString *all = [NSString stringWithFormat:@"%@%@", ac.title ?: @"", ac.message ?: @""];
        BOOL isCardAlert = (ac.textFields.count > 0);          // 带输入框 = 卡密弹窗
        NSArray *kw = @[@"卡", @"激活", @"授权", @"验证", @"失败", @"到期", @"错误", @"购买", @"联系"];
        for (NSString *k in kw) {
            if ([all containsString:k]) { isCardAlert = YES; break; }
        }
        if (isCardAlert) return;   // 直接吞掉，不 present
    }
    ((void (*)(id, SEL, UIViewController *, BOOL, id))gOrigPresent)(self, _cmd, vc, animated, completion);
}

static void installAlertHook(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Method m = class_getInstanceMethod([UIViewController class],
                                           @selector(presentViewController:animated:completion:));
        if (m) {
            gOrigPresent = method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_present);
        }
    });
}

#pragma mark - b/c. 伪造激活状态 + 维护守卫

// 状态结构 S 字段关系（还原自 iconOnClick 0xfac54）:
//   x14=S[0x119a]  x10=S[0x11a2]  x13=S[0x11aa]  x12=S[0x11b2]  x11=S[0x11ba]
//   S[0x78]      = x14 ^ x10 ^ 0xa5c3e1f7b6d2489a
//   S32[0x8e]    = (u32)x13 ^ 0x4a9b5206 ^ (u32)(x14>>7)
//   S32[0x92]    = (u32)x12 ^ 0x8c1a73e5 ^ (u32)(x14>>13)
//   S32[0x00]    = (u32)x11 ^ 0x5f8a16e3 ^ (u32)(x14>>19)
//   S32[0x11c2]  = hash(x10,x13,x12,x11)  (乘 0x45d9f3b7/0x8e4b1395/0x1f3d6a71 链)
static void forgeState(uint8_t *S) {
    uint64_t *p14 = (uint64_t *)(S + 0x119a);
    uint64_t *p10 = (uint64_t *)(S + 0x11a2);
    uint64_t *p13 = (uint64_t *)(S + 0x11aa);
    uint64_t *p12 = (uint64_t *)(S + 0x11b2);
    uint64_t *p11 = (uint64_t *)(S + 0x11ba);
    if (!*p14) *p14 = 0xc6a4a7935bd1e995ull;            // 靶场自写的 magic
    if (!*p10) *p10 = 0x9e3779b97f4a7c15ull;
    if (!*p13) *p13 = 0xc2b2ae3d27d4eb4full;
    if (!*p12) *p12 = 0x165667b19e3779f9ull;
    if (!*p11) *p11 = 0x85ebca6b27d4eb2full;
    uint64_t x14 = *p14, x10 = *p10, x13 = *p13, x12 = *p12, x11 = *p11;

    *(uint64_t *)(S + 0x78)  = x14 ^ x10 ^ 0xa5c3e1f7b6d2489aull;
    *(uint32_t *)(S + 0x8e)  = (uint32_t)x13 ^ 0x4a9b5206u ^ (uint32_t)(x14 >> 7);
    *(uint32_t *)(S + 0x92)  = (uint32_t)x12 ^ 0x8c1a73e5u ^ (uint32_t)(x14 >> 13);
    *(uint32_t *)(S + 0x00)  = (uint32_t)x11 ^ 0x5f8a16e3u ^ (uint32_t)(x14 >> 19);

    uint32_t w = (uint32_t)(x10 >> 32) ^ (uint32_t)x10;
    w *= 0x45d9f3b7u;
    w ^= (uint32_t)x13;  w *= 0x8e4b1395u;
    w ^= (uint32_t)x12;  w *= 0x1f3d6a71u;
    w ^= (uint32_t)x11;  w ^= w >> 16;
    *(uint32_t *)(S + 0x11c2) = w;
}

// 守卫组公式（还原自 iconOnClick / 0x109020 的校验链）:
//   K  = T ^ 0xb75e8052babd72a6
//   V0 = chain((u32)T ^ 0xd18ddb25 ^ (u32)(T>>32))，再 ^ (w>>17)
//   V1 = chain(V0 ^ 0x1767cedc)，w = (u32)T    ^ (w>>17) ^ w
//   V2 = chain(V1 ^ 0x5d41c293)，w = (u32)(T>>32) ^ (w>>17) ^ w
static inline uint32_t guardChain(uint32_t w) {
    w ^= w >> 15;  w *= 0x1f3d6a71u;
    w ^= w >> 11;  w *= 0x8e4b1395u;
    return w;
}

static uint64_t nowTicks(void) {   // 与靶场一致的时间基：mach 时间 → 毫秒
    static mach_timebase_info_data_t tb = {0, 0};
    if (!tb.denom) mach_timebase_info(&tb);
    uint64_t ns = mach_absolute_time() * tb.numer / tb.denom;
    return ns / 1000000ull;
}

static void writeGuardPair(uintptr_t base /* K 的地址 */, uint64_t T) {
    *(uint64_t *)base = T ^ 0xb75e8052babd72a6ull;                 // K
    uint32_t w = (uint32_t)T ^ 0xd18ddb25u ^ (uint32_t)(T >> 32);
    w = guardChain(w);  w ^= w >> 17;
    *(uint32_t *)(base + 8)  = w;                                  // V0
    w = guardChain(w ^ 0x1767cedcu);
    w = ((uint32_t)T ^ (w >> 17)) ^ w;
    *(uint32_t *)(base + 12) = w;                                  // V1
    w = guardChain(w ^ 0x5d41c293u);
    w = ((uint32_t)(T >> 32) ^ (w >> 17)) ^ w;
    *(uint32_t *)(base + 16) = w;                                  // V2
}

#pragma mark - d. 建界面 + 直接点开菜单

static void showMenuNow(void) {
    if (!gAce) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        // 1) 调界面创建函数（内部已"创建过"标记，重复调用安全）
        ((void (*)(void))(gAce + 0x109020))();

        // 2) 找到左上角悬浮球，若菜单未显则触发 iconOnClick 直接显现
        for (UIWindow *win in UIApplication.sharedApplication.windows) {
            NSString *cn = NSStringFromClass(win.class);
            if ([cn containsString:@"_0xD4E9A3C7"]) {
                SEL ctxSel = sel_registerName("_0xE4C8719B");
                SEL tapSel = sel_registerName("iconOnClick");
                if ([win respondsToSelector:ctxSel] && [win respondsToSelector:tapSel]) {
                    void *ctx = ((void *(*)(id, SEL))objc_msgSend)(win, ctxSel);
                    uint8_t visible = ctx ? *(uint8_t *)ctx : 0;   // 首字节 = 菜单显隐标志
                    if (!visible) ((void (*)(id, SEL))objc_msgSend)(win, tapSel);
                }
            }
        }
    });
}

#pragma mark - 主逻辑

static void crackTick(void) {
    locateAce();
    if (!gAce) return;

    // 取/建共享状态结构 S（靶场惰性创建：全局指针在 0x3d6ed0）
    uint8_t **slot = (uint8_t **)(gAce + 0x3d6ed0);
    if (!*slot) {
        uint8_t *S = (uint8_t *)calloc(1, 0x11c6);
        *(int32_t *)S = -1;                                       // 与靶场初始值一致
        *(uint64_t *)(S + 0x119a) = 0xc6a4a7935bd1e995ull;
        __atomic_store_n(slot, S, __ATOMIC_RELEASE);
    }
    uint8_t *S = *slot;

    forgeState(S);                                                // b. 状态伪造
    *(uint32_t *)(gAce + 0x3d6f0c) = 1;                           // 心跳存活标记

    uint64_t T = nowTicks();
    writeGuardPair(gAce + 0x3d6ed8, T);                           // c. 守卫组 A
    writeGuardPair(gAce + 0x3d6eb8, T);                           //    守卫组 B

    showMenuNow();                                                // d. 显出功能界面
}

__attribute__((constructor))
static void bypassInit(void) {
    installAlertHook();                                           // a. 抑弹窗
    // 等靶场加载完成后开始工作，之后每 3 秒刷新一次守卫/补建界面
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        crackTick();
        dispatch_source_t t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                     dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0));
        dispatch_source_set_timer(t, DISPATCH_TIME_NOW, 3ull * NSEC_PER_SEC, 1ull * NSEC_PER_SEC);
        dispatch_source_set_event_handler(t, ^{ crackTick(); });
        dispatch_resume(t);
    });
}
