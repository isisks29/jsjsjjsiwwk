/*
 * bypass.m — 授权靶场 dylib 解锁（本地可做的全部）
 *
 * == 本次深入分析得出的重要结论 ==
 *  1) 方法表【没有混淆】。之前把 types 指针误当成 imp（imp 在条目 +16 处）。
 *     真实实现：
 *        CK_R_aX1ny_FloatBall +Ra_x1nY_Install        = 0x239a4
 *        CK_R_axI1nY_Features +Ra_x1nY_InstallBuiltin = 0x21a9c
 *     而 0x239a4 / 0x21a9c 都是【空 stub】（只保存参数就 ret）。
 *     → 调用 Ra_x1nY_Install 在测试版1 上【什么都不会发生】。
 *       同学 KamiGate"调 install 出悬浮球"的做法在测试版1 上无效
 *       （那是测试版2 的差异：测试版2 的 install 是真实实现）。
 *
 *  2) 验证是 LIC 授权系统，弹窗文字实为
 *        "[LIC-1] 网络或解密失败"（解密失败，不是"验证失败"）。
 *     本地卡密关(弹"卡密不存在")已被下面 4 个全局绕过（实测弹窗推进），
 *     剩余闸门是【已验证会话对象】(全局 0x12912a8，本 dylib 唯一写入点
 *     0x2c298，由函数 0x2bf24 计算写入)。它由服务器 blob 解密+派生而来，
 *     无法凭空构造（读取处会对其发消息，写错值会闪退）。
 *
 *  3) 因此本文件做的是【本地能做的全部】：把验证流程从"卡密不存在"
 *     推进到"[LIC-1] 网络或解密失败"。完整解锁需拿到有效 blob/会话。
 *
 * 编译：
 *   xcrun --sdk iphoneos clang -arch arm64 -dynamiclib -O2 -fobjc-arc \
 *         -framework Foundation -o bypass.dylib bypass.m
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <string.h>

static uintptr_t image_base_of(const void *ptr)
{
    uintptr_t p = (uintptr_t)ptr;
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        uintptr_t base = (uintptr_t)h;
        if (p < base) continue;
        uintptr_t vmsize = 0;
        const uint8_t *cur = (const uint8_t *)(base + sizeof(struct mach_header_64));
        for (uint32_t j = 0; j < h->ncmds; j++) {
            const struct load_command *c = (const struct load_command *)cur;
            if (c->cmd == LC_SEGMENT_64)
                vmsize += ((const struct segment_command_64 *)c)->vmsize;
            cur += c->cmdsize;
        }
        if (p >= base && p < base + vmsize) return base;
    }
    return 0;
}

static uintptr_t find_target_base(void)
{
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "Zhuanz"))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    void *sym = dlsym(RTLD_DEFAULT, "_JH_OnLicenseChange");
    if (!sym) sym = dlsym(RTLD_DEFAULT, "_JH_OnHeartbeat");
    if (sym) return image_base_of(sym);
    return 0;
}

/* 写 4 个解锁全局：magic1/magic2 + proof1/proof2（本地校验关绕过，
 * 实测把弹窗从"卡密不存在"推进到"[LIC-1] 网络或解密失败"）。 */
static void write_unlock_globals(uintptr_t base)
{
    if (!base) return;
    volatile uint32_t *magic = (volatile uint32_t *)(base + 0x1291248);
    magic[0] = 0x7a31c9e5u;  /* magic1 @0x1291248 */
    magic[1] = 0xb4f27e13u;  /* magic2 @0x129124c */
    volatile uint32_t *proof = (volatile uint32_t *)(base + 0x1291048);
    proof[0] = 0xa4835821u;  /* proof1 @0x1291048 */
    proof[1] = 0x8958d9aeu;  /* proof2 @0x129104c */
}

/* 最佳尝试调 install（测试版1 上是空 stub，多半无效；留着无害，
 * 万一你的 dylib 版本里 install 是真实实现则能直接解锁）。 */
static void call_install_on(Class cls)
{
    if (!cls) return;
    SEL sInstall = NSSelectorFromString(@"Ra_x1nY_Install");
    SEL sBuiltin = NSSelectorFromString(@"Ra_x1nY_InstallBuiltin");
    SEL sShared  = NSSelectorFromString(@"sharedInstance");
    SEL sSharedAlt = NSSelectorFromString(@"shared");
    @try {
        if ([cls respondsToSelector:sInstall])
            ((void (*)(id, SEL))objc_msgSend)(cls, sInstall);
        else if ([cls respondsToSelector:sBuiltin])
            ((void (*)(id, SEL))objc_msgSend)(cls, sBuiltin);
        else {
            id inst = nil;
            if ([cls respondsToSelector:sShared])
                inst = ((id (*)(id, SEL))objc_msgSend)(cls, sShared);
            else if ([cls respondsToSelector:sSharedAlt])
                inst = ((id (*)(id, SEL))objc_msgSend)(cls, sSharedAlt);
            if (inst) {
                if ([inst respondsToSelector:sInstall])
                    ((void (*)(id, SEL))objc_msgSend)(inst, sInstall);
                else if ([inst respondsToSelector:sBuiltin])
                    ((void (*)(id, SEL))objc_msgSend)(inst, sBuiltin);
            }
        }
    } @catch (NSException *e) { }
}

static void try_install_menu(void)
{
    call_install_on(NSClassFromString(@"CK_R_aX1ny_FloatBall"));
    call_install_on(NSClassFromString(@"CK_R_axI1nY_Features"));
}

static void do_unlock(void)
{
    write_unlock_globals(find_target_base());
}

static void schedule_installs(void)
{
    double delays[] = {0.3, 0.8, 1.5, 2.5, 4.0, 6.0, 9.0, 13.0};
    for (unsigned i = 0; i < sizeof(delays)/sizeof(delays[0]); i++) {
        double d = delays[i];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(d * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            do_unlock();
            try_install_menu();
        });
    }
}

static void on_add_image(const struct mach_header *h, intptr_t slide)
{
    (void)h; (void)slide;
    do_unlock();
}

__attribute__((constructor))
static void bypass_init(void)
{
    do_unlock();
    _dyld_register_func_for_add_image(on_add_image);
    schedule_installs();
}
