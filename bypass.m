/*
 * bypass.m — 授权靶场 dylib 解锁（写全局 + 稳健触发悬浮球安装）
 *
 * 已确认（对测试版1 静态分析）：
 *   - 类  CK_R_aX1ny_FloatBall      有类方法 Ra_x1nY_Install
 *   - 类  CK_R_axI1nY_Features      有类方法 Ra_x1nY_InstallBuiltin
 *   - 靶场方法表是混淆的（imp 指向 __objc_methtype），运行时才解混淆，
 *     因此调 install 必须在解混淆完成后，本版用长窗口多次重试覆盖。
 *
 * 第一步：写 4 个解锁全局（本地校验通过，弹窗可从"卡密不存在"推进到
 *         "网络或验证失败"，证明生效）。
 * 第二步：跨类、跨时机、主线程多次尝试调 Ra_x1nY_Install / InstallBuiltin，
 *         让悬浮球显现（复刻同学 KamiGate 的解锁动作）。
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

static void write_unlock_globals(uintptr_t base)
{
    if (!base) return;
    volatile uint32_t *magic = (volatile uint32_t *)(base + 0x1291248);
    magic[0] = 0x7a31c9e5u;
    magic[1] = 0xb4f27e13u;
    volatile uint32_t *proof = (volatile uint32_t *)(base + 0x1291048);
    proof[0] = 0xa4835821u;
    proof[1] = 0x8958d9aeu;
}

/* 跨两个类、类方法优先、单例实例回退，调用 install */
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
    } @catch (NSException *e) { /* 吞异常，绝不闪退 */ }
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

/* 在多次延迟点触发 install（覆盖靶场解混淆/初始化完成后的时机） */
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
