/*
 * bypass.m — 授权靶场 dylib 深度解锁版（数据全局写入，不改代码，无反篡改风险）
 *
 * 经过对靶场 dylib 的反汇编分析，解锁的真正开关是 4 个 __bss 数据全局：
 *   magic1(0x1291248)=0x7a31c9e5    —— 总闸 session 检查 (0x209b8)
 *   magic2(0x129124c)=0xb4f27e13    —— 菜单解锁检查 (0x209e8)
 *   proof1(0x1291048)=0xa4835821    —— 总闸成功路径写入的 proof 组合
 *   proof2(0x129104c)=0x8958d9ae    —— 总闸成功路径写入的 proof2 组合
 *
 * 菜单解锁判定 (0x1d700) 会实时校验 magic2 + 读这两个 proof 全局做异或，
 * 只有和总闸成功时写入的数值一致才判定"已解锁"。把这 4 个全局写成解锁态，
 * 靶场自己的代码就会认为授权通过并自行解锁菜单 —— 全程只改数据，不碰代码。
 *
 * 注意：不要额外设置 NSUserDefaults 的 twbypass_activation_v1 / twbypass_session_v1，
 *       否则菜单检查实时重算的 proof2 会变，导致 proof 全局校验不一致而失效。
 *
 * 编译（GitHub Actions / macOS，iPhone arm64 动态库）：
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

/* 找到包含指定地址的镜像基址（遍历镜像段范围） */
static uintptr_t image_base_of(const void *ptr)
{
    uintptr_t p = (uintptr_t)ptr;
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        uintptr_t base = (uintptr_t)h;
        if (p < base) continue;
        uintptr_t vmsize = 0;
        const struct load_command *lc = (const struct load_command *)(base + sizeof(struct mach_header_64));
        const uint8_t *cur = (const uint8_t *)lc;
        for (uint32_t j = 0; j < h->ncmds; j++) {
            const struct load_command *c = (const struct load_command *)cur;
            if (c->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)c;
                vmsize += sg->vmsize;
            }
            cur += c->cmdsize;
        }
        if (p >= base && p < base + vmsize) return base;
    }
    return 0;
}

/* 定位靶场 dylib 的镜像基址 */
static uintptr_t find_target_base(void)
{
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "Zhuanz"))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    /* 兜底：用靶场唯一导出符号反查镜像 */
    void *sym = dlsym(RTLD_DEFAULT, "_JH_OnLicenseChange");
    if (!sym) sym = dlsym(RTLD_DEFAULT, "_JH_OnHeartbeat");
    if (sym) return image_base_of(sym);
    return 0;
}

/* 写入 4 个解锁全局（纯数据写，无反篡改） */
static void write_unlock_globals(uintptr_t base)
{
    if (!base) return;
    volatile uint32_t *magic = (volatile uint32_t *)(base + 0x1291248);
    magic[0] = 0x7a31c9e5u;   /* +0x1291248 magic1 */
    magic[1] = 0xb4f27e13u;   /* +0x129124c magic2 */
    volatile uint32_t *proof = (volatile uint32_t *)(base + 0x1291048);
    proof[0] = 0xa4835821u;   /* +0x1291048 proof 组合 */
    proof[1] = 0x8958d9aeu;   /* +0x129104c proof2 组合 */
}

/* 可选：触发菜单安装（在解锁态下调用，理论上安全；失败也不致命） */
static void try_install_menu(void)
{
    @try {
        Class cls = NSClassFromString(@"CK_R_aX1ny_FloatBall");
        if (!cls) return;
        SEL sInstall = NSSelectorFromString(@"Ra_x1nY_Install");
        if ([cls respondsToSelector:sInstall]) {
            ((void (*)(id, SEL))objc_msgSend)(cls, sInstall);
        } else {
            SEL sBuiltin = NSSelectorFromString(@"Ra_x1nY_InstallBuiltin");
            if ([cls respondsToSelector:sBuiltin])
                ((void (*)(id, SEL))objc_msgSend)(cls, sBuiltin);
        }
    } @catch (NSException *e) {
        /* 吞掉异常，绝不闪退 */
    }
}

static void do_unlock(void)
{
    uintptr_t base = find_target_base();
    if (!base) return;
    write_unlock_globals(base);
    /* 写完后，主线程异步触发一次菜单安装 */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ try_install_menu(); });
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
    /* 多次重试，确保靶场已加载 */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ do_unlock(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ do_unlock(); });
}
