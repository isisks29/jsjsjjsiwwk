/*
 * bypass.c — 绕过「Zhuanz-第四课-授权靶场.dylib」授权验证的旁路 dylib
 * ===================================================================
 * 任务目标：编译一个 dylib 绕过靶场 dylib 的验证系统，使其功能直接可用。
 *
 * 原理（基于静态分析结论）：
 *   靶场 dylib 的"功能是否可用"由两条判定链决定：
 *     ① isMenuUnlocked (0xfa374) —— 检查 32 字节会话密钥 + 过期时间，
 *        被菜单安装(0x15680c)与功能开关(0xad5d4/0xad734/0x2efe8)调用。
 *     ② jh_activate_bypass (0x18fe4) —— 两道 proof 通过后才写入
 *        "已认证会话"状态并递增会话计数器，供内存挂钩安装器读取。
 *   本 dylib 在加载时对这两处指令做等价改写：
 *     ① 0xfa374  -> mov w0,#1; ret           （恒判定已解锁）
 *     ② 0x19000  -> nop                       （不再因参数为空拒绝）
 *        0x19018  -> nop                       （不再因长度<32 拒绝）
 *        0x19024  -> b  #0x19044               （强制跳过状态检查）
 *        0x19054  -> b  #0x19074               （强制跳过 session proof）
 *   随后通过 dlsym 调用导出的功能原语 _jh_install_memory_hook /
 *   _jh_enable_fullview / _jh_activate_camera_patch，功能直接可用。
 *
 * 编译（macOS，产物 arm64 dylib）：
 *   clang -arch arm64 -dynamiclib -O2 -fobjc-arc bypass.c -o bypass.dylib
 * 或（iOS）：
 *   xcrun --sdk iphoneos clang -arch arm64 -dynamiclib -O2 -fobjc-arc \
 *         bypass.c -o bypass.dylib
 *
 * 加载方式（任选其一）：
 *   A. DYLD_INSERT_LIBRARIES=bypass.dylib ./宿主App
 *   B. 越狱/trollstore 注入：将 bypass.dylib 与宿主一起加载
 *
 * 说明：靶场 dylib 的 __TEXT vmaddr = 0，运行时指令地址 = 镜像基址 + 虚拟地址。
 *       补丁使用 mach_vm_protect 临时放开写权限，写回后恢复可执行。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/mman.h>

/* 补丁点（虚拟地址，__TEXT vmaddr=0） */
#define P_UNLOCK      0xfa374   /* isMenuUnlocked 入口                     */
#define P_SESS_CBZ    0x19000   /* cbz  x8, #0x1902c  参数为空拒绝          */
#define P_SESS_BLO    0x19018   /* b.lo #0x1902c     长度<32 拒绝           */
#define P_SESS_TBNZ   0x19024   /* tbnz w0,#0,#0x19044 状态检查             */
#define P_SESS_CBNZ   0x19054   /* cbnz w8,#0x19074  session proof 检查     */

/* 新指令字节（小端） */
static const uint8_t BYTES_UNLOCK[8]  = { 0x20,0x00,0x80,0x52,  0xc0,0x03,0x5f,0xd6 }; /* mov w0,#1; ret */
static const uint8_t BYTES_NOP[4]     = { 0x1f,0x20,0x03,0xd5 };                        /* nop            */
static const uint8_t BYTES_B19044[4]  = { 0x08,0x00,0x00,0x14 };                        /* b  #0x19044    */
static const uint8_t BYTES_B19074[4]  = { 0x08,0x00,0x00,0x14 };                        /* b  #0x19074    */

static int already_patched(const uint8_t *p)
{
    return memcmp(p, BYTES_UNLOCK, 8) == 0;
}

/* 写一个补丁：放开所在页写权限 -> 写入 -> 恢复 */
static kern_return_t write_patch(uint8_t *dst, const uint8_t *src, size_t n)
{
    uintptr_t page = (uintptr_t)dst & ~(uintptr_t)0x3fff;
    kern_return_t kr;

    kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                         VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        /* 回退：mprotect；仍失败则中止，避免写入只读页导致崩溃 */
        if (mprotect((void *)page, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
            return kr;
    }
    memcpy(dst, src, n);
    /* 恢复只读可执行（RWX -> RX），保持系统安全姿态 */
    kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                         VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        mprotect((void *)page, 0x4000, PROT_READ | PROT_EXEC);
    }
    return KERN_SUCCESS;
}

/* 对已加载的靶场镜像应用补丁并启用功能 */
static void patch_target_and_enable(const void *header, uintptr_t slide)
{
    uint8_t *base = (uint8_t *)header + slide;   /* __TEXT vmaddr = 0 */

    if (base == NULL || already_patched(base + P_UNLOCK))
        return;                                   /* 幂等：已补过则跳过 */

    write_patch(base + P_UNLOCK,  BYTES_UNLOCK,  8);
    write_patch(base + P_SESS_CBZ, BYTES_NOP,    4);
    write_patch(base + P_SESS_BLO, BYTES_NOP,    4);
    write_patch(base + P_SESS_TBNZ, BYTES_B19044, 4);
    write_patch(base + P_SESS_CBNZ, BYTES_B19074, 4);

    /* —— 功能直接可用：调用导出的功能原语 —— */
    void (*fn_install)(void) = (void (*)(void))dlsym(RTLD_DEFAULT, "_jh_install_memory_hook");
    void (*fn_fullview)(int) = (void (*)(int))dlsym(RTLD_DEFAULT, "_jh_enable_fullview");
    void (*fn_camera)(void)  = (void (*)(void))dlsym(RTLD_DEFAULT, "_jh_activate_camera_patch");

    if (fn_install)  fn_install();
    if (fn_fullview) fn_fullview(1);
    if (fn_camera)   fn_camera();
}

/* 镜像名是否指向靶场 dylib（安装名 @rpath/bsphp.framework/bsphp） */
static int is_target(const char *name)
{
    return name && strstr(name, "bsphp") != NULL;
}

/* 新镜像加载回调：靶场 dylib 作为宿主依赖，晚于本 dylib 加载 */
static void on_add_image(const struct mach_header *mh, intptr_t vmaddr_slide)
{
    uint32_t i, c = _dyld_image_count();
    for (i = 0; i < c; i++) {
        if (_dyld_get_image_header(i) == mh) {
            if (is_target(_dyld_get_image_name(i)))
                patch_target_and_enable(mh, (uintptr_t)vmaddr_slide);
            return;
        }
    }
}

__attribute__((constructor)) static void bypass_ctor(void)
{
    uint32_t i, c = _dyld_image_count();

    /* 情况1：靶场已被加载（例如注入场景）—— 直接修补 */
    for (i = 0; i < c; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (is_target(nm)) {
            patch_target_and_enable(_dyld_get_image_header(i),
                                    (uintptr_t)_dyld_get_image_vmaddr_slide(i));
            return;
        }
    }

    /* 情况2：靶场尚未加载（DYLD_INSERT_LIBRARIES 场景）—— 注册回调 */
    _dyld_register_func_for_add_image(on_add_image);
}
