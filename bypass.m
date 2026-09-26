/*
 * bypass.m v4 — 弹窗 verify 全链 inline hook（修复版）
 *
 * 反编译结论（Ghidra，可信）：
 *   弹窗【无条件显示】，输入卡密后走 ck_lic::R_axIny_Verify(0xa944) 的完成块
 *   (block_invoke @0xbcd8)：
 *     ParsePlaintext(0xc5a8) -> IsSuccess(0xc704) -> HasSuspiciousExpire(0xc904)
 *     -> MaterializeFields(0xcbc8) -> DeriveSessionKey(0xcd28) -> 成功:
 *        PersistActivation + LoadSession + MarkVerified(0xcfd0) + DispatchUnlock(0xd1d8)
 *   失败路径打 [LIC-1] 网络或解密失败。
 *   由于没有服务器，fetch 必失败，所以一直卡 "[LIC-1] 网络或解密失败"。
 *
 *   MarkVerified 会对会话调用 r_aXiNy_VerifySeal(0x1648c) + r_aXiNy_CanarySeal(0x1666c)
 *   做签名校验，任一返回 0 就 ClearVerified()（打掉也白搭）。
 *
 * 本文件对上述所有判定函数做 inline hook，让 verify 无论服务器返回什么
 * 都直接走成功路径（用本地造的 32 字节会话密钥），从而：
 *   - 弹窗关闭（verify 成功）
 *   - 会话标记已验证、解锁菜单/悬浮球
 *
 * 编译：
 *   xcrun --sdk iphoneos clang -arch arm64 -dynamiclib -O2 -fobjc-arc \
 *         -framework Foundation -o bypass.dylib bypass.m
 */
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/kern_return.h>
#import <string.h>

static uintptr_t sBase = 0;
static NSData *sSession = nil;

static uintptr_t find_base(void)
{
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "Zhuanz"))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

static void patch8(uintptr_t base, uint32_t off, const uint8_t patch[8])
{
    uintptr_t va = base + off;
    vm_address_t page = va & ~(vm_page_size - 1);
    vm_size_t size = vm_page_size;
    kern_return_t kr = vm_protect(mach_task_self(), page, size, 0,
            VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) return;

    memcpy((void*)va, patch, 8);

    kr = vm_protect(mach_task_self(), page, size, 0, VM_PROT_READ|VM_PROT_EXECUTE);
}

/* mov w0,#imm ; ret */
static void patch_ret(uintptr_t base, uint32_t off, uint32_t imm)
{
    uint8_t p[8] = {0};
    uint32_t enc = 0x52800000u | ((imm & 0xffff) << 5);
    memcpy(p, &enc, 4);
    p[4]=0xc0; p[5]=0x03; p[6]=0x5f; p[7]=0xd6;
    patch8(base, off, p);
}

/* b target 仅用于镜像内部地址跳转 */
static void patch_branch(uintptr_t base, uint32_t off, uintptr_t target_va)
{
    uintptr_t pc = base + off;
    int64_t delta = (int64_t)(target_va - pc);
    int32_t imm26 = (int32_t)(delta >> 2);
    uint32_t insn = 0x14000000u | ((uint32_t)imm26 & 0x03ffffffu);
    uint8_t p[8] = {0};
    memcpy(p, &insn, 4);
    patch8(base, off, p);
}

static void do_unlock(void)
{
    uintptr_t base = find_base();
    if (!base) return;
    sBase = base;

    static const unsigned char keyb[32] = {
        0x58,0xfd,0x32,0xab,0xb3,0x93,0x07,0x5c,0x60,0x6a,0x24,0xb1,0xc9,0xc1,0x00,0x71,
        0x49,0x2b,0x42,0xc7,0x93,0xe8,0x16,0x1f,0xab,0xe5,0x16,0xe0,0xca,0xe1,0xcf,0xe7
    };
    if (!sSession)
        sSession = [NSData dataWithBytes:keyb length:32];

    /* ----1.绕过block_invoke网络nil空检查，强制跳入解析路径 0xbe4c---- */
    patch_branch(base, 0xbd38, base + 0xbe4c);

    /* ----2.全部校验函数直接返回成功---- */
    patch_ret(base, 0xc5a8, 0);   /* ParsePlaintext -> 0 */
    patch_ret(base, 0xc704, 1);   /* IsSuccess -> 1 */
    patch_ret(base, 0xc904, 0);   /* HasSuspiciousExpire -> 0 */
    patch_ret(base, 0xcbc8, 1);   /* MaterializeFields -> 1 */

    /* DeriveSessionKey(0xcd28):直接补丁mov x0,#固定session地址;ret，不能b跳外部C函数 */
    uint64_t sessPtr = (uint64_t)(__bridge void*)sSession;
    uint8_t ds_patch[8];
    // mov x0, #sessPtr低16位 ; movk x0,#sessPtr高48位 ; ret
    uint32_t mov0 = 0x52800000 | ((sessPtr & 0xFFFF) <<5);
    uint32_t movk1 = 0xf2a00000 | (((sessPtr >>16) &0xFFFF) <<5);
    memcpy(ds_patch+0, &mov0,4);
    memcpy(ds_patch+4, &movk1,4);
    patch8(base,0xcd28,ds_patch);

    /* ----3.seal签名校验全部放行---- */
    patch_ret(base, 0x1648c, 1);  /* r_aXiNy_VerifySeal ->1 */
    patch_ret(base, 0x1666c, 1);  /* r_aXiNy_CanarySeal ->1 */

    /* ----4.全局BSS状态，去掉CFBridgingRetain，避免内存泄漏---- */
    *(__unsafe_unretained NSData **)(base + 0x12a00b0) = sSession; /* gMenuUnlockKey */
    *(uint64_t *)(base + 0x12a00c0) = 0;                           /* expireTS=0 */
    *(volatile uint8_t *)(base + 0x12a01d2) = 0x00;
    *(volatile uint8_t *)(base + 0x1eba70)  = 0x01;
    *(volatile uint8_t *)(base + 0x12a01d3) = 0x00;
    *(volatile uint8_t *)(base + 0x1eba71)  = 0x01;

    /* ----5.总闸函数返回true---- */
    patch_ret(base, 0xfa374, 1);   /* HasMenuUnlockKey -> TRUE */
    patch_ret(base, 0x121b04, 0);
    patch_ret(base, 0x121c1c, 0);
    patch_ret(base, 0x667c8, 1);   /* isEnabledForKey -> TRUE */
}

__attribute__((constructor))
static void bypass_init(void)
{
    //延迟0.4秒执行，等待目标镜像所有ctor(优先级101)初始化完成
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(),^{
        do_unlock();
    });
}
