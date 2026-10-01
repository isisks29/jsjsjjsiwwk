












#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>

// ============================================================
// 关键偏移（相对于模块基址）
// ============================================================

// __bss段偏移
#define BSS_OFFSET          0x3ef470

// 关键变量在__bss中的偏移
#define OFF_LATCH           (0x3ff658 - BSS_OFFSET)  // 0x101E8 验证成功锁存字节
#define OFF_SESSION         (0x3ff698 - BSS_OFFSET)  // 0x10228 会话对象指针
#define OFF_GATE0_SEED      (0x3ff6a0 - BSS_OFFSET)  // 0x10230 门卫块seed
#define OFF_GATE0_A         (0x3ff6a8 - BSS_OFFSET)  // 0x10238
#define OFF_GATE0_B         (0x3ff6ac - BSS_OFFSET)  // 0x1023c
#define OFF_GATE0_C         (0x3ff6b0 - BSS_OFFSET)  // 0x10240

// iconOnClick中的检查点偏移（需要patch跳过）
#define OFF_ICON_CHECK1     0x111dac   // cbz w9, #fail (obj+0x8e==0)
#define OFF_ICON_CHECK2     0x111db4   // cbz w9, #fail (obj+0x92==0)
#define OFF_ICON_CHECK3     0x111dec   // b.ne #fail  (obj+0x78校验)
#define OFF_ICON_CHECK4     0x111e14   // b.ne #fail  (obj+0x8e校验)
#define OFF_ICON_CHECK5     0x111e34   // b.ne #fail  (obj+0x92校验)
#define OFF_ICON_CHECK6     0x111e54   // b.ne #fail  (obj+0x0校验)
#define OFF_EXPIRE_CHECK    0x111d40   // b.hi #fail  (过期检查)

// 验证函数中的检查
#define OFF_VERIFY_CHECK    0x3b2b8    // cbz w8, #fail (0x658==0)

// NOP编码 (arm64)
#define ARM64_NOP           0xd503201f

// ============================================================
// 全局变量
// ============================================================
static IMP g_orig_present = NULL;
static uintptr_t g_module_base = 0;
static BOOL g_armed = NO;

// ============================================================
// 辅助函数
// ============================================================

// 获取模块基址
static uintptr_t findModuleBase(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (name && (strstr(name, "ace") || strstr(name, "ballsace"))) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    // 回退：找包含dylib的模块
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (name && strstr(name, "dylib") && !strstr(name, "libSystem") && !strstr(name, "/usr/")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    return 0;
}

// 写入NOP
static void patchNOP(uintptr_t addr) {
    uint32_t nop = ARM64_NOP;
    vm_address_t page = addr & ~0xFFF;
    vm_size_t size = sizeof(nop);
    vm_protect(mach_task_self(), page, 0x1000, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    memcpy((void*)addr, &nop, sizeof(nop));
}

// 写入字节
static void patchByte(uintptr_t addr, uint8_t val) {
    vm_address_t page = addr & ~0xFFF;
    vm_protect(mach_task_self(), page, 0x1000, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    *(uint8_t*)addr = val;
}

// 写入32位
static void patchWord(uintptr_t addr, uint32_t val) {
    vm_address_t page = addr & ~0xFFF;
    vm_protect(mach_task_self(), page, 0x1000, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    *(uint32_t*)addr = val;
}

// 写入64位
static void patchQWord(uintptr_t addr, uint64_t val) {
    vm_address_t page = addr & ~0xFFF;
    vm_protect(mach_task_self(), page, 0x1000, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    *(uint64_t*)addr = val;
}

// ============================================================
// 门卫块计算（精确匹配反汇编逻辑）
// ============================================================

static void computeGateBlock(uintptr_t bss) {
    uint64_t* pSeed = (uint64_t*)(bss + OFF_GATE0_SEED);
    uint32_t* pA = (uint32_t*)(bss + OFF_GATE0_A);
    uint32_t* pB = (uint32_t*)(bss + OFF_GATE0_B);
    uint32_t* pC = (uint32_t*)(bss + OFF_GATE0_C);
    
    // 设置seed
    uint64_t seed = 0;
    *pSeed = seed;
    
    // x26 = seed ^ 0xb75e8052babb72a6
    uint64_t x26 = seed ^ 0xb75e8052babb72a6ULL;
    uint32_t x26_lo = (uint32_t)(x26 & 0xFFFFFFFF);
    uint32_t x26_hi = (uint32_t)(x26 >> 32);
    
    // 常量
    uint32_t C1 = 0xd18ddb25;
    uint32_t C2 = 0x8e4b1395;
    uint32_t C3 = 0x1f3d6a71;
    
    // === [0x6a8] 计算 ===
    // w11 = x26_lo ^ C1
    // w11 ^= x26_hi
    // w11 ^= (w11 >> 15)
    // w11 *= C3
    // w11 ^= (w11 >> 11)
    // w11 *= C2
    // w11 ^= (w11 >> 17)
    uint32_t w11 = x26_lo ^ C1;
    w11 ^= x26_hi;
    w11 ^= (w11 >> 15);
    w11 *= C3;
    w11 ^= (w11 >> 11);
    w11 *= C2;
    w11 ^= (w11 >> 17);
    *pA = w11;
    
    // === [0x6ac] 计算 ===
    // w9 = [0x6a8] ^ 0x1767cedc
    // w9 ^= (w9 >> 15)
    // w9 *= C3
    // w9 ^= (w9 >> 11)
    // w9 *= C2
    // w12 = x26_lo ^ (w9 >> 17)
    // w9 = w12 ^ w9
    uint32_t C4 = 0x1767cedc;
    uint32_t w9 = w11 ^ C4;  // 用[0x6a8]的值
    w9 ^= (w9 >> 15);
    w9 *= C3;
    w9 ^= (w9 >> 11);
    w9 *= C2;
    uint32_t w12 = x26_lo ^ (w9 >> 17);
    w9 = w12 ^ w9;
    *pB = w9;
    
    // === [0x6b0] 计算 ===
    // w10 = [0x6ac] ^ 0x5d41c293
    // w10 ^= (w10 >> 15)
    // w10 *= C3
    // w10 ^= (w10 >> 11)
    // w10 *= C2
    // w8 = x26_hi ^ (w10 >> 17)
    // w8 ^= w10
    uint32_t C5 = 0x5d41c293;
    uint32_t w10 = (*pB) ^ C5;  // 用[0x6ac]的值
    w10 ^= (w10 >> 15);
    w10 *= C3;
    w10 ^= (w10 >> 11);
    w10 *= C2;
    uint32_t w8 = x26_hi ^ (w10 >> 17);
    w8 ^= w10;
    *pC = w8;
    
    NSLog(@"[Bypass] 门卫块: seed=0x%llx A=0x%x B=0x%x C=0x%x",
          (unsigned long long)*pSeed, *pA, *pB, *pC);
}

// ============================================================
// 构造自洽会话对象
// ============================================================

static void buildSessionObject(uintptr_t bss) {
    void** pSession = (void**)(bss + OFF_SESSION);
    
    // 如果已有对象，先释放
    if (*pSession) {
        // 不释放，直接用
        NSLog(@"[Bypass] 会话对象已存在: %p", *pSession);
    }
    
    // 分配对象 (大小0x11c6，与原始代码一致)
    size_t objSize = 0x1200;  // 稍大一点
    void* obj = calloc(1, objSize);
    if (!obj) {
        NSLog(@"[Bypass] 分配会话对象失败");
        return;
    }
    
    // 载荷缓冲区在 obj+0x119a
    uint8_t* payload = (uint8_t*)obj + 0x119a;
    
    // 自选载荷值（5个qword）
    uint64_t b0  = 0xc6a4a7935bd1e995ULL;  // 使用默认值
    uint64_t b8  = 0x1111111111111111ULL;
    uint64_t b16 = 0x2222222222222222ULL;
    uint64_t b24 = 0x3333333333333333ULL;
    uint64_t b32 = 0x4444444444444444ULL;
    
    // 写入载荷缓冲区
    *(uint64_t*)(payload + 0x00) = b0;
    *(uint64_t*)(payload + 0x08) = b8;
    *(uint64_t*)(payload + 0x10) = b16;
    *(uint64_t*)(payload + 0x18) = b24;
    *(uint64_t*)(payload + 0x20) = b32;
    
    // 计算并写入字段
    
    // obj+0x78 = (b0 ^ b8) ^ 0xa5c3e1f7b6d2489a
    uint64_t field78 = (b0 ^ b8) ^ 0xa5c3e1f7b6d2489aULL;
    *(uint64_t*)((uint8_t*)obj + 0x78) = field78;
    
    // obj+0x8e = ((uint32_t)b16 ^ 0x4a9b5206) ^ (uint32_t)(b0 >> 7)
    uint32_t field8e = ((uint32_t)(b16 & 0xFFFFFFFF) ^ 0x4a9b5206) ^ (uint32_t)((b0 >> 7) & 0xFFFFFFFF);
    if (field8e == 0) field8e = 1;  // 必须非0
    *(uint32_t*)((uint8_t*)obj + 0x8e) = field8e;
    
    // obj+0x92 = ((uint32_t)b24 ^ 0x8c1a73e5) ^ (uint32_t)(b0 >> 0xd)
    uint32_t field92 = ((uint32_t)(b24 & 0xFFFFFFFF) ^ 0x8c1a73e5) ^ (uint32_t)((b0 >> 0xd) & 0xFFFFFFFF);
    if (field92 == 0) field92 = 1;  // 必须非0
    *(uint32_t*)((uint8_t*)obj + 0x92) = field92;
    
    // obj+0x0 = ((uint32_t)b32 ^ 0x5f8a16e3) ^ (uint32_t)(b0 >> 0x13)
    uint32_t field0 = ((uint32_t)(b32 & 0xFFFFFFFF) ^ 0x5f8a16e3) ^ (uint32_t)((b0 >> 0x13) & 0xFFFFFFFF);
    *(uint32_t*)((uint8_t*)obj + 0x0) = field0;
    
    *pSession = obj;
    
    NSLog(@"[Bypass] 会话对象: %p, +0x0=0x%x, +0x78=0x%llx, +0x8e=0x%x, +0x92=0x%x",
          obj, field0, (unsigned long long)field78, field8e, field92);
}

// ============================================================
// 完整武装
// ============================================================

static void armAll(uintptr_t base) {
    if (g_armed) return;
    g_armed = YES;
    
    uintptr_t bss = base + BSS_OFFSET;
    NSLog(@"[Bypass] 开始武装 base=0x%lx bss=0x%lx", (unsigned long)base, (unsigned long)bss);
    
    // 1. 设置验证锁存
    uint8_t* latch = (uint8_t*)(bss + OFF_LATCH);
    *latch = 1;
    NSLog(@"[Bypass] 验证锁存=1");
    
    // 2. 计算门卫块
    computeGateBlock(bss);
    
    // 3. 构造会话对象
    buildSessionObject(bss);
    
    // 4. Patch iconOnClick中的检查点
    uintptr_t checks[] = {
        OFF_ICON_CHECK1,   // obj+0x8e==0 检查
        OFF_ICON_CHECK2,   // obj+0x92==0 检查
        OFF_ICON_CHECK3,   // obj+0x78 校验
        OFF_ICON_CHECK4,   // obj+0x8e 校验
        OFF_ICON_CHECK5,   // obj+0x92 校验
        OFF_ICON_CHECK6,   // obj+0x0 校验
        OFF_EXPIRE_CHECK,  // 过期检查
    };
    int numChecks = sizeof(checks) / sizeof(checks[0]);
    for (int i = 0; i < numChecks; i++) {
        patchNOP(base + checks[i]);
    }
    NSLog(@"[Bypass] 已patch %d个检查点", numChecks);
    
    // 5. Patch验证函数中的检查
    patchNOP(base + OFF_VERIFY_CHECK);
    NSLog(@"[Bypass] 已patch验证函数检查");
    
    NSLog(@"[Bypass] 武装完成!");
}

// ============================================================
// Hook实现
// ============================================================

// Hook passwordForService:account:
static id hook_passwordForService(id self, SEL _cmd, NSString* service, NSString* account) {
    NSLog(@"[Bypass] passwordForService service=%@ account=%@", service, account);
    
    if (!g_armed) {
        uintptr_t base = findModuleBase();
        if (base) {
            g_module_base = base;
            armAll(base);
        }
    }
    
    return @"A";
}

// Hook setupUI（空转）
static void hook_setupUI(id self, SEL _cmd) {
    NSLog(@"[Bypass] setupUI 跳过");
}

// Hook presentViewController
static void hook_present(id self, SEL _cmd, UIViewController* vc, BOOL animated, void(^completion)(void)) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        NSLog(@"[Bypass] 拦截弹窗: %@", [(UIAlertController*)vc title]);
        if (completion) completion();
        return;
    }
    if (g_orig_present) {
        ((void(*)(id, SEL, id, BOOL, id))g_orig_present)(self, _cmd, vc, animated, completion);
    }
}

// ============================================================
// 安装Hook
// ============================================================

static void installHooks(void) {
    NSLog(@"[Bypass] 安装Hook...");
    
    // 1. Hook passwordForService:account: (类方法)
    Class keychainCls = NSClassFromString(@"_0xD5A13E79");
    if (keychainCls) {
        Method m = class_getClassMethod(keychainCls, @selector(passwordForService:account:));
        if (m) {
            method_setImplementation(m, (IMP)hook_passwordForService);
            NSLog(@"[Bypass] ✓ passwordForService:account:");
        }
    }
    
    // 2. Hook setupUI（尝试多个类）
    NSArray* classes = @[@"_0x8C2F4D71", @"_0x6D1C8F45", @"_0xB1D7F3A9", @"_0xE4A91C73",
                         @"_0x3A9E5B62", @"_0x1E6B7A93", @"_0x37C8E2B6", @"_0x7D3B5E28",
                         @"_0x8B4F26C1", @"_0xA6C1F894", @"_0xD4E9A3C7", @"_0xC8E2A541",
                         @"_0x6E3B8D52", @"_0xA91D5F47", @"_0xF2A74C19", @"_0x6D1C8F45"];
    for (NSString* clsName in classes) {
        Class cls = NSClassFromString(clsName);
        if (cls) {
            Method m = class_getInstanceMethod(cls, @selector(setupUI));
            if (m) {
                method_setImplementation(m, (IMP)hook_setupUI);
                NSLog(@"[Bypass] ✓ setupUI (类: %@)", clsName);
                break;
            }
        }
    }
    
    // 3. Hook presentViewController
    Method presentMethod = class_getInstanceMethod([UIViewController class],
                                                    @selector(presentViewController:animated:completion:));
    if (presentMethod) {
        g_orig_present = method_setImplementation(presentMethod, (IMP)hook_present);
        NSLog(@"[Bypass] ✓ presentViewController");
    }
    
    // 4. 延迟武装
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!g_armed) {
            uintptr_t base = findModuleBase();
            if (base) {
                g_module_base = base;
                armAll(base);
            } else {
                NSLog(@"[Bypass] ⚠ 未找到模块基址");
            }
        }
    });
}

// ============================================================
// 构造函数
// ============================================================

__attribute__((constructor))
static void init(void) {
    NSLog(@"[Bypass] ===== ACE靶场绕过 v2 =====");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        installHooks();
    });
}
