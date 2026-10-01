







#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach-o/dyld.h>
#import <libkern/OSCacheControl.h>

#pragma mark - 靶场定位（用构建函数 prologue 指纹，不依赖安装名/ASLR slide）
// 0x109020: sub sp, sp, #0x150  -> 0xD10543FF
// 0x109134: b.ne #0x109df8      -> 0x54006621
static uintptr_t ace_base(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h) continue;
        uintptr_t base = (uintptr_t)h;
        uint32_t p0 = *(volatile uint32_t *)(base + 0x109020);
        uint32_t p1 = *(volatile uint32_t *)(base + 0x109134);
        if (p0 == 0xD10543FF && p1 == 0x54006621) return base;   // 命中 ace 构建函数
    }
    return 0;
}

#pragma mark - 21 处校验分支（NOP 名单）
static const uint32_t kChecks[] = {
    0x109068,                                   // 入口守卫 cbz g1==0 -> return
    0x109134, 0x1091D4, 0x109288, 0x1092E0, 0x109308,   // Phase1: gate/时间/对象字段
    0x1093E4, 0x10941C, 0x109458, 0x1094B0, 0x109574,   // Phase1: 对象字段自洽
    0x1098D4, 0x10996C, 0x109A34, 0x109A94, 0x109AA0,   // Phase2: gate/时间
    0x109BA4, 0x109BFC, 0x109C6C, 0x109CD4, 0x109D48    // Phase2: 对象字段自洽
};
static const int  kCheckCount = 21;
static const uint32_t kNOP = 0xD503201F;

// 返回已补丁的分支数；-1 = 未定位到靶场
static int patch_checks(uintptr_t base) {
    if (!base) return -1;

    // 计算覆盖全部补丁点所需的最小页范围
    uintptr_t lo = base + kChecks[0], hi = base + kChecks[0];
    for (int i = 1; i < kCheckCount; i++) {
        uintptr_t a = base + kChecks[i];
        if (a < lo) lo = a;
        if (a > hi) hi = a;
    }
    uintptr_t pg   = (uintptr_t)vm_page_size;
    uintptr_t p0   = lo & ~(pg - 1);
    uintptr_t p1   = (hi + pg - 1) & ~(pg - 1);

    // 使目标页可写（保持可执行，避免写回时被保护触发）
    mach_vm_protect(mach_task_self(), p0, p1 - p0, 0,
                    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    int done = 0;
    for (int i = 0; i < kCheckCount; i++) {
        volatile uint32_t *p = (volatile uint32_t *)(base + kChecks[i]);
        uint32_t cur = *p;
        // 只改写"确实是要旁路的条件分支/入口 cbz"，防止误伤其它代码
        BOOL isBail = (kChecks[i] == 0x109068) ? (cur == 0x34006C88)
                                               : ((cur & 0xFF000000) == 0x54000000);
        if (isBail && cur != kNOP) {
            *p = kNOP;
            done++;
        }
    }

    // 关键：刷新指令缓存，否则 CPU 可能执行到旧指令 → 崩
    sys_icache_invalidate((void *)p0, p1 - p0);

    // 恢复只读+可执行
    mach_vm_protect(mach_task_self(), p0, p1 - p0, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    return done;
}

#pragma mark - 三件套 hook（抑制卡密弹窗，保持你已验证的稳定组合）
static void (*g_orig_present)(id, SEL, id, BOOL, id);

static void install_popup_hooks(void) {
    // 1) 钥匙串查询判定入口：+[_0xD5A13E79 passwordForService:account:] 恒返回 @"A"
    Class keychain = NSClassFromString(@"_0xD5A13E79");
    if (!keychain) {                                        // 兜底：枚举任意实现该选择器的类
        unsigned n = 0; Class *cs = objc_copyClassList(&n);
        for (unsigned i = 0; i < n; i++)
            if (class_getClassMethod(cs[i], sel_registerName("passwordForService:account:")))
            { keychain = cs[i]; break; }
        free(cs);
    }
    if (keychain) {
        Method m = class_getClassMethod(keychain, sel_registerName("passwordForService:account:"));
        if (m)
            method_setImplementation(m, imp_implementationWithBlock(
                ^id(id s, SEL c, id svc, id acct) { return @"A"; }));
    }

    // 2) setupUI 空转（弹窗容器兜底；哪个类定义就空转哪个）
    unsigned n = 0; Class *cs = objc_copyClassList(&n);
    for (unsigned i = 0; i < n; i++) {
        Method m = class_getInstanceMethod(cs[i], sel_registerName("setupUI"));
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s) { }));
    }
    free(cs);

    // 3) 全局拦截 UIAlertController，其余 present 放行
    Method pm = class_getInstanceMethod([UIViewController class],
                                        sel_registerName("presentViewController:animated:completion:"));
    if (pm) {
        g_orig_present = (void (*)(id, SEL, id, BOOL, id))method_getImplementation(pm);
        method_setImplementation(pm, imp_implementationWithBlock(
            ^void(id self, SEL c, id vc, BOOL anim, id comp) {
                if ([vc isKindOfClass:[UIAlertController class]]) {
                    if (comp) { void (^cb)(void) = comp; cb(); }
                    return;
                }
                g_orig_present(self, c, vc, anim, comp);
            }));
    }
}

#pragma mark - 对外入口
// 请在"写门卫字之前、调用 0x109020 之前"调用一次。
// 返回已补丁分支数；-1 表示未找到 ace 靶场。
int ace_activate(void) {
    install_popup_hooks();                    // 幂等，可重复调用
    uintptr_t base = ace_base();
    return patch_checks(base);
}

// 注入时先装好弹窗 hook（不写门卫字、不打代码补丁，避免过早触发构建）
__attribute__((constructor))
static void bypass_init(void) {
    install_popup_hooks();
}
