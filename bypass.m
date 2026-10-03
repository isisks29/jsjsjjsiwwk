#define ACE_ENABLE_OBJC_LAYER 1

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <unistd.h>
#import <stdlib.h>

// ══════════ 第 0 层：dyld 拦截（先于所有 +load/构造函数生效）══════
// 回调签名与 <mach-o/dyld.h> 声明完全一致（Xcode15+ 函数指针不匹配即报错）
typedef void (*ACEAddImageFn)(const struct mach_header *mh, intptr_t vmaddr_slide);

static const struct mach_header *ACE_self_header(void) {
    Dl_info info;
    if (dladdr((const void *)&ACE_self_header, &info))
        return (const struct mach_header *)info.dli_fbase;
    return NULL;   // 取不到就放弃隐身，其余功能照常工作
}

static int g_our_index = -1;
static int ACE_find_our_index(void) {
    if (g_our_index >= 0) return g_our_index;
    const struct mach_header *self = ACE_self_header();
    if (!self) return -1;
    uint32_t n = _dyld_image_count();           // 本镜像内的调用不受本表影响
    for (uint32_t i = 0; i < n; i++)
        if (_dyld_get_image_header(i) == self) { g_our_index = (int)i; return g_our_index; }
    return -1;
}

// 把补丁从模块枚举里摘掉（watchdog 的扫描循环失明）
static uint32_t ACE_image_count(void) {
    return (uint32_t)((int)_dyld_image_count() - (ACE_find_our_index() >= 0 ? 1 : 0));
}
static const char *ACE_image_name(uint32_t i) {
    int o = ACE_find_our_index();
    return _dyld_get_image_name((o >= 0 && i >= (uint32_t)o) ? i + 1 : i);
}
static const struct mach_header *ACE_image_header(uint32_t i) {
    int o = ACE_find_our_index();
    return _dyld_get_image_header((o >= 0 && i >= (uint32_t)o) ? i + 1 : i);
}

// 接管监视器注册：转发给靶场回调，但把“补丁镜像”伪装成“主程序镜像”。
// 监视器 @0x44bc 对主程序直接放行（跳过匹配），其余镜像原样喂入。
static ACEAddImageFn g_watch_cb = NULL;
static void ACE_watch_wrapper(const struct mach_header *mh, intptr_t slide) {
    if (!g_watch_cb) return;
    if (mh && mh == ACE_self_header())
        g_watch_cb(_dyld_get_image_header(0), slide);   // 伪装成主程序
    else
        g_watch_cb(mh, slide);
}
static void ACE_register_add_image(ACEAddImageFn f) {
    g_watch_cb = f;
    _dyld_register_func_for_add_image(ACE_watch_wrapper);
}

// 反调试/异常劫持关闭（返回成功但不给数据 → 扫描循环自然空转）
static kern_return_t ACE_task_threads(mach_port_t task, thread_act_array_t *arr,
                                      mach_msg_type_number_t *cnt) {
    if (arr) *arr = NULL;
    if (cnt) *cnt = 0;
    return KERN_SUCCESS;
}
static kern_return_t ACE_task_set_exception_ports(mach_port_t task,
                                                  exception_mask_t mask,
                                                  exception_handler_t handler,
                                                  exception_behavior_t behavior,
                                                  thread_state_flavor_t flavor) {
    return KERN_SUCCESS;   // 不安装它的异常处理器
}

// kill 路径兜底：不返回（保持进程存活，便于继续观察）
static void ACE_exit(int code) {
    NSLog(@"[ace] 拦截 exit(%d) —— kill 路径已熔断", code);
    for (;;) sleep(86400);
}
static void ACE_abort(void) {
    NSLog(@"[ace] 拦截 abort() —— kill 路径已熔断");
    for (;;) sleep(86400);
}

#define ACE_INTERPOSE(rep, orig) \
    const struct { const void *r, *o; } _ace_ip_##orig \
    __attribute__((used, section("__DATA,__interpose"))) = { (const void *)(rep), (const void *)(orig) };

ACE_INTERPOSE(ACE_register_add_image,   _dyld_register_func_for_add_image)
ACE_INTERPOSE(ACE_image_count,          _dyld_image_count)
ACE_INTERPOSE(ACE_image_name,           _dyld_get_image_name)
ACE_INTERPOSE(ACE_image_header,         _dyld_get_image_header)
ACE_INTERPOSE(ACE_task_threads,         task_threads)
ACE_INTERPOSE(ACE_task_set_exception_ports, task_set_exception_ports)
ACE_INTERPOSE(ACE_exit,                 exit)
ACE_INTERPOSE(ACE_abort,                abort)

#if ACE_ENABLE_OBJC_LAYER
// ══════════ 第 1 层：授权核心 hook（带完整防御）══════════════════════
static IMP ACEReplace(Class cls, SEL sel, IMP newImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (!m) return NULL;
    return method_setImplementation(m, newImp);
}
static BOOL ACEAlwaysYes(id self, SEL _cmd) { return YES; }
static void ACENoop(id self, SEL _cmd, ...) {}
static void ACESetterSwallow(id self, SEL _cmd, ...) {}
#endif

@interface ACELicensePatch : NSObject
@end

@implementation ACELicensePatch

+ (void)load {
    // 主队列异步：此时 interpose 已生效、靶场构造函数已跑完、类已全部注册
    dispatch_async(dispatch_get_main_queue(), ^{
#if ACE_ENABLE_OBJC_LAYER
        @try {
            Class core = NSClassFromString(@"_0x7D3B5E28");
            if (!core) { NSLog(@"[ace] 授权核心类缺席（版本不符?）"); return; }

            // ① 标志位强制 + setter 吞写
            ACEReplace(core, NSSelectorFromString(@"q2"),  (IMP)ACEAlwaysYes);
            ACEReplace(core, NSSelectorFromString(@"q13"), (IMP)ACEAlwaysYes);
            ACEReplace(core, NSSelectorFromString(@"setQ2:"),  (IMP)ACESetterSwallow);
            ACEReplace(core, NSSelectorFromString(@"setQ13:"), (IMP)ACESetterSwallow);

            // ② 校验链空转（心跳/到期/重排/信封校验）
            for (NSString *s in @[@"q5", @"q17", @"q18:", @"q20:", @"q21:", @"q22:"])
                ACEReplace(core, NSSelectorFromString(s), (IMP)ACENoop);

            // ③ 兜底停 timer（确认 selector 存在，防 unrecognized selector）
            SEL q0s = NSSelectorFromString(@"q0:");
            if ([core respondsToSelector:q0s]) {
                id inst = ((id (*)(id, SEL))objc_msgSend)((id)core, q0s);
                if (inst) {
                    id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                    for (NSString *t in @[@"q8", @"q12"]) {
                        SEL g = NSSelectorFromString(t);
                        if ([inst respondsToSelector:g]) {
                            id tm = get(inst, g);
                            if ([tm isKindOfClass:[NSTimer class]]) [tm invalidate];
                        }
                    }
                }
            }

            // ④ 注销网络拦截器（响应改写通路）
            Class mitm = NSClassFromString(@"_0xE4A91C73");
            if (mitm) [NSURLProtocol unregisterClass:mitm];

            NSLog(@"[ace] 完整补丁生效：隐身 + 授权链空转 + 拦截器注销");
        } @catch (NSException *e) {
            NSLog(@"[ace] 补丁异常(不影响 interpose 层): %@", e);
        }
#else
        NSLog(@"[ace] 诊断模式：仅 interpose 隐身层生效");
#endif
    });
}

@end
