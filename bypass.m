#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

// ── 工具：替换实例/类方法，返回旧 IMP 便于对照 ──────────────────────
static IMP ACEReplace(Class cls, SEL sel, IMP newImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (!m) { NSLog(@"[ace] 方法缺失: %@", NSStringFromSelector(sel)); return NULL; }
    return method_setImplementation(m, newImp);
}

// BOOL getter：恒真
static BOOL ACEAlwaysYes(id self, SEL _cmd) { return YES; }
// void 方法：空转（停心跳/停到期判断/停信封校验）
static void ACENoop(id self, SEL _cmd, ...) {}
// setter：吞掉写入，防止心跳把 q2/q13 复位
static void ACESetterSwallow(id self, SEL _cmd, id a, id b, id c) {}

// +q0: 是单例入口（selector 带冒号但实现按无参读取 —— 靶场的 arity 伪装）。
static id core_get_singleton(Class core) {
    id (*msgSend0)(id, SEL) = (id(*)(id, SEL))objc_msgSend;
    return msgSend0((id)core, NSSelectorFromString(@"q0:"));
}

@interface ACELicensePatch : NSObject
@end

@implementation ACELicensePatch

// 靶场加载后由宿主注入本类，+load 后转主队列，此时靶场 dylib 的
// __mod_init_func 已执行完，类已注册、单例已建。
+ (void)load {
    dispatch_async(dispatch_get_main_queue(), ^{
        Class core = NSClassFromString(@"_0x7D3B5E28");
        if (!core) { NSLog(@"[ace] 未找到授权核心类"); return; }

        // ① 标志位强制为真（q2 授权 / q13 二次标志）
        ACEReplace(core, NSSelectorFromString(@"q2"),  (IMP)ACEAlwaysYes);
        ACEReplace(core, NSSelectorFromString(@"q13"), (IMP)ACEAlwaysYes);

        // ② 吞掉 setter：心跳 q5 里 setQ2:NO / setQ13:NO 全部失效
        ACEReplace(core, NSSelectorFromString(@"setQ2:"),  (IMP)ACESetterSwallow);
        ACEReplace(core, NSSelectorFromString(@"setQ13:"), (IMP)ACESetterSwallow);

        // ③ 停掉验证链：心跳 q5、到期 q17、信封校验 q21:/q22:/q20:、
        //    重排定时器 q18:。q4 保留（它初始化单例状态，只断后续心跳）。
        ACEReplace(core, NSSelectorFromString(@"q5"),   (IMP)ACENoop);
        ACEReplace(core, NSSelectorFromString(@"q17"),  (IMP)ACENoop);
        ACEReplace(core, NSSelectorFromString(@"q18:"), (IMP)ACENoop);
        ACEReplace(core, NSSelectorFromString(@"q20:"), (IMP)ACENoop);
        ACEReplace(core, NSSelectorFromString(@"q21:"), (IMP)ACENoop);
        ACEReplace(core, NSSelectorFromString(@"q22:"), (IMP)ACENoop);

        // ④ 已经排上的 NSTimer 兜底 invalidate（防止 q5 残帧再跑一次）
        id (*get)(id, SEL) = (id(*)(id, SEL))objc_msgSend;
        for (NSString *t in @[@"q8", @"q12"]) {
            id timer = get((id)core_get_singleton(core), NSSelectorFromString(t));
            if ([timer respondsToSelector:@selector(invalidate)]) [timer invalidate];
        }

        // ⑤ 注销 NSURLProtocol 拦截器 _0xE4A91C73（切断响应改写通路）
        Class mitm = NSClassFromString(@"_0xE4A91C73");
        if (mitm) [NSURLProtocol unregisterClass:mitm];

        NSLog(@"[ace] 授权链已失效：标志位强制 + 心跳/到期/信封校验全部空转");
    });
}

@end

// ── 对照解法 B：“用靶场自己的引擎打靶场” ──────────────────────────
// dylib 导出 Dobby 完整 API，可在 C 层直接 inline hook 同一批函数。
// extern "C" int DobbyInstrument(void *addr, void (*callback)(void *, void **));
// extern "C" int DobbyDestroy(void *addr);
// 思路：对 -[q5]/-[q17] 的 IMP（class-dump 得 0x9f840/0xa67b4，运行时
// 加 slide：header + __dyld_get_image_vmaddr_slide）调 DobbyInstrument
// 把入口改成 ret。
//
// ── 对照解法 C：钥匙串投毒（仅作分析认知）──────────────────────────
// setPassword:forService:account: 明文写钥匙串（无二次签名）；
// “信封加密”只防中间人、不防端点 —— 端点即密钥保管者。
// ────────────────────────────────────────────────────────────────────
