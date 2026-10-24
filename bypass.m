// ═══════════════════════════════════════════════════════════════════
//  bypass6.m — 第六课靶场 PitchKit.app (VocalPal 2.2.5) 会员解锁
//
//  目标识别：主可执行文件 PitchKit，LC_UUID d2ca6d1918b733b9a979e4020def2303
//            Bundle ID com.leleyes.PitchAnalyzers，4,795,216 B
//            MD5(ipa 内主二进制所在包) 3a3325bd9375f606cac2a0799c08c022
//
//  ── 会员机制全景（全部来自 Ghidra 导出 + 原始二进制逐字节互证）──
//  · 纯 Swift + UIKit。业务核心 AccountManager（登录态）/ PurchaseManager
//    （StoreKit 三商品 pro_half_year / pro_one_year / pro_forever @0x1003b7000
//    Swift small-string 数组）/ RecordManager / StateEntityManager。
//  · 服务器 api.leleyes.com：/api/auth/login、/api/auth/check-status、
//    /api/apple/pay/index、/api/apple/restore、/api/auth/sms-code 等。
//    响应信封 DataResponse{code,message,result:String?}，result 为
//    base64(AES-256-CBC) 密文，KEY/IV 硬编码明文在二进制里：
//      KEY "Njc8uIR3HzhoUPegDxtqJLOpVXAWrv6Q" @0x1002e72b0
//      IV  "2gSmRTMbuKQ8wGo6"                  @0x1002e72e0
//    解密变换 FUN_100084ff0 / FUN_100084e28，解密后 JSONDecoder 直接解码，
//    无任何签名/MAC 校验。
//  · 模型（__swift5_fieldmd 字段描述符还原）：
//      LoginDataResponse { uid:Int, is_vip:Int?, vip_type:Int?,
//                          vip_expired_at:Int?, token:String, is_new_user:Bool }
//      CheckStatusResponse { uid:Int, is_vip:Int, vip_type:Int, vip_expired_at:Int? }
//  · 会员判定唯一语义点 updateVipValidity = FUN_100085e44：
//      isVipValid = (is_vip==1) && (vip_type==2 /*永久*/ || vip_expired_at>now)
//  · 本地持久化 FUN_100086048：整个 LoginDataResponse JSONEncoder 编码后
//    **明文**存 UserDefaults["loginDataKey"]（无加密无签名）；nil 时删键。
//    启动恢复 FUN_100085758（HomeVC.viewDidLoad @0x100021080 调用）：
//    dataForKey → JSONDecoder(LoginDataResponse) → Published 写入 →
//    updateVipValidity。JSONDecoder 为默认配置（FUN_10008b884 仅取
//    Decodable witness table，未设 keyDecodingStrategy）→ 键名=字段名。
//  · 自动游客登录 FUN_100086314 仅当 loginDataResponse==nil 时触发
//    → 预置伪造缓存即完全抑制。
//  · ★ 功能门全部读同一个 UserDefaults 布尔键 "isVipValid"（boolForKey:），
//    共 9 个读取点（按 movz#0x7369/movk 指令签名全量扫描，证明无遗漏）：
//      0x1000557c4 FUN_100055708  录音启动门（非会员且 maxRecordTime≤20 拒录）
//      0x10005634c FUN_100056168  录音计时门（20 秒强制截断+bugMember 弹窗）
//      0x100035910 FUN_10003588c  VocaliseTips/底栏切换区
//      0x100036338 FUN_100036244  HomeBottomSwichView 区
//      0x10004d4c8+0x10004d714 FUN_10004d31c 练声曲目 cell 显示
//      0x10004eec4 FUN_10004ee7c  HomePianoView 钢琴面板区
//      0x1000535a0 FUN_100053558  HomeTonoView 主视图区
//      0x10008f144 FUN_10008f080  登录/账号 UI 区
//      0x100090e6c FUN_100090de4  VocaliseVC 滑动操作区
//    该键唯一写入点 = 侧边栏 isVipValid 的 Combine sink FUN_1000b9928
//    （setObject:forKey: objc_msgSend @0x1000b9b60）。
//  · 内存态 isVipValid 为 AccountManager 的 @Published<Bool>（ivar cell
//    0x1003c95f8），写入走 keypath 描述符对 (0x10030fee8,0x10030ff10)：
//      判定写: FUN_100085e44 (updateVipValidity)
//      清零写: FUN_100088140(无token)/FUN_100088530(check-status失败尾)
//              /FUN_100088cf0(restore失败尾)/FUN_100089634(登出)
//  · 本 App 无任何反调试/反注入/完整性自检（无 sysctl、无越狱探测、
//    无黑名单、无心跳杀）。
//
//  ── 攻击设计（四层，全部运行时生效，不改磁盘文件）──
//  A  构造期预置 UserDefaults：isVipValid=true + loginDataKey=伪造 VIP 缓存
//     {uid,is_vip:1,vip_type:2(永久),vip_expired_at:null,token,is_new_user}
//     → 启动恢复链原生算出 isVipValid=true；游客自动登录被抑制。
//  B  swizzle -[NSUserDefaults boolForKey:]：键 "isVipValid" 恒 YES
//     → 9 个功能门无论谁写过什么，读到永远 true（写入方全部失效化）。
//  C  运行时内存补丁 13 点（仅 LC_UUID 精确匹配 + 每点原字节逐位校验通过
//     才写；任一校验失败自动整体降级为 A+B+D，功能门不受影响）：
//     C1×3 check-status 失败尾清零（0x1000886f4/0x100088734/0x10008873c→NOP）
//          → 服务器拒绝伪造 token 时不再清内存态、不再删本地缓存
//     C2×3 restore 失败尾清零（0x100088dac/0x100088df0/0x100088df4→NOP）
//     C3×7 updateVipValidity 全部判定分支重定向到 true 路径（0x100085f6c）
//          → 任何服务器响应（含真实免费账号）都判为有效会员
//  D  2s 看门狗：维持两个键（blob 合并式强制，保留真实 uid/token）、
//     swizzle 完整性自愈、HUD 状态。
//
//  兼容性：真实购买/真实登录不冲突——C3 只把判定抬成 true；A/D 的 blob
//  合并保留服务器真 token，check-status 用真 token 成功时走原生更新。
//  已知边界：用户主动「登出/注销」会清内存态（显式用户行为，不拦）；
//  下次启动 A 层立即恢复 VIP。侧边栏 VIP 徽章由 C3 的 Published send
//  原生点亮（sink 链完整，UI 自动刷新）。
// ═══════════════════════════════════════════════════════════════════

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <libkern/OSCacheControl.h>

#define CK6_BUNDLE_ID   @"com.leleyes.PitchAnalyzers"
#define CK6_UUID_HEX    @"d2ca6d1918b733b9a979e4020def2303"
#define CK6_UD_VIPKEY   @"isVipValid"
#define CK6_UD_BLOBKEY  @"loginDataKey"

static const struct mach_header_64 *g_mh = NULL;      // PitchKit 主二进制头
static intptr_t g_slide = 0;                    // 运行时滑移
static BOOL g_uuid_match = NO;
static int  g_patch_ok = 0, g_patch_total = 0, g_patch_skip = 0;
static BOOL g_swizzle_ok = NO;
static UILabel *g_hud = NULL;
static int g_tick = 0;

static void CKLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[bypass6] %@", s);
}

// ───────────────────────── 目标识别 ─────────────────────────
static NSString *CK6_uuid_of(const struct mach_header_64 *mh) {
    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_UUID) {
            const struct uuid_command *uc = (const struct uuid_command *)lc;
            const uint8_t *u = uc->uuid;
            NSMutableString *s = [NSMutableString string];
            for (int k = 0; k < 16; k++) [s appendFormat:@"%02x", u[k]];
            return s;
        }
        p += lc->cmdsize;
    }
    return @"";
}

static void CK6_locate_target(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        NSString *path = [NSString stringWithUTF8String:nm];
        if (![path.lastPathComponent isEqualToString:@"PitchKit"]) continue;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64 || mh->filetype != MH_EXECUTE) continue;
        g_mh = mh;
        g_slide = (intptr_t)mh - 0x100000000;
        NSString *uuid = CK6_uuid_of(mh);
        g_uuid_match = [uuid isEqualToString:CK6_UUID_HEX];
        CKLog(@"命中主二进制 %s base=%p slide=0x%lx", nm, mh, (long)g_slide);
        CKLog(@"LC_UUID=%@ 匹配=%@ (期望 %@)", uuid, g_uuid_match ? @"YES" : @"NO", CK6_UUID_HEX);
        return;
    }
    // 名字兜底：主可执行文件 + bundle id 校验
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    if ([bid isEqualToString:CK6_BUNDLE_ID]) {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
        g_mh = mh;
        g_slide = (intptr_t)mh - 0x100000000;
        g_uuid_match = [CK6_uuid_of(mh) isEqualToString:CK6_UUID_HEX];
        CKLog(@"按 bundle id 命中主二进制 base=%p uuid匹配=%d", mh, g_uuid_match);
    }
}

static void *T(uint32_t off) {   // off = 静态 vmaddr - 0x100000000
    return (void *)((uintptr_t)g_mh + off);
}

// ───────────────────────── C 层：内存补丁 ─────────────────────────
typedef struct { uint32_t off; uint32_t expect; uint32_t patch; const char *what; } CK6Patch;

// true 路径 = 0x100085f6c（getKeyPath(isVipValid) + mov w8,#1 + sturb + setter）
static const CK6Patch kPatches[] = {
    // C1: check-status 失败尾（FUN_100088530 @0x100088530）清零三连
    {0x886f4, 0x94095f53, 0xd503201f, "C1a checkStatus失败尾·loginDataResponse=nil setter→NOP"},
    {0x88734, 0x94095f43, 0xd503201f, "C1b checkStatus失败尾·isVipValid=false setter→NOP"},
    {0x8873c, 0x97fff643, 0xd503201f, "C1c checkStatus失败尾·persist(删loginDataKey)→NOP"},
    // C2: restore 失败尾（FUN_100088cf0）清零三连
    {0x88dac, 0x94095da5, 0xd503201f, "C2a restore失败尾·loginDataResponse=nil setter→NOP"},
    {0x88df0, 0x94095d94, 0xd503201f, "C2b restore失败尾·isVipValid=false setter→NOP"},
    {0x88df4, 0x97fff495, 0xd503201f, "C2c restore失败尾·persist→NOP"},
    // C3: updateVipValidity（FUN_100085e44）判定分支全部改道 true 路径
    {0x85f18, 0xb4000888, 0x14000015, "C3-1 VIP判定·nil缓存早退→true"},
    {0x85f54, 0x370004b7, 0x14000006, "C3-2 VIP判定·is_vip缺失→true"},
    {0x85f5c, 0x54000461, 0x14000004, "C3-3 VIP判定·is_vip≠1→true"},
    {0x85f60, 0x370001db, 0x14000003, "C3-4 VIP判定·vip_type缺失→true"},
    {0x85f68, 0x54000181, 0x14000001, "C3-5 VIP判定·vip_type≠2→true"},
    {0x85f98, 0x37000298, 0x17fffff5, "C3-6 VIP判定·到期时间缺失→true"},
    {0x85fe4, 0x3707fc57, 0x17ffffe2, "C3-7 VIP判定·已过期→true"},
};

static BOOL CK6_write_word(void *addr, uint32_t val) {
    vm_address_t page = (vm_address_t)addr & ~(vm_address_t)(vm_page_size - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, vm_page_size * 2,
                                  FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS)
        kr = vm_protect(mach_task_self(), page, vm_page_size * 2,
                        TRUE, VM_PROT_READ | VM_PROT_WRITE);   // set-maximum 再试
    if (kr != KERN_SUCCESS) {
        CKLog(@"vm_protect RW 失败 @%p kr=%d", addr, kr);
        return NO;
    }
    *(volatile uint32_t *)addr = val;
    vm_protect(mach_task_self(), page, vm_page_size * 2, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(addr, 4);
    return (*(volatile uint32_t *)addr) == val;
}

static void CK6_apply_patches(void) {
    g_patch_total = (int)(sizeof(kPatches) / sizeof(kPatches[0]));
    if (!g_uuid_match) {
        CKLog(@"⚠️ UUID 不匹配（可能换了构建）——跳过全部代码补丁，A/B/D 层照常生效");
        g_patch_skip = g_patch_total;
        return;
    }
    for (int i = 0; i < g_patch_total; i++) {
        const CK6Patch *p = &kPatches[i];
        volatile uint32_t *site = (volatile uint32_t *)T(p->off);
        uint32_t cur = *site;
        if (cur == p->patch) { g_patch_ok++; continue; }        // 幂等
        if (cur != p->expect) {
            CKLog(@"✗ %s 原字节不符: 0x%08x ≠ 期望 0x%08x → 跳过该点", p->what, cur, p->expect);
            g_patch_skip++;
            continue;
        }
        if (CK6_write_word((void *)site, p->patch)) {
            g_patch_ok++;
            CKLog(@"✓ %s @0x%lx: %08x→%08x", p->what, (unsigned long)(0x100000000 + p->off), cur, p->patch);
        } else {
            g_patch_skip++;
            CKLog(@"✗ %s 写入失败", p->what);
        }
    }
    CKLog(@"补丁结果: %d/%d 生效, %d 跳过", g_patch_ok, g_patch_total, g_patch_skip);
}

// ───────────────────────── B 层：boolForKey: swizzle ─────────────────────────
typedef BOOL (*CK6_bool_imp)(id, SEL, NSString *);
static CK6_bool_imp g_orig_boolForKey = NULL;
static Method g_boolMethod = NULL;

static BOOL CK6_boolForKey(id self, SEL _cmd, NSString *key) {
    if ([key isKindOfClass:[NSString class]] && [key isEqualToString:CK6_UD_VIPKEY])
        return YES;
    return g_orig_boolForKey(self, _cmd, key);
}

static void CK6_install_swizzle(void) {
    Class cls = [NSUserDefaults class];
    g_boolMethod = class_getInstanceMethod(cls, @selector(boolForKey:));
    if (!g_boolMethod) { CKLog(@"✗ boolForKey: 方法未找到"); return; }
    g_orig_boolForKey = (CK6_bool_imp)method_getImplementation(g_boolMethod);
    if (g_orig_boolForKey == (CK6_bool_imp)CK6_boolForKey) { g_swizzle_ok = YES; return; }
    method_setImplementation(g_boolMethod, (IMP)CK6_boolForKey);
    g_swizzle_ok = (method_getImplementation(g_boolMethod) == (IMP)CK6_boolForKey);
    CKLog(@"B层 boolForKey: swizzle %@ (原IMP=%p)", g_swizzle_ok ? @"✓" : @"✗", g_orig_boolForKey);
}

static void CK6_check_swizzle(void) {   // 看门狗自愈
    if (!g_boolMethod) { CK6_install_swizzle(); return; }
    IMP cur = method_getImplementation(g_boolMethod);
    if (cur != (IMP)CK6_boolForKey && g_orig_boolForKey != (CK6_bool_imp)cur) {
        CKLog(@"swizzle 被覆盖(%p)，重新接管并保留链", cur);
        g_orig_boolForKey = (CK6_bool_imp)cur;
        method_setImplementation(g_boolMethod, (IMP)CK6_boolForKey);
    } else if (cur != (IMP)CK6_boolForKey) {
        method_setImplementation(g_boolMethod, (IMP)CK6_boolForKey);
    }
}

// ───────────────────────── A/D 层：UserDefaults 伪造与维持 ─────────────────────────
static NSString *CK6_token(void) {
    static NSString *t = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *raw = [[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""];
        t = [NSString stringWithFormat:@"CK6LOCAL%@", [raw substringToIndex:16]];
    });
    return t;
}

// 合并式强制：保留已有 uid/token（真实登录过则用真 token），只抬 VIP 字段
static BOOL CK6_enforce_blob(NSUserDefaults *ud) {
    NSMutableDictionary *blob = nil;
    NSData *d = [ud dataForKey:CK6_UD_BLOBKEY];
    if (d) {
        id j = [NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingMutableContainers error:NULL];
        if ([j isKindOfClass:[NSDictionary class]]) blob = [j mutableCopy];
    }
    BOOL fresh = (blob == nil);
    if (fresh) blob = [NSMutableDictionary dictionary];
    BOOL dirty = fresh;
    if (![blob[@"is_vip"] isEqual:@1])            { blob[@"is_vip"] = @1; dirty = YES; }
    if (![blob[@"vip_type"] isEqual:@2])          { blob[@"vip_type"] = @2; dirty = YES; }
    id exp = blob[@"vip_expired_at"];
    if (exp && exp != [NSNull null])              { blob[@"vip_expired_at"] = [NSNull null]; dirty = YES; }
    else if (!exp)                                { blob[@"vip_expired_at"] = [NSNull null]; dirty = YES; }
    if (!blob[@"uid"])                            { blob[@"uid"] = @(88888888); dirty = YES; }
    id tk = blob[@"token"];
    if (![tk isKindOfClass:[NSString class]] || [(NSString *)tk length] < 8) {
        blob[@"token"] = CK6_token(); dirty = YES;
    }
    if (!blob[@"is_new_user"])                    { blob[@"is_new_user"] = @NO; dirty = YES; }
    if (dirty) {
        NSData *out = [NSJSONSerialization dataWithJSONObject:blob options:0 error:NULL];
        if (out) [ud setObject:out forKey:CK6_UD_BLOBKEY];
        return YES;
    }
    return NO;
}

static void CK6_forge_defaults(BOOL verbose) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    // 诚实读回（objectForKey 未被 swizzle）
    NSNumber *cur = [ud objectForKey:CK6_UD_VIPKEY];
    if (![cur isKindOfClass:[NSNumber class]] || !cur.boolValue) {
        [ud setObject:@YES forKey:CK6_UD_VIPKEY];
        if (verbose) CKLog(@"A层 写入 %@=true（原值=%@）", CK6_UD_VIPKEY, cur);
    }
    BOOL blobWritten = CK6_enforce_blob(ud);
    if (verbose) {
        NSData *d = [ud dataForKey:CK6_UD_BLOBKEY];
        NSString *s = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : @"(nil)";
        CKLog(@"A层 loginDataKey=%@ (本次%@)", s, blobWritten ? @"重写" : @"已合规");
    }
}

// ───────────────────────── HUD ─────────────────────────
@interface CK6HudTarget : NSObject
+ (instancetype)shared;
- (void)tapped;
- (void)panned:(UIPanGestureRecognizer *)g;
@end

static UIWindow *CK6_key_window(void) {
    UIWindow *kw = nil;
    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
        if ([sc isKindOfClass:[UIWindowScene class]]) {
            for (UIWindow *w in ((UIWindowScene *)sc).windows)
                if (w.isKeyWindow) kw = w;
        }
    }
    if (!kw) for (UIWindow *w in [UIApplication sharedApplication].windows) if (w.isKeyWindow) kw = w;
    if (!kw) kw = [UIApplication sharedApplication].windows.firstObject;
    return kw;
}

static NSString *CK6_status_line(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSNumber *vip = [ud objectForKey:CK6_UD_VIPKEY];      // 诚实读（objectForKey 未被 swizzle）
    NSData *blob = [ud dataForKey:CK6_UD_BLOBKEY];
    return [NSString stringWithFormat:
        @"A 缓存伪造: %@ (blob %@B)\n"
        @"B 门读取恒真: %@\n"
        @"C 内存补丁: %d/%d (跳过%d) UUID%@\n"
        @"D 看门狗: t=%d\n"
        @"诚实读回 isVipValid=%@",
        blob ? @"✓" : @"✗", blob ? @([blob length]) : @0,
        g_swizzle_ok ? @"✓" : @"✗",
        g_patch_ok, g_patch_total, g_patch_skip, g_uuid_match ? @"✓" : @"✗",
        g_tick, vip];
}

@implementation CK6HudTarget
+ (instancetype)shared {
    static CK6HudTarget *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [CK6HudTarget new]; });
    return s;
}
- (void)tapped {
    UIViewController *vc = CK6_key_window().rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    if (!vc) return;
    UIAlertController *al = [UIAlertController alertControllerWithTitle:@"bypass6 状态"
        message:CK6_status_line() preferredStyle:UIAlertControllerStyleAlert];
    [al addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [vc presentViewController:al animated:YES completion:nil];
}
- (void)panned:(UIPanGestureRecognizer *)g {
    UIView *v = g.view;
    CGPoint p = [g translationInView:v.superview];
    v.center = CGPointMake(v.center.x + p.x, v.center.y + p.y);
    [g setTranslation:CGPointMake(0, 0) inView:v.superview];   // 不用 CGPointZero：避免依赖 CoreGraphics 常量符号（工作流未链 CG）
}
@end

static UIControl *g_hudCtl = nil;
static void CK6_make_hud(void) {
    if (g_hudCtl) return;
    UIWindow *kw = CK6_key_window();
    if (!kw) return;
    UIControl *ctl = [[UIControl alloc] initWithFrame:CGRectMake(12, 54, 132, 26)];
    ctl.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.55];
    ctl.layer.cornerRadius = 13;
    ctl.clipsToBounds = YES;
    UILabel *l = [[UILabel alloc] initWithFrame:ctl.bounds];
    l.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    l.text = @"🎵VIP·bypass6";
    l.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightSemibold];
    l.textColor = [UIColor colorWithRed:0.35 green:1.0 blue:0.55 alpha:1.0];
    l.textAlignment = NSTextAlignmentCenter;
    l.userInteractionEnabled = NO;
    [ctl addSubview:l];
    g_hud = l;
    [ctl addTarget:[CK6HudTarget shared] action:@selector(tapped) forControlEvents:UIControlEventTouchUpInside];
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
        initWithTarget:[CK6HudTarget shared] action:@selector(panned:)];
    [ctl addGestureRecognizer:pan];
    [kw addSubview:ctl];
    g_hudCtl = ctl;
}

// ───────────────────────── 看门狗 ─────────────────────────
static dispatch_source_t g_timer = NULL;   // 必须静态持有，ARC 下局部变量出作用域即被释放
static void CK6_watchdog(void) {
    if (g_timer) return;
    dispatch_source_t t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(t, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                              2 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(t, ^{
        g_tick++;
        CK6_check_swizzle();
        CK6_forge_defaults(NO);
        if (!g_hudCtl) CK6_make_hud();
        if (g_hud) {
            g_hud.text = [NSString stringWithFormat:@"🎵VIP·b6 C%d/%d t%d",
                          g_patch_ok, g_patch_total, g_tick];
        }
        if (g_tick % 15 == 1) {   // 每 30s 一次心跳日志
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            CKLog(@"心跳 t=%d 诚实读回 isVipValid=%@ blob=%luB 补丁=%d/%d swizzle=%d",
                  g_tick, [ud objectForKey:CK6_UD_VIPKEY],
                  (unsigned long)[[ud dataForKey:CK6_UD_BLOBKEY] length],
                  g_patch_ok, g_patch_total, g_swizzle_ok);
        }
    });
    g_timer = t;
    dispatch_resume(t);
}

// ───────────────────────── 入口 ─────────────────────────
__attribute__((constructor))
static void CK6_ctor(void) {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"?";
        if (![bid isEqualToString:CK6_BUNDLE_ID]) {
            // 注入进错进程：完全静默，不动任何东西
            NSLog(@"[bypass6] 宿主不是 PitchKit (%@)，本 dylib 不动作", bid);
            return;
        }
        CKLog(@"══ bypass6 装载 ══ 宿主=%@ ver=%@", bid,
              [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]);
        CK6_locate_target();
        if (!g_mh) { CKLog(@"✗ 未找到主二进制映像，仅 A/B/D 数据层生效"); }
        CK6_install_swizzle();          // B：先于一切 App 代码
        CK6_forge_defaults(YES);        // A：抢在 viewDidLoad 恢复之前
        if (g_mh) CK6_apply_patches();  // C：UUID+逐点字节双校验
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            CK6_make_hud();
            CKLog(@"状态:\n%@", CK6_status_line());
        });
        CK6_watchdog();                 // D
        CKLog(@"装载完成：9 个功能门（boolForKey:\"isVipValid\"）恒通，"
              @"启动恢复链将原生判为永久会员(vip_type=2)");
    }
}
