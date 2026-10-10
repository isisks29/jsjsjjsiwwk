// ═══════════════════════════════════════════════════════════════════
//  bypass5.m — 第五课授权靶场 (Zhuanz-第五课-授权靶场.dylib) 激活 + 悬浮球
//
//  路线：本地强制"已验证会话"状态 + 直调仍完整的悬浮球安装器 + 卡密弹窗拦截
//  依据（全部来自 Ghidra 导出 + 反汇编逐条确认）：
//    · 会话魔数   [base+0x13e8748]=0x7a31c9e5  [base+0x13e874c]=0xb4f27e13
//                 (FUN_0014bc8c 验证成功后写入；安装器 FUN_001514c0 开头 ldar 比对)
//    · 激活旗标   [base+0x13a2720] 字节 (安装器 ldrb+tbz #0；封印解析成功也置 1)
//    · 授权字段   0x13a2750/2758/2760/2768 = NSString*4 (悬浮球标题/面板头显示)
//                 0x13a2770/2778 = int64 (解析要求非 0，无其它消费者)
//    · 悬浮球视图 0x13a2728 (UIButton*)  重试计数 0x13a2790 (int64, <0x1e)
//    · 安装器     FUN_001514c0：主线程直调；自带 keyWindow 重试 30×0.4s；
//                 已有 superview 时幂等早退。所有原生调用点(Ra_x1nY_Install/
//                 _JH_OnLicenseChange/00152ab4/00152b3c/001574f4)均为 68B 空壳，
//                 故必须由我们代调 —— 这正是"真激活也不出球"的原因。
//    · 密钥派生   FUN_0014bc8c(NSData≥32B) 惰性 dlsym CC 符号→HMAC 派生会话密钥
//                 →置魔数；FUN_0014618c(NSData≥32B) 派生功能密钥并打印
//                 "tweak bypass enabled after license verification"。
//                 我们喂一份自造 32B proof，派生全走目标自己的逻辑。
//    · 卡密弹窗   FUN_0013ca64：UIAlertController+1输入框，经 presentViewController:
//                 呈现；标题串由 FUN_0013ddfc 运行时解码到 0x25eebc(≤19B)。
//                 swizzle present 精确按标题拦截；兜底：启动 3 分钟内带输入框
//                 的 alert 且我方已激活时一并拦下。
//    · 反制维持   FUN_00150cc8(远程 kill 路径)会清旗标/字段/魔数 → 2s 看门狗重申。
//    · 目标识别   文件名 1.dylib/Zhuanz/第五课/授权靶场 + __TEXT vmsize==0x23c000
//                 + LC_UUID 90229b4c-… 三重校验，防误伤其它注入镜像。
//
//  不修改目标 .text；只写 .data/.bss 状态位——与验证成功路径写入的是同一批全局。
// ═══════════════════════════════════════════════════════════════════

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CommonCrypto/CommonDigest.h>
#import <unistd.h>

// ═══ v9.01 目标定位 ═══

static uint8_t *g_tbase = NULL;          // 目标 dylib 运行时基址
static BOOL     g_armed  = NO;           // 首拍激活序列已完成
static BOOL     g_booted = NO;           // CK_boot 只完整跑一次
static BOOL     g_swizzled = NO;         // present swizzle 只装一次
static int      g_ticks  = 0;            // 看门狗拍数

#define T(off) ((void *)(g_tbase + (off)))

// 关键偏移（Ghidra 静态地址，__TEXT vmaddr=0，运行时 = base + off）
static const uint64_t OFF_MAGIC_A   = 0x13e8748;   // uint32 0x7a31c9e5
static const uint64_t OFF_MAGIC_B   = 0x13e874c;   // uint32 0xb4f27e13
static const uint64_t OFF_LIC_FLAG  = 0x13a2720;   // uint8  激活旗标
static const uint64_t OFF_F_NAME    = 0x13a2750;   // NSString* 悬浮球标题
static const uint64_t OFF_F_CARD    = 0x13a2758;   // NSString*
static const uint64_t OFF_F_EXPSTR  = 0x13a2760;   // NSString* 面板到期显示
static const uint64_t OFF_F_DEV     = 0x13a2768;   // NSString*
static const uint64_t OFF_F_NUM1    = 0x13a2770;   // int64
static const uint64_t OFF_F_NUM2    = 0x13a2778;   // int64
static const uint64_t OFF_BALL      = 0x13a2728;   // UIButton* 悬浮球
static const uint64_t OFF_RETRY     = 0x13a2790;   // int64 keyWindow 重试计数

static const uint64_t OFF_FN_INSTALLER = 0x1514c0; // FUN_001514c0 装球
static const uint64_t OFF_FN_SESSION   = 0x14bc8c; // FUN_0014bc8c 会话密钥+魔数
static const uint64_t OFF_FN_ENABLE    = 0x14618c; // FUN_0014618c 功能密钥派生
static const uint64_t OFF_FN_DLG_TITLE = 0x13ddfc; // FUN_0013ddfc 标题串解码器
static const uint64_t OFF_FN_DLG_BTN   = 0x13df48; // FUN_0013df48 按钮串解码器
static const uint64_t OFF_STR_DLG_TITLE= 0x25eebc; // 解码后 char[19]
static const uint64_t OFF_STR_DLG_BTN  = 0x25ed2d; // 解码后 char[13]

typedef void (*fn_void_t)(void);
typedef void (*fn_data_t)(void *);

static void CKLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[ck5] %@", s);
}

// LC_UUID 前 4 字节 90229b4c（README: 90229b4c-2096-39c2-b3bc-1aa1d505ccc6）
static BOOL CK_uuid_match(const struct mach_header_64 *h) {
    const uint8_t *p = (const uint8_t *)h + sizeof(*h);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_UUID) {
            const struct uuid_command *uc = (const struct uuid_command *)lc;
            return uc->uuid[0] == 0x90 && uc->uuid[1] == 0x22 &&
                   uc->uuid[2] == 0x9b && uc->uuid[3] == 0x4c;
        }
        p += lc->cmdsize;
    }
    return NO;
}

static BOOL CK_text_size_ok(const struct mach_header_64 *h) {
    const uint8_t *p = (const uint8_t *)h + sizeof(*h);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64 &&
            strncmp(((const struct segment_command_64 *)lc)->segname, "__TEXT", 16) == 0) {
            return ((const struct segment_command_64 *)lc)->vmsize == 0x23c000;
        }
        p += lc->cmdsize;
    }
    return NO;
}

#import <dlfcn.h>

static void CK_try_dlopen(void) {
    // 目标安装名就是 /Library/1.dylib（LC_ID_DYLIB）；若注入器没把它带进进程，
    // 我们自己拉进来。文件不存在时 dlopen 返回 NULL，无害。
    static BOOL tried = NO;
    if (tried) return;
    tried = YES;
    CKLog(@"镜像表未见目标，尝试 dlopen /Library/1.dylib");
    void *h = dlopen("/Library/1.dylib", RTLD_NOW);
    CKLog(@"dlopen 结果=%p err=%s", h, h ? "-" : (dlerror() ?: "?"));
}

static void CK_find_target(void) {
    if (g_tbase) return;
    uint32_t n = _dyld_image_count();
    // 第一轮：只认 LC_UUID（决定性特征），不依赖文件名——
    // 注入器可能把靶场改名成任意名字
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *h =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        if (!CK_uuid_match(h)) continue;
        if (!CK_text_size_ok(h)) {
            CKLog(@"UUID 命中但 __TEXT 尺寸不符 #%u %s（跳过）", i,
                  _dyld_get_image_name(i) ?: "?");
            continue;
        }
        g_tbase = (uint8_t *)h;
        CKLog(@"命中目标(UUID) #%u %s base=%p slide=%p",
              i, _dyld_get_image_name(i) ?: "?", g_tbase,
              (void *)_dyld_get_image_vmaddr_slide(i));
        return;
    }
    // 第二轮：名字兜底（万一老师重编译过、UUID 变了）
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "/usr/lib/") || strstr(nm, "/System/Library/") ||
            strstr(nm, "/Developer/")) continue;
        const struct mach_header_64 *h =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        BOOL name_hit = (strstr(nm, "1.dylib") || strstr(nm, "Zhuanz") ||
                         strstr(nm, "第五课") || strstr(nm, "授权靶场"));
        if (!name_hit) continue;
        if (!CK_text_size_ok(h)) continue;
        g_tbase = (uint8_t *)h;
        CKLog(@"命中目标(名字) #%u %s base=%p slide=%p",
              i, nm, g_tbase, (void *)_dyld_get_image_vmaddr_slide(i));
        return;
    }
}


// ═══ v9.02b 屏幕角标（无日志环境的状态回显）═══

static UILabel *g_hud = nil;

static void CK_hud(NSString *text, BOOL ok) {
    dispatch_block_t work = ^{
        UIWindow *kw = nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.isKeyWindow) { kw = w; break; }
        }
        if (!kw) kw = [UIApplication sharedApplication].windows.firstObject;
        if (!kw) return;
        if (!g_hud) {
            g_hud = [[UILabel alloc] initWithFrame:CGRectMake(8, 0, 320, 22)];
            g_hud.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightBold];
            g_hud.layer.zPosition = 9999;
            g_hud.userInteractionEnabled = NO;
            [kw addSubview:g_hud];
        }
        if (!g_hud.superview) [kw addSubview:g_hud];
        g_hud.textColor = ok ? [UIColor colorWithRed:0.2 green:0.9 blue:0.4 alpha:1]
                             : [UIColor colorWithRed:1 green:0.35 blue:0.3 alpha:1];
        g_hud.text = text;
        CGRect f = g_hud.frame;
        f.origin.y = kw.safeAreaInsets.top + 2;
        g_hud.frame = f;
    };
    if ([NSThread isMainThread]) work();
    else dispatch_async(dispatch_get_main_queue(), work);
}

// ═══ v9.02 授权状态强制 ═══

static NSString *g_keep_name = nil, *g_keep_card = nil,
                *g_keep_exp  = nil, *g_keep_dev  = nil;
static NSData   *g_proof = nil;

static void CK_make_proof(void) {
    if (g_proof) return;
    const char *seed = "CK5-ZHUANZ-LOCAL-ACTIVATION-PROOF";
    unsigned char md[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(seed, (CC_LONG)strlen(seed), md);
    g_proof = [[NSData alloc] initWithBytes:md length:32];
}

static void CK_poke_state(BOOL verbose) {
    *(volatile uint32_t *)T(OFF_MAGIC_A) = 0x7a31c9e5u;
    *(volatile uint32_t *)T(OFF_MAGIC_B) = 0xb4f27e13u;
    if (!g_keep_name) {
        g_keep_name = [[NSString alloc] initWithFormat:@"已激活"];
        g_keep_card = [[NSString alloc] initWithFormat:@"CK5-LOCAL-0001"];
        g_keep_exp  = [[NSString alloc] initWithFormat:@"2099-12-31"];
        g_keep_dev  = [[NSString alloc] initWithFormat:@"local"];
    }
    *(void * volatile *)T(OFF_F_NAME)   = (__bridge void *)g_keep_name;
    *(void * volatile *)T(OFF_F_CARD)   = (__bridge void *)g_keep_card;
    *(void * volatile *)T(OFF_F_EXPSTR) = (__bridge void *)g_keep_exp;
    *(void * volatile *)T(OFF_F_DEV)    = (__bridge void *)g_keep_dev;
    *(volatile int64_t *)T(OFF_F_NUM1)  = 0x7fffffffffffffffLL;
    *(volatile int64_t *)T(OFF_F_NUM2)  = 0x2710;
    *(volatile uint8_t *)T(OFF_LIC_FLAG) = 1;   // 旗标最后写
    if (verbose) {
        CKLog(@"状态写入: magic=%08x/%08x flag=%u",
              *(volatile uint32_t *)T(OFF_MAGIC_A),
              *(volatile uint32_t *)T(OFF_MAGIC_B),
              *(volatile uint8_t *)T(OFF_LIC_FLAG));
    }
}

// bc8c/enable 各只喂一次（内部会调度 dispatch_after 链，重复调用会叠闹钟）
static BOOL g_session_done = NO, g_enable_done = NO;

static void CK_run_session_and_enable(void) {
    CK_make_proof();
    if (!g_session_done) {
        g_session_done = YES;
        fn_data_t f = (fn_data_t)T(OFF_FN_SESSION);
        CKLog(@"调用会话派生 %p (proof %luB)", f, (unsigned long)g_proof.length);
        f((__bridge void *)g_proof);
        if (*(volatile uint32_t *)T(OFF_MAGIC_A) != 0x7a31c9e5u) {
            CKLog(@"会话派生未置魔数，直接写魔数兜底");
            *(volatile uint32_t *)T(OFF_MAGIC_A) = 0x7a31c9e5u;
            *(volatile uint32_t *)T(OFF_MAGIC_B) = 0xb4f27e13u;
        }
    }
    if (!g_enable_done) {
        g_enable_done = YES;
        fn_data_t f = (fn_data_t)T(OFF_FN_ENABLE);
        CKLog(@"调用功能密钥派生 %p", f);
        f((__bridge void *)g_proof);
    }
}

// ═══ v9.03 悬浮球安装器直调 ═══

static void CK_install_ball(void) {
    if (!g_tbase) return;
    void *ball = *(void * volatile *)T(OFF_BALL);
    UIView *bv = (__bridge UIView *)ball;
    if (bv && bv.superview) return;                 // 已上屏，幂等
    if (!bv) *(volatile int64_t *)T(OFF_RETRY) = 0; // 内部重试计数复位
    fn_void_t inst = (fn_void_t)T(OFF_FN_INSTALLER);
    CKLog(@"直调安装器 %p (ball=%p)", inst, ball);
    inst();
}

// ═══ v9.04 卡密弹窗拦截 ═══

static char g_dlg_title[24] = {0};
static BOOL g_dlg_title_ok = NO;

static void CK_decode_dialog_strings(void) {
    if (g_dlg_title_ok || !g_tbase) return;
    // 解码器幂等（内部一次性旗标 0x25eecf/0x25ed3a），可安全代调
    ((fn_void_t)T(OFF_FN_DLG_TITLE))();
    ((fn_void_t)T(OFF_FN_DLG_BTN))();
    const char *t = (const char *)T(OFF_STR_DLG_TITLE);
    const char *b = (const char *)T(OFF_STR_DLG_BTN);
    size_t n = strnlen(t, 19);          // 缓冲区共 19B，含结尾 NUL
    if (n == 0 || n > 18) { CKLog(@"弹窗标题解码异常 n=%zu", n); return; }
    memcpy(g_dlg_title, t, n);
    g_dlg_title[n] = 0;
    g_dlg_title_ok = YES;
    CKLog(@"卡密弹窗标题已解码: 「%s」按钮「%.*s」",
          g_dlg_title, (int)strnlen(b, 13), b ? b : "?");
}

static void (*g_orig_present)(id, SEL, id, BOOL, void (^)(void));

static BOOL CK_is_card_dialog(id vc) {
    if (![vc isKindOfClass:[UIAlertController class]]) return NO;
    UIAlertController *a = (UIAlertController *)vc;
    if (g_dlg_title_ok && a.title) {
        NSString *t = [[NSString alloc] initWithUTF8String:g_dlg_title];
        if (t && [a.title isEqualToString:t]) return YES;
    }
    // 兜底：启动 3 分钟内、我方已激活、带输入框的 alert → 视为卡密弹窗拦下
    if (g_armed && g_ticks < 90) {
        @try {
            NSArray *tfs = [a valueForKey:@"textFields"];
            if (tfs.count > 0) {
                CKLog(@"兜底拦截带输入框弹窗: 「%@」", a.title ?: @"(无题)");
                return YES;
            }
        } @catch (NSException *e) {}
    }
    return NO;
}

static void CK_present_hook(id self, SEL _cmd, id vc, BOOL anim, void (^comp)(void)) {
    (void)self; (void)_cmd; (void)anim;
    if (CK_is_card_dialog(vc)) {
        CKLog(@"拦截卡密弹窗 present: 「%@」", [(UIAlertController *)vc title] ?: @"?");
        if (comp) comp();
        return;
    }
    g_orig_present(self, _cmd, vc, anim, comp);
}

static void CK_install_present_swizzle(void) {
    if (g_swizzled) return;
    Class cls = [UIViewController class];
    SEL sel = @selector(presentViewController:animated:completion:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { CKLog(@"present swizzle 失败: 方法未找到"); return; }
    g_swizzled = YES;
    g_orig_present = (void (*)(id, SEL, id, BOOL, void (^)(void)))method_getImplementation(m);
    method_setImplementation(m, (IMP)CK_present_hook);
    CKLog(@"present swizzle 完成");
}

// ═══ v9.05 看门狗与启动序列 ═══

static dispatch_source_t g_timer = nil;

static void CK_watchdog(void) {
    g_ticks++;
    if (!g_tbase) {
        CK_find_target();
        if (!g_tbase) {
            if (g_ticks == 3) CK_try_dlopen();     // 第 3 拍仍没找到 → 自己拉
            CK_hud([NSString stringWithFormat:@"bypass5: 找靶场中… t=%d", g_ticks], NO);
            return;
        }
        CK_hud(@"bypass5: 靶场已定位，激活中…", NO);
        CKLog(@"看门狗内定位到目标，补跑激活序列");
        CK_decode_dialog_strings();
        dispatch_async(dispatch_get_main_queue(), ^{
            CK_poke_state(YES);
            CK_run_session_and_enable();
            CK_poke_state(YES);
            g_armed = YES;
            CK_install_ball();
            CK_hud(@"bypass5: 已激活", YES);
        });
        return;
    }
    CK_poke_state(NO);                    // 对抗远程清除路径
    void *ball = *(void * volatile *)T(OFF_BALL);
    UIView *bv = (__bridge UIView *)ball;
    if (!bv || !bv.superview) CK_install_ball();   // 定时器在主队列，直接调
    if (g_ticks <= 30 && g_ticks % 5 == 0) {
        CKLog(@"体检 t=%d magic=%08x/%08x flag=%u ball=%p superview=%p",
              g_ticks,
              *(volatile uint32_t *)T(OFF_MAGIC_A),
              *(volatile uint32_t *)T(OFF_MAGIC_B),
              *(volatile uint8_t *)T(OFF_LIC_FLAG),
              bv, bv ? bv.superview : nil);
        CK_hud([NSString stringWithFormat:@"bypass5: 已激活 球%@ t=%d",
                (bv && bv.superview) ? @"在屏" : @"未上屏", g_ticks],
               (bv && bv.superview) ? YES : NO);
    }
}

static void CK_boot(void) {
    if (g_booted) return;
    g_booted = YES;

    CK_find_target();
    if (g_tbase) {
        CKLog(@"目标 base=%p", g_tbase);
        CK_decode_dialog_strings();
    } else {
        CKLog(@"启动时未见目标镜像，交给看门狗轮询");
    }
    CK_install_present_swizzle();         // 先装拦截再激活，弹窗无缝隙
    CK_make_proof();

    if (g_tbase) {
        dispatch_async(dispatch_get_main_queue(), ^{
            CK_poke_state(YES);
            CK_run_session_and_enable();
            CK_poke_state(YES);
            g_armed = YES;
            CK_install_ball();
            CKLog(@"首拍激活序列完成: magic=%08x flag=%u ball=%p",
                  *(volatile uint32_t *)T(OFF_MAGIC_A),
                  *(volatile uint8_t *)T(OFF_LIC_FLAG),
                  *(void * volatile *)T(OFF_BALL));
            CK_hud(@"bypass5: 已激活", YES);
        });
    }

    if (!g_timer) {
        g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                         dispatch_get_main_queue());
        dispatch_source_set_timer(g_timer,
                                  dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                                  (uint64_t)(2.0 * NSEC_PER_SEC),
                                  (uint64_t)(0.2 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(g_timer, ^{ CK_watchdog(); });
        dispatch_resume(g_timer);
    }
}

__attribute__((constructor))
static void CK5_main(void) {
    CKLog(@"bypass5 v9.02 加载 (第五课·强制激活+悬浮球+HUD) pid=%d", getpid());
    CK_boot();
}

__attribute__((constructor))
static void CK5_main2(void) {
    // 防呆：半秒后若仍未定位到目标，再扫一遍并补跑
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!g_booted) CK_boot();
        else if (!g_tbase) { CK_find_target(); }
    });
}
