// =====================================================================
//  bypass7.m — 第七课 v1.04（快连 VPN / Catspiration · com.zheyoutech.app v1.03）
//  目标：注入后直接获得会员权益（SVIP 界面 + 连接不被拒 + 会话不被服务端掐断）
//
//  ▍v1.04 变更（实测：choose 已 200 下发 accessLink，但「网络异常」且连不上；
//             该文案不在两个二进制/资源里 → 服务端下发或系统层，且不走已钩 API）
//   1. NE 观测钩子：saveToPreferences / loadAll / load / startVPNTunnel×2
//      全部包日志——entitlement 缺失、VPN 权限被拒、配置保存失败等系统层
//      真实错误直接进诊断（最后一公里失败点现形）
//   2. SVProgressHUD 追加 showSuccess/showInfo/showImage:status: 日志钩子
//   3. UILabel setText: 关键词哨兵（网络异常/失败/错误/权限/denied/无法，
//      3s 去重、先放行后记录，零行为影响）——无论文案从哪条路渲染都能抓到
//   4. L1 到期时间按服务端格式改写：字符串型 → "2100-12-31 00:00:00"
//      （实测服务端格式 yyyy-MM-dd HH:mm:ss），界面不再显示裸时间戳
//   5. 实测确认：游客未注册即自动获 10 分钟会员试用（vipGranted=1 +
//      vipExpires=now+10min，服务端下发）；体验时长不按设备限领（L6 保留作后备）
//
//  ▍v1.03 变更（实测：901「未开通会员或会员已过期」；新账号无免费时长）
//   1. L6 设备码轮换：出站 JSON 同点交换 dataWithJSONObject:options:error:，
//      请求体 rk_terminalCode_mv（HardwareUnitStore 的 UUID().uuidString，
//      FUN_10006a48c 实证）统一替换为持久化轮换 UUID → 服务端把新注册
//      视为新设备，体验时长按设备限领时被绕过
//   2. 诊断增强：信封日志追加会员/新人字段值（newcomer/vipGranted/
//      vipExpires/accountRole/joinedAt/usedAt/signInCount/welcomeSeconds，
//      敏感值不落日志）+ relayDetails 摘要；HUD 加 T(设备码改写) 计数
//   3. 诊断文本含轮换码与 L6 计数；看门狗自愈同时护两个方向的交换
//
//  ▍v1.02 变更
//   1. 悬浮窗单击 = 一键复制完整诊断到剪贴板（模式/UUID/五层计数/最近60条
//      日志环形缓存），直接粘贴即可提交分析；HUD 短暂显示「✓ 诊断已复制」
//   2. 长按悬浮窗 = 原弹窗详情；拖动不变
//   3. HUD 计数改纯 ASCII（C1/C0 代替 ✓/✗，部分字体渲染成方框）
//   4. CKLog 全部进入线程安全环形缓存（信封/toast/重放记录都能被复制出来）
//
//  ▍v1.01 变更（实测反馈：点连接无反应且无任何提示）
//   1. L3 不再无脑吞错误 toast：仅当兜底可用（有缓存 link 或系统已保存
//      隧道配置）才吞并直启；否则原样放行并打日志——v1.00 在两者皆无时
//      把服务端的真实拒绝原因（如 permission denied）静默吃掉了
//   2. 新增信封诊断日志：主程序每个 API 回包打印 state/note/bodyKeys，
//      直接看清 route/choose 到底回了什么
//   3. 所有 SVProgressHUD 错误 toast 全量入日志（含被放行的）
//   4. 新增 g_savedCfg 探测（启动 4s + 每 30s）：loadAllFromPreferences
//      检查系统里有无本 App 隧道配置；HUD 增加 S(已存配置)/W(吞toast) 字段
//
//  ▍靶场结构（全部来自 Ghidra 导出 + 原始二进制交叉验证）
//   主程序  Payload/Catspiration.app/Catspiration        (4,071,968 B, Swift)
//   隧道    PlugIns/Tunnel.appex/Tunnel                  (8,476,320 B, Swift+Rust leaf)
//   App组   group.com.zheyoutech.app（token/隧道配置共享容器）
//
//  ▍服务端 API（信封 {rk_responseState_mv:Int, rk_statusNote_mv:String,
//                       rk_responseBody_mv:{...}}）
//   /vzmr/gateway/visitor   游客登录     → FUN_100005a80 / 处理 FUN_100006474
//   /vzmr/gateway/account   账号登录     → FUN_10001f404 / 处理 FUN_1000200b0
//   /vzmr/member/enlist     注册         → FUN_100022f40
//   /vzmr/member/summary    会员信息     → FUN_1000105a4 / 处理 FUN_100010a30
//   /vzmr/route/ready       节点列表     → FUN_10000b318 / FUN_100012940
//   /vzmr/route/choose      取节点配置   → FUN_10007d218（重连 FUN_10007ff3c）
//   /vzmr/route/keep        隧道保活     → 仅 Tunnel 进程 FUN_10001c208
//   /vzmr/checkout/open|verify、/vzmr/mall/options（充值）
//   登录成功 → token 存 App组 UserDefaults["kAccessToken"]（TokenManager，
//              init FUN_100074014，明文、无签名）
//
//  ▍会员判定链（客户端读到的字段）
//   member/summary 的 body 整体存入 userDetails 字典：
//    · rk_vipGranted_mv  Int  ==0 → HomeMemberView 显示「会员已过期」
//                                        (FUN_10001a258 @0x10001a288)
//                               !=0 → 显示「会员到期时间：」+ rk_vipExpires_mv
//    · PersonalListCell (FUN_10003a878) 用 rk_accountRole_mv + rk_vipGranted_mv
//      切换 会员/非会员 两套面板
//    · PersonalWithMembershipView (FUN_100042420) 副标题拼 rk_vipExpires_mv
//   连接授权（服务端）：
//    · route/choose 返回 state==901 → 弹订阅窗 SubscriptionView (FUN_100084698)
//    · stateNote=="permission denied" → 原样 toast（FUN_10000e650 @0x10000e660）
//    · state==200 → body.rk_accessLink_mv = AES-128-ECB(硬编码key
//      "81zvl1fk9mcruawg" @0x1002a6de0) + base64("vmess://"+base64(JSON))
//      → 解密解析(FUN_1000841b4) → 写 App组 running_config.json +
//      NETunnelProviderProtocol 存系统偏好(FUN_1000790c8) → startVPNTunnel
//   会话掐断（服务端）：
//    · Tunnel 进程周期 POST route/keep；回包 body.rk_connectionState_mv==0
//      → 主队列异步停隧道（FUN_10001c208 尾部，0x10001c628 判 0）
//   客户端没有任何本地时长扣减/断开逻辑（TemporalMetricAccumulator
//   FUN_10001d1c4 只把已连时长格式化成 %02d:%02d:%02d 更新 UI 标签）。
//
//  ▍攻击面（本 dylib 全部为运行时手法，零指令补丁，不依赖二进制版本）
//   全 App 的 JSON 响应都经 +[NSJSONSerialization JSONObjectWithData:options:error:]
//   （主程序 FUN_1000b38d8 @0x1000b3d8c 一带；Tunnel 同型 3 处），单点交换即可：
//   [主程序] L1 会员字段改写：任何含 rk_vipGranted_mv 的字典 → 强制 granted=1、
//            expires=4133376000（2100-12-31），保持原值类型（Int/String），
//            覆盖 summary/login 全部回包 → 一进入即全套 SVIP 界面
//   [主程序] L2 拒绝重放：缓存最近一次成功的 rk_accessLink_mv；
//            收到 state==901 或 note 含 "permission denied" 的信封时，
//            整体替换为合成的 200 成功信封（带缓存 link）→ 走 App 自己的
//            解密/写配置/起隧道成功路径，时长耗尽/无权限也能连
//   [主程序] L3 直启兜底：hook SVProgressHUD showErrorWithStatus:，命中
//            连接失败文案时吞掉 toast，1.5s 后经 dlopen(NetworkExtension)
//            NETunnelProviderManager.loadAllFromPreferences →
//            startVPNTunnelWithOptions 直接拉起系统里已保存的隧道偏好
//            （running_config.json 仍在 App 组容器 → 无需服务端参与）
//   [隧道]   L4 保活免疫：rk_connectionState_mv==0 → 改写为 1（掐不断）；
//            keep 回包异常时用上次缓存的健康回包顶替
//   [通用]   L5 2s 看门狗：swizzle 自愈 + HUD（主程序）+ 30s 心跳日志
//
//  ▍前提
//   · 需至少成功连过一次（新用户有 rk_welcomeSeconds_mv 体验时长），
//     以缓存 accessLink / 留存系统隧道偏好；此后完全脱钩服务端授权
//   · 注入器需同时覆盖主程序与 Tunnel.appex（越狱注入按 bundle 过滤时
//     两个 id 都要放行；只注入主程序也有 L1+L2+L3 完整效果）
// =====================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

#define CK7_APP_BID     "com.zheyoutech.app"
#define CK7_TUNNEL_BID  "com.zheyoutech.app.tunnel"
#define CK7_PROVIDER    "com.zheyoutech.app.tunnel"

// 服务端信封 / 会员字段（与二进制 __cstring 逐一核对）
static NSString *const kCK7State  = @"rk_responseState_mv";
static NSString *const kCK7Note   = @"rk_statusNote_mv";
static NSString *const kCK7Body   = @"rk_responseBody_mv";
static NSString *const kCK7Vip    = @"rk_vipGranted_mv";
static NSString *const kCK7Exp    = @"rk_vipExpires_mv";
static NSString *const kCK7Link   = @"rk_accessLink_mv";
static NSString *const kCK7Conn   = @"rk_connectionState_mv";
// 本 dylib 自己的缓存键（standardUserDefaults，避免污染 App 组容器）
static NSString *const kCK7CacheLink = @"ck7_cached_access_link";
static NSString *const kCK7CacheKeep = @"ck7_cached_keep_envelope";
static NSString *const kCK7RotatedDev = @"ck7_rotated_device_code";  // v1.03
// v1.03: 请求体里的设备码键（HardwareUnitStore 生成 UUID().uuidString 存 Keychain，
//        FUN_10006a48c 实证）——服务端体验时长按它限领，故出站统一轮换
static NSString *const kCK7TermCode = @"rk_terminalCode_mv";
// 伪造的到期时间：2100-12-31 00:00:00 UTC
static const long long kCK7ExpForever = 4133376000LL;

typedef NS_ENUM(NSInteger, CK7Mode) {
    CK7ModeInert = 0,
    CK7ModeApp,
    CK7ModeTunnel,
};

static CK7Mode g_mode = CK7ModeInert;
static long g_vipRewrite = 0;    // L1 命中次数
static long g_replay = 0;        // L2 重放次数
static long g_linkSeen = 0;      // 缓存 link 更新次数
static long g_cutBlocked = 0;    // L4 掐断拦截次数
static long g_keepReplay = 0;    // L4 keep 重放次数
static long g_directStart = 0;   // L3 直启次数
static long g_toastSeen = 0;     // v1.01: 看到的错误 toast 数
static long g_toastSwallowed = 0;// v1.01: 有兜底时吞掉的 toast 数
static BOOL g_savedCfg = NO;     // v1.01: 系统里是否有本 App 已保存的隧道配置
static long g_devRewrite = 0;    // v1.03: 出站请求设备码改写次数
static BOOL g_inReqRewrite = NO; // v1.03: 出站重序列化防递归
static long g_tick = 0;
static dispatch_source_t g_timer = nil;
static UIControl *g_hud = nil;
static UILabel *g_hudLabel = nil;
static BOOL g_swizzled = NO;
// JSONSerialization 原始 IMP（提前声明：隧道缓存解析需绕过钩子防递归）
static id (*g_origJSON)(id, SEL, NSData *, NSJSONReadingOptions, NSError **);

#pragma mark - 日志

static NSString *CK7StatusLine(void);   // 前置声明（HUD/直启共用）

// v1.02: 环形日志缓存（点悬浮窗一键复制诊断用），多线程安全
#define CK7_RING_MAX 60
static NSMutableArray<NSString *> *g_logRing = nil;

static void CK7RingInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ g_logRing = [NSMutableArray array]; });
}

static void CKLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[bypass7] %@", msg);
    CK7RingInit();
    @synchronized (g_logRing) {
        [g_logRing addObject:msg];
        while (g_logRing.count > CK7_RING_MAX) [g_logRing removeObjectAtIndex:0];
    }
}

static NSString *CK7UUIDHex(void) {
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!mh) return @"?";
    uintptr_t p = (uintptr_t)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_UUID) {
            const struct uuid_command *uc = (const struct uuid_command *)lc;
            NSMutableString *s = [NSMutableString string];
            for (int j = 0; j < 16; j++)
                [s appendFormat:@"%02x", uc->uuid[j]];
            return s;
        }
        p += lc->cmdsize;
    }
    return @"?";
}

#pragma mark - L1/L2/L4 JSON 改写

// 递归改写；返回（可能是新的）对象。copy-on-write，未命中原样返回。
static id CK7Rewrite(id obj, NSInteger depth);

static BOOL CK7DictHasVIPKey(NSDictionary *d) {
    return [d isKindOfClass:[NSDictionary class]] && d[kCK7Vip] != nil;
}

static id CK7RewriteVIPDict(NSDictionary *d) {
    NSMutableDictionary *m = [d mutableCopy];
    id g = d[kCK7Vip];
    // 保持原类型：Int→NSNumber，String→NSString（App 端 dynamicCast 依赖类型）
    m[kCK7Vip] = [g isKindOfClass:[NSString class]] ? @"1" : @(1);
    id e = d[kCK7Exp];
    // v1.04: 服务端日期格式实证为 "yyyy-MM-dd HH:mm:ss"（如 2026-10-25 15:04:57），
    // 字符串型给同格式远期日期，数字型给 epoch，界面显示不再出现裸时间戳
    if (e == nil) {
        m[kCK7Exp] = @(kCK7ExpForever);
    } else if ([e isKindOfClass:[NSString class]]) {
        m[kCK7Exp] = @"2100-12-31 00:00:00";
    } else {
        m[kCK7Exp] = @(kCK7ExpForever);
    }
    g_vipRewrite++;
    return m;
}

static void CK7CacheLink(NSString *link) {
    if (![link isKindOfClass:[NSString class]] || link.length < 16) return;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSString *old = [ud stringForKey:kCK7CacheLink];
    if (![link isEqualToString:old]) {
        [ud setObject:link forKey:kCK7CacheLink];
        g_linkSeen++;
        CKLog(@"L2 已缓存 accessLink（%lu 字节）", (unsigned long)link.length);
    }
}

static NSString *CK7CachedLink(void) {
    return [[NSUserDefaults standardUserDefaults] stringForKey:kCK7CacheLink];
}

static BOOL CK7IsDeniedEnvelope(NSDictionary *d) {
    id st = d[kCK7State];
    if (![st isKindOfClass:[NSNumber class]]) return NO;
    if ([st integerValue] == 901) return YES;
    id note = d[kCK7Note];
    if ([note isKindOfClass:[NSString class]] &&
        [(NSString *)note rangeOfString:@"permission denied"
                                options:NSCaseInsensitiveSearch].location != NSNotFound)
        return YES;
    return NO;
}

// ---- 主程序模式：VIP 改写 + accessLink 缓存 + 拒绝重放 ----
static id CK7RewriteApp(id obj, NSInteger depth) {
    if (depth > 5) return obj;
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)obj;
        // v1.01: 信封诊断日志（state/note/body 键名，定位“点击无反应”）
        if (d[kCK7State] != nil) {
            id body = d[kCK7Body];
            NSArray *bk = [body isKindOfClass:[NSDictionary class]]
                              ? ((NSDictionary *)body).allKeys : @[];
            NSString *note = [d[kCK7Note] isKindOfClass:[NSString class]]
                                 ? (NSString *)d[kCK7Note] : @"(非字符串)";
            if (note.length > 80) note = [[note substringToIndex:80] stringByAppendingString:@"…"];
            CKLog(@"信封 state=%@ note=「%@」 bodyKeys=%@", d[kCK7State], note, bk);
            // v1.03: 会员/新人相关字段值（白名单，敏感值不落日志）
            if ([body isKindOfClass:[NSDictionary class]]) {
                NSDictionary *bd = (NSDictionary *)body;
                for (NSString *vk in @[ @"rk_newcomer_mv", @"rk_vipGranted_mv",
                                        @"rk_vipExpires_mv", @"rk_accountRole_mv",
                                        @"rk_joinedAt_mv", @"rk_usedAt_mv",
                                        @"rk_signInCount_mv", @"rk_welcomeSeconds_mv" ]) {
                    if (bd[vk]) CKLog(@"  ↳ %@ = %@", vk, bd[vk]);
                }
                id relay = bd[@"rk_relayDetails_mv"];
                if (relay) {
                    NSString *rs = [relay description];
                    if (rs.length > 200) rs = [[rs substringToIndex:200] stringByAppendingString:@"…"];
                    CKLog(@"  ↳ rk_relayDetails_mv ≈ %@", rs);
                }
            }
        }
        // 顶层信封：被拒 → 用缓存 link 合成成功信封
        if (d[kCK7State] != nil && d[kCK7Note] != nil && CK7IsDeniedEnvelope(d)) {
            NSString *link = CK7CachedLink();
            if (link.length > 0) {
                g_replay++;
                CKLog(@"L2 拦截拒绝信封(state=%@)，重放缓存 accessLink",
                      d[kCK7State]);
                return @{ kCK7State : @(200),
                          kCK7Note  : @"ok",
                          kCK7Body  : @{ kCK7Link : link } };
            }
            CKLog(@"L2 收到拒绝信封但无缓存 link（需先成功连过一次）");
        }
        BOOL changed = NO;
        NSMutableDictionary *m = nil;
        for (NSString *k in d) {
            id v = d[k];
            if ([k isEqualToString:kCK7Link] && [v isKindOfClass:[NSString class]]) {
                CK7CacheLink(v);
            }
            id nv = CK7Rewrite(v, depth + 1);
            if (nv != v) {
                if (!m) m = [d mutableCopy];
                m[k] = nv;
                changed = YES;
            }
        }
        if (CK7DictHasVIPKey(d)) {
            id vip = CK7RewriteVIPDict(m ? m : d);
            return vip;
        }
        return changed ? m : obj;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSArray *a = (NSArray *)obj;
        NSMutableArray *m = nil;
        for (NSUInteger i = 0; i < a.count; i++) {
            id nv = CK7Rewrite(a[i], depth + 1);
            if (nv != a[i]) {
                if (!m) m = [a mutableCopy];
                m[i] = nv;
            }
        }
        return m ? m : obj;
    }
    return obj;
}

// ---- 隧道模式：保活免疫 ----
static void CK7CacheKeepEnvelope(NSDictionary *env) {
    NSError *err = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:env options:0 error:&err];
    if (json && !err) {
        NSString *b64 = [json base64EncodedStringWithOptions:0];
        [[NSUserDefaults standardUserDefaults] setObject:b64 forKey:kCK7CacheKeep];
    }
}

static NSDictionary *CK7CachedKeepEnvelope(void) {
    NSString *b64 = [[NSUserDefaults standardUserDefaults] stringForKey:kCK7CacheKeep];
    if (!b64) return nil;
    NSData *json = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (!json) return nil;
    // 直接走原始 IMP，避免经我们的 swizzle 造成递归重入
    id o = nil;
    if (g_origJSON) {
        o = g_origJSON([NSJSONSerialization class],
                       @selector(JSONObjectWithData:options:error:), json, 0, NULL);
    }
    return [o isKindOfClass:[NSDictionary class]] ? o : nil;
}

static id CK7RewriteTunnel(id obj, NSInteger depth) {
    // keep 回包是顶层信封；只处理顶层 + body 一层
    if (![obj isKindOfClass:[NSDictionary class]]) return obj;
    NSDictionary *d = (NSDictionary *)obj;
    if (d[kCK7State] == nil) return obj;
    NSInteger state = [d[kCK7State] isKindOfClass:[NSNumber class]]
                          ? [d[kCK7State] integerValue] : -1;
    id body = d[kCK7Body];
    BOOL healthy = (state == 200) && [body isKindOfClass:[NSDictionary class]] &&
                   ((NSDictionary *)body)[kCK7Conn] != nil;
    if (healthy) {
        NSInteger conn = [((NSDictionary *)body)[kCK7Conn] integerValue];
        if (conn == 0) {
            // 服务端下令断开 → 改写为 1，会话保持
            NSMutableDictionary *nb = [body mutableCopy];
            id cv = nb[kCK7Conn];
            nb[kCK7Conn] = [cv isKindOfClass:[NSString class]] ? @"1" : @(1);
            NSMutableDictionary *ne = [d mutableCopy];
            ne[kCK7Body] = nb;
            g_cutBlocked++;
            CKLog(@"L4 拦截 keep 断开指令(connectionState=0→1) 第%ld次", g_cutBlocked);
            CK7CacheKeepEnvelope(ne);   // 缓存改写后的健康信封
            return ne;
        }
        CK7CacheKeepEnvelope(d);
        return obj;
    }
    // 非 200 / 结构异常 → 用缓存的健康 keep 回包顶替，防错误路径停隧道
    NSDictionary *cached = CK7CachedKeepEnvelope();
    if (cached) {
        g_keepReplay++;
        CKLog(@"L4 keep 回包异常(state=%ld)，重放缓存健康回包 第%ld次",
              (long)state, g_keepReplay);
        return cached;
    }
    return obj;
}

static id CK7Rewrite(id obj, NSInteger depth) {
    if (g_mode == CK7ModeApp) return CK7RewriteApp(obj, depth);
    if (g_mode == CK7ModeTunnel) return CK7RewriteTunnel(obj, depth);
    return obj;
}

#pragma mark - L6 设备码轮换（出站请求改写，v1.03）

// 轮换设备码：首次生成 UUID（与 HardwareUnitStore 同格式），持久化保证跨启动稳定
static NSString *CK7RotatedDeviceCode(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSString *code = [ud stringForKey:kCK7RotatedDev];
    if (code.length < 8) {
        code = [[NSUUID UUID].UUIDString uppercaseString];
        [ud setObject:code forKey:kCK7RotatedDev];
        CKLog(@"L6 生成轮换设备码 %@（持久化，跨启动稳定）", code);
    }
    return code;
}

// 递归改写请求对象里的 rk_terminalCode_mv；copy-on-write，未命中返回原对象
static id CK7RewriteRequestObject(id obj, NSInteger depth) {
    if (depth > 4) return obj;
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)obj;
        NSMutableDictionary *m = nil;
        id tc = d[kCK7TermCode];
        if ([tc isKindOfClass:[NSString class]]) {
            NSString *rot = CK7RotatedDeviceCode();
            if (![tc isEqualToString:rot]) {
                static BOOL logged = NO;
                if (!logged) {
                    logged = YES;
                    CKLog(@"L6 原始设备码 len=%lu 前8位=%@… → 一律替换为轮换码",
                          (unsigned long)((NSString *)tc).length,
                          [(NSString *)tc substringToIndex:MIN(8, ((NSString *)tc).length)]);
                }
                m = [d mutableCopy];
                m[kCK7TermCode] = rot;
                g_devRewrite++;
            }
        }
        for (NSString *k in d) {
            id nv = CK7RewriteRequestObject(d[k], depth + 1);
            if (nv != d[k]) {
                if (!m) m = [d mutableCopy];
                m[k] = nv;
            }
        }
        return m ? m : obj;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSArray *a = (NSArray *)obj;
        NSMutableArray *m = nil;
        for (NSUInteger i = 0; i < a.count; i++) {
            id nv = CK7RewriteRequestObject(a[i], depth + 1);
            if (nv != a[i]) {
                if (!m) m = [a mutableCopy];
                m[i] = nv;
            }
        }
        return m ? m : obj;
    }
    return obj;
}

static NSData *(*g_origJSONData)(id, SEL, id, NSJSONWritingOptions, NSError **);

static NSData *CK7DataWithJSONObject(id self, SEL _cmd, id obj,
                                     NSJSONWritingOptions opt, NSError **error) {
    if (g_mode == CK7ModeApp && !g_inReqRewrite &&
        [obj isKindOfClass:[NSDictionary class]] && ((NSDictionary *)obj)[kCK7TermCode]) {
        id rw = CK7RewriteRequestObject(obj, 0);
        if (rw != obj) {
            g_inReqRewrite = YES;
            NSData *out = g_origJSONData(self, _cmd, rw, opt, error);
            g_inReqRewrite = NO;
            return out;
        }
    }
    return g_origJSONData(self, _cmd, obj, opt, error);
}

#pragma mark - NSJSONSerialization swizzle（L1/L2/L4 的单点入口）

static id CK7JSONObjectWithData(id self, SEL _cmd, NSData *data,
                                NSJSONReadingOptions opt, NSError **error) {
    id obj = g_origJSON(self, _cmd, data, opt, error);
    if (obj && g_mode != CK7ModeInert) {
        @try {
            id rw = CK7Rewrite(obj, 0);
            if (rw != obj) {
                // 返回不可变副本，保持与原始返回一致的 +0 语义
                if ([rw isKindOfClass:[NSMutableDictionary class]] ||
                    [rw isKindOfClass:[NSMutableArray class]]) {
                    return [rw copy];
                }
                return rw;
            }
        } @catch (NSException *ex) {
            CKLog(@"改写异常: %@", ex);
        }
    }
    return obj;
}

static BOOL CK7InstallJSONSwizzle(void) {
    Class cls = [NSJSONSerialization class];
    SEL sel = @selector(JSONObjectWithData:options:error:);
    Method m = class_getClassMethod(cls, sel);
    if (!m) { CKLog(@"未找到 JSONObjectWithData:options:error:"); return NO; }
    IMP orig = method_getImplementation(m);
    if (orig != (IMP)CK7JSONObjectWithData) {
        g_origJSON = (id(*)(id, SEL, NSData *, NSJSONReadingOptions, NSError **))orig;
        method_setImplementation(m, (IMP)CK7JSONObjectWithData);
        CKLog(@"L1/L2/L4 JSON 响应单点交换完成 (原 IMP=%p)", (void *)orig);
    }
    g_swizzled = YES;
    // v1.03: 出站方向同点交换（设备码轮换）
    SEL sel2 = @selector(dataWithJSONObject:options:error:);
    Method m2 = class_getClassMethod(cls, sel2);
    if (m2) {
        IMP orig2 = method_getImplementation(m2);
        if (orig2 != (IMP)CK7DataWithJSONObject) {
            g_origJSONData = (NSData *(*)(id, SEL, id, NSJSONWritingOptions, NSError **))orig2;
            method_setImplementation(m2, (IMP)CK7DataWithJSONObject);
            CKLog(@"L6 JSON 请求单点交换完成 (原 IMP=%p)", (void *)orig2);
        }
    } else {
        CKLog(@"未找到 dataWithJSONObject:options:error:（L6 不可用）");
    }
    return YES;
}

static BOOL CK7SwizzleAlive(void) {
    Class cls = [NSJSONSerialization class];
    Method m = class_getClassMethod(cls, @selector(JSONObjectWithData:options:error:));
    BOOL ok = m && method_getImplementation(m) == (IMP)CK7JSONObjectWithData;
    Method m2 = class_getClassMethod(cls, @selector(dataWithJSONObject:options:error:));
    if (m2 && g_origJSONData &&
        method_getImplementation(m2) != (IMP)CK7DataWithJSONObject) ok = NO;
    return ok;
}

#pragma mark - L3 直启兜底（主程序）

static void CK7DirectStartTunnel(void) {
    void *ne = dlopen("/System/Library/Frameworks/NetworkExtension.framework/"
                      "NetworkExtension", RTLD_NOW);
    if (!ne) { CKLog(@"L3 dlopen NetworkExtension 失败: %s", dlerror()); return; }
    Class mgrCls = NSClassFromString(@"NETunnelProviderManager");
    if (!mgrCls) mgrCls = NSClassFromString(@"NEVPNManager");
    if (!mgrCls) { CKLog(@"L3 找不到 NETunnelProviderManager"); return; }
    SEL loadSel = NSSelectorFromString(@"loadAllFromPreferencesWithCompletionHandler:");
    void (*sendLoad)(id, SEL, void (^)(NSArray *, NSError *)) =
        (void (*)(id, SEL, void (^)(NSArray *, NSError *)))objc_msgSend;
    sendLoad(mgrCls, loadSel, ^(NSArray *managers, NSError *error) {
        if (error) { CKLog(@"L3 loadAllFromPreferences 失败: %@", error); return; }
        id target = nil;
        for (id mgr in managers) {
            @try {
                id proto = [mgr valueForKey:@"protocolConfiguration"];
                NSString *bid = [proto valueForKey:@"providerBundleIdentifier"];
                if ([bid isEqualToString:@CK7_PROVIDER]) { target = mgr; break; }
            } @catch (NSException *ex) { /* 跳过不合规对象 */ }
        }
        if (!target) {
            CKLog(@"L3 系统偏好里没有本 App 的隧道配置（从未成功连过），放弃直启");
            return;
        }
        @try {
            id conn = [target valueForKey:@"connection"];
            NSInteger st = [[conn valueForKey:@"status"] integerValue];
            // 0 Invalid / 5 Disconnected 才拉起；1/2/3 已在连或已连
            if (st != 0 && st != 5) {
                CKLog(@"L3 隧道已在状态 %ld，无需直启", (long)st);
                return;
            }
            NSError *err = nil;
            BOOL (*sendStart)(id, SEL, id, NSError **) =
                (BOOL (*)(id, SEL, id, NSError **))objc_msgSend;
            BOOL ok = sendStart(conn,
                                NSSelectorFromString(@"startVPNTunnelWithOptions:andReturnError:"),
                                nil, &err);
            g_directStart++;
            CKLog(@"L3 直启隧道 %@ (err=%@)", ok ? @"成功" : @"失败", err);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (g_hudLabel) g_hudLabel.text = CK7StatusLine();
            });
        } @catch (NSException *ex) {
            CKLog(@"L3 直启异常: %@", ex);
        }
    });
}

// v1.01: 探测系统偏好里是否存有本 App 的隧道配置（L3 直启 / toast 吞并的前提）
static void CK7ProbeSavedCfg(void) {
    if (g_mode != CK7ModeApp) return;
    void *ne = dlopen("/System/Library/Frameworks/NetworkExtension.framework/"
                      "NetworkExtension", RTLD_NOW);
    if (!ne) return;
    Class mgrCls = NSClassFromString(@"NETunnelProviderManager");
    if (!mgrCls) return;
    SEL loadSel = NSSelectorFromString(@"loadAllFromPreferencesWithCompletionHandler:");
    void (*sendLoad)(id, SEL, void (^)(NSArray *, NSError *)) =
        (void (*)(id, SEL, void (^)(NSArray *, NSError *)))objc_msgSend;
    sendLoad(mgrCls, loadSel, ^(NSArray *managers, NSError *error) {
        BOOL found = NO;
        for (id mgr in managers) {
            @try {
                id proto = [mgr valueForKey:@"protocolConfiguration"];
                NSString *pbid = [proto valueForKey:@"providerBundleIdentifier"];
                if ([pbid isEqualToString:@CK7_PROVIDER]) { found = YES; break; }
            } @catch (NSException *ex) { /* 跳过 */ }
        }
        if (found != g_savedCfg) {
            g_savedCfg = found;
            CKLog(@"探测：系统已保存隧道配置 = %@", found ? @"有" : @"无");
        }
    });
}

static NSArray<NSString *> *CK7FailNeedles(void) {
    return @[ @"permission denied", @"配置数据结构缺失", @"Vmess配置解析失败",
              @"服务器响应格式异常", @"rk_accessLink_mv", @"Base64 解码失败" ];
}

// SVProgressHUD showErrorWithStatus: hook
static void (*g_origShowError)(id, SEL, NSString *);

static void CK7ShowErrorWithStatus(id self, SEL _cmd, NSString *status) {
    g_toastSeen++;
    CKLog(@"toast#%ld:「%@」", g_toastSeen, status);   // v1.01: 全量记录，不再静默
    BOOL hit = NO;
    if (g_mode == CK7ModeApp && [status isKindOfClass:[NSString class]]) {
        for (NSString *needle in CK7FailNeedles()) {
            if ([status rangeOfString:needle
                              options:NSCaseInsensitiveSearch].location != NSNotFound) {
                hit = YES; break;
            }
        }
    }
    // v1.01: 只有存在可行兜底（缓存 link 或系统已保存隧道配置）才吞 toast；
    // 否则原样放行——静默失败会掩盖真实拒绝原因（v1.00 教训）
    BOOL canFallback = (CK7CachedLink().length > 0) || g_savedCfg;
    if (hit && canFallback) {
        g_toastSwallowed++;
        CKLog(@"L3 吞掉失败 toast「%@」(兜底可用)，1.5s 后直启已保存隧道", status);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            CK7DirectStartTunnel();
        });
        return;   // 不调原实现 → 用户看不到报错
    }
    if (hit && !canFallback) {
        CKLog(@"L3 放行 toast「%@」：无缓存 link 且无已保存隧道配置——"
              @"需先成功连一次（新号有体验时长）以建立重放缓存", status);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (g_hudLabel) g_hudLabel.text = @"⚠️需先成功连一次建立缓存";
        });
    }
    if (g_origShowError) g_origShowError(self, _cmd, status);
}

static void CK7InstallToastHook(void) {
    Class cls = NSClassFromString(@"SVProgressHUD");
    if (!cls) { CKLog(@"SVProgressHUD 未加载，跳过 L3 hook"); return; }
    SEL sel = NSSelectorFromString(@"showErrorWithStatus:");
    Method m = class_getClassMethod(cls, sel);
    if (!m) { CKLog(@"未找到 showErrorWithStatus:"); return; }
    g_origShowError = (void (*)(id, SEL, NSString *))method_getImplementation(m);
    method_setImplementation(m, (IMP)CK7ShowErrorWithStatus);
    CKLog(@"L3 SVProgressHUD 钩子完成");
}

#pragma mark - v1.04 最后一公里观测（NE / SVProgressHUD / UILabel 钩子）

// ---- NetworkExtension：拿系统层真实错误（entitlement/权限/配置保存失败都在这现形）----
static void (*g_origSaveToPrefs)(id, SEL, void (^)(NSError *));
static void CK7SaveToPrefs(id self, SEL _cmd, void (^completion)(NSError *)) {
    CKLog(@"NE saveToPreferences 调用");
    void (^wrapped)(NSError *) = completion ? ^(NSError *error) {
        CKLog(@"NE saveToPreferences 结果: %@", error ? error : @"成功");
        completion(error);
    } : nil;
    g_origSaveToPrefs(self, _cmd, wrapped);
}

static void (*g_origLoadAllFromPrefs)(id, SEL, void (^)(NSArray *, NSError *));
static void CK7LoadAllFromPrefs(id self, SEL _cmd,
                                void (^completion)(NSArray *, NSError *)) {
    void (^wrapped)(NSArray *, NSError *) = ^(NSArray *mgrs, NSError *error) {
        CKLog(@"NE loadAllFromPreferences: %lu 个管理器, err=%@",
              (unsigned long)mgrs.count, error ?: @"无");
        if (completion) completion(mgrs, error);
    };
    g_origLoadAllFromPrefs(self, _cmd, wrapped);
}

static void (*g_origLoadFromPrefs)(id, SEL, void (^)(id, NSError *));
static void CK7LoadFromPrefs(id self, SEL _cmd, void (^completion)(id, NSError *)) {
    void (^wrapped)(id, NSError *) = ^(id mgr, NSError *error) {
        CKLog(@"NE loadFromPreferences: mgr=%@ err=%@",
              mgr ? @"有" : @"无", error ?: @"无");
        if (completion) completion(mgr, error);
    };
    g_origLoadFromPrefs(self, _cmd, wrapped);
}

static BOOL (*g_origStartTunnel)(id, SEL, NSDictionary *, NSError **);
static BOOL CK7StartTunnel(id self, SEL _cmd, NSDictionary *options, NSError **error) {
    NSError *local = nil;
    BOOL ok = g_origStartTunnel(self, _cmd, options, error ? error : &local);
    NSError *e = error ? *error : local;
    CKLog(@"NE startVPNTunnelWithOptions 结果=%@ err=%@",
          ok ? @"YES" : @"NO", e ?: @"无");
    return ok;
}

static BOOL (*g_origStartTunnelSimple)(id, SEL, NSError **);
static BOOL CK7StartTunnelSimple(id self, SEL _cmd, NSError **error) {
    NSError *local = nil;
    BOOL ok = g_origStartTunnelSimple(self, _cmd, error ? error : &local);
    NSError *e = error ? *error : local;
    CKLog(@"NE startVPNTunnel 结果=%@ err=%@", ok ? @"YES" : @"NO", e ?: @"无");
    return ok;
}

static void CK7InstallNEHooks(void) {
    void *ne = dlopen("/System/Library/Frameworks/NetworkExtension.framework/"
                      "NetworkExtension", RTLD_NOW);
    if (!ne) { CKLog(@"NE dlopen 失败，跳过 NE 钩子"); return; }
    Class vpnMgr = NSClassFromString(@"NEVPNManager");
    if (vpnMgr) {
        SEL s1 = NSSelectorFromString(@"saveToPreferencesWithCompletionHandler:");
        Method m1 = class_getInstanceMethod(vpnMgr, s1);
        if (m1) {
            g_origSaveToPrefs =
                (void (*)(id, SEL, void (^)(NSError *)))method_getImplementation(m1);
            method_setImplementation(m1, (IMP)CK7SaveToPrefs);
        }
        SEL s2 = NSSelectorFromString(@"loadAllFromPreferencesWithCompletionHandler:");
        Method m2 = class_getClassMethod(vpnMgr, s2);
        if (m2) {
            g_origLoadAllFromPrefs =
                (void (*)(id, SEL, void (^)(NSArray *, NSError *)))method_getImplementation(m2);
            method_setImplementation(m2, (IMP)CK7LoadAllFromPrefs);
        }
        SEL s2b = NSSelectorFromString(@"loadFromPreferencesWithCompletionHandler:");
        Method m2b = class_getInstanceMethod(vpnMgr, s2b);
        if (m2b) {
            g_origLoadFromPrefs =
                (void (*)(id, SEL, void (^)(id, NSError *)))method_getImplementation(m2b);
            method_setImplementation(m2b, (IMP)CK7LoadFromPrefs);
        }
    }
    Class conn = NSClassFromString(@"NEVPNConnection");
    if (conn) {
        SEL s3 = NSSelectorFromString(@"startVPNTunnelWithOptions:andReturnError:");
        Method m3 = class_getInstanceMethod(conn, s3);
        if (m3) {
            g_origStartTunnel =
                (BOOL (*)(id, SEL, NSDictionary *, NSError **))method_getImplementation(m3);
            method_setImplementation(m3, (IMP)CK7StartTunnel);
        }
        SEL s4 = NSSelectorFromString(@"startVPNTunnelAndReturnError:");
        Method m4 = class_getInstanceMethod(conn, s4);
        if (m4) {
            g_origStartTunnelSimple =
                (BOOL (*)(id, SEL, NSError **))method_getImplementation(m4);
            method_setImplementation(m4, (IMP)CK7StartTunnelSimple);
        }
    }
    CKLog(@"v1.04 NE 钩子完成（save/loadAll/load/start×2）");
}

// ---- SVProgressHUD 其余展示 API：全部入日志 ----
static void (*g_origShowSuccess)(id, SEL, NSString *);
static void CK7ShowSuccess(id self, SEL _cmd, NSString *status) {
    CKLog(@"toast(成功):「%@」", status);
    if (g_origShowSuccess) g_origShowSuccess(self, _cmd, status);
}

static void (*g_origShowInfo)(id, SEL, NSString *);
static void CK7ShowInfo(id self, SEL _cmd, NSString *status) {
    CKLog(@"toast(信息):「%@」", status);
    if (g_origShowInfo) g_origShowInfo(self, _cmd, status);
}

static void (*g_origShowImage)(id, SEL, UIImage *, NSString *);
static void CK7ShowImage(id self, SEL _cmd, UIImage *image, NSString *status) {
    CKLog(@"toast(图片):「%@」", status);
    if (g_origShowImage) g_origShowImage(self, _cmd, image, status);
}

static void CK7InstallMoreToastHooks(void) {
    Class cls = NSClassFromString(@"SVProgressHUD");
    if (!cls) return;
    struct { SEL sel; IMP imp; void **slot; } hooks[] = {
        { NSSelectorFromString(@"showSuccessWithStatus:"), (IMP)CK7ShowSuccess, (void **)&g_origShowSuccess },
        { NSSelectorFromString(@"showInfoWithStatus:"), (IMP)CK7ShowInfo, (void **)&g_origShowInfo },
        { NSSelectorFromString(@"showImage:status:"), (IMP)CK7ShowImage, (void **)&g_origShowImage },
    };
    int n = 0;
    for (unsigned i = 0; i < sizeof(hooks)/sizeof(hooks[0]); i++) {
        Method m = class_getClassMethod(cls, hooks[i].sel);
        if (!m) continue;
        IMP orig = method_getImplementation(m);
        if (orig == hooks[i].imp) continue;
        *hooks[i].slot = (void *)orig;
        method_setImplementation(m, hooks[i].imp);
        n++;
    }
    CKLog(@"v1.04 SVProgressHUD 追加钩子 %d 个", n);
}

// ---- UILabel setText: 关键词哨兵：抓「网络异常」等不在二进制里的服务端/系统文案 ----
static void (*g_origLabelText)(id, SEL, NSString *);
static NSString *g_lastLabelHit = nil;
static NSTimeInterval g_lastLabelHitAt = 0;

static void CK7LabelSetText(id self, SEL _cmd, NSString *text) {
    if (g_origLabelText) g_origLabelText(self, _cmd, text);   // 先放行，观测零影响
    if (![text isKindOfClass:[NSString class]]) return;
    if (text.length < 2 || text.length > 120) return;
    static NSArray *needles = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[ @"网络异常", @"失败", @"错误", @"权限", @"denied", @"无法" ];
    });
    BOOL hit = NO;
    for (NSString *nd in needles) {
        if ([text rangeOfString:nd options:NSCaseInsensitiveSearch].location != NSNotFound) {
            hit = YES; break;
        }
    }
    if (!hit) return;
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    if (g_lastLabelHit && [g_lastLabelHit isEqualToString:text] &&
        now - g_lastLabelHitAt < 3.0) return;   // 3s 去重
    g_lastLabelHit = text;
    g_lastLabelHitAt = now;
    CKLog(@"UILabel 命中文案:「%@」", text);
}

static void CK7InstallLabelHook(void) {
    Method m = class_getInstanceMethod([UILabel class], @selector(setText:));
    if (!m) { CKLog(@"UILabel setText: 未找到"); return; }
    g_origLabelText = (void (*)(id, SEL, NSString *))method_getImplementation(m);
    method_setImplementation(m, (IMP)CK7LabelSetText);
    CKLog(@"v1.04 UILabel 文案哨兵完成");
}

#pragma mark - HUD（主程序）

static NSString *CK7StatusLine(void) {
    NSString *mode = (g_mode == CK7ModeApp) ? @"APP" :
                     (g_mode == CK7ModeTunnel) ? @"TUN" : @"--";
    // v1.02: 全 ASCII 计数（✓/✗ 在部分字体下渲染成方框）
    int cached = CK7CachedLink().length > 0 ? 1 : 0;
    return [NSString stringWithFormat:
        @"🛰VIP·b7 %@ V%ld R%ld C%d S%d W%ld D%ld T%ld K%ld/%ld",
        mode, g_vipRewrite, g_replay, cached, (int)g_savedCfg,
        g_toastSwallowed, g_directStart, g_devRewrite, g_cutBlocked, g_keepReplay];
}

// v1.02: 完整诊断文本（点悬浮窗复制到剪贴板，直接粘给分析者）
static NSString *CK7Diagnostics(void) {
    NSMutableString *s = [NSMutableString string];
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.dateFormat = @"HH:mm:ss";
    [s appendFormat:@"== bypass7 v1.04 诊断 %@ ==\n", [df stringFromDate:[NSDate date]]];
    [s appendFormat:@"进程: %@ | 模式: %@\n",
        [[NSBundle mainBundle] bundleIdentifier] ?: @"?",
        (g_mode == CK7ModeApp ? @"主程序" : (g_mode == CK7ModeTunnel ? @"隧道" : @"惰性"))];
    [s appendFormat:@"UUID: %@\n", CK7UUIDHex()];
    [s appendFormat:@"L1 会员改写=%ld | L2 重放=%ld(link更新%ld,缓存%@) | "
                    @"L3 直启=%ld(toast见%ld/吞%ld,已存配置%d) | L4 拦截=%ld/keep重放=%ld\n",
        g_vipRewrite, g_replay, g_linkSeen,
        CK7CachedLink().length > 0 ? @"有" : @"无",
        g_directStart, g_toastSeen, g_toastSwallowed, (int)g_savedCfg,
        g_cutBlocked, g_keepReplay];
    [s appendFormat:@"L6 设备码改写=%ld 次 | 轮换码=%@\n",
        g_devRewrite,
        [[NSUserDefaults standardUserDefaults] stringForKey:kCK7RotatedDev] ?: @"(未生成)"];
    [s appendFormat:@"swizzle存活: %@ | tick=%ld\n",
        CK7SwizzleAlive() ? @"是" : @"否", g_tick];
    [s appendString:@"---- 最近日志(旧→新) ----\n"];
    CK7RingInit();
    @synchronized (g_logRing) {
        for (NSString *line in g_logRing) [s appendFormat:@"%@\n", line];
    }
    return s;
}

@interface CK7HudTarget : NSObject
@end

@implementation CK7HudTarget
+ (instancetype)shared {
    static CK7HudTarget *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[CK7HudTarget alloc] init]; });
    return s;
}
- (void)tapped {
    // v1.02: 单击 = 一键复制完整诊断到剪贴板（直接粘贴给分析者）
    NSString *diag = CK7Diagnostics();
    [UIPasteboard generalPasteboard].string = diag;
    CKLog(@"诊断已复制到剪贴板（%lu 字节），长按悬浮窗可看弹窗详情",
          (unsigned long)diag.length);
    if (g_hudLabel) {
        NSString *old = g_hudLabel.text;
        g_hudLabel.text = @"✓ 诊断已复制";
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (g_hudLabel) g_hudLabel.text = CK7StatusLine();
            (void)old;
        });
    }
}
- (void)longPressed {
    NSString *msg = [NSString stringWithFormat:
        @"模式: %@\n"
        @"L1 会员字段改写: %ld 次\n"
        @"L2 拒绝重放: %ld 次（link 缓存更新 %ld 次）\n"
        @"L3 直启隧道: %ld 次（toast 见到 %ld / 吞掉 %ld）\n"
        @"L4 掐断拦截: %ld 次 / keep 重放: %ld 次\n"
        @"系统已存隧道配置: %@（直启兜底前提）\n"
        @"swizzle 存活: %@\n主程序 UUID: %@\n\n"
        @"（单击悬浮窗 = 复制完整诊断到剪贴板）",
        (g_mode == CK7ModeApp ? @"主程序" : @"隧道"),
        g_vipRewrite, g_replay, g_linkSeen, g_directStart,
        g_toastSeen, g_toastSwallowed, g_cutBlocked, g_keepReplay,
        g_savedCfg ? @"有" : @"无",
        CK7SwizzleAlive() ? @"是" : @"否（看门狗将重挂）",
        CK7UUIDHex()];
    UIAlertController *ac =
        [UIAlertController alertControllerWithTitle:@"bypass7 状态"
                                            message:msg
                                     preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"好"
                                           style:UIAlertActionStyleDefault
                                         handler:nil]];
    UIViewController *top = nil;
    for (UIScene *sc0 in [UIApplication sharedApplication].connectedScenes) {
        if (![sc0 isKindOfClass:[UIWindowScene class]]) continue;
        UIWindowScene *sc = (UIWindowScene *)sc0;
        if (sc.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *w in sc.windows) {
                if (w.isKeyWindow) { top = w.rootViewController; break; }
            }
        }
        if (top) break;
    }
    while (top.presentedViewController) top = top.presentedViewController;
    [top presentViewController:ac animated:YES completion:nil];
}
- (void)panned:(UIPanGestureRecognizer *)g {
    UIView *v = g.view;
    CGPoint t = [g translationInView:v.superview];
    v.center = CGPointMake(v.center.x + t.x, v.center.y + t.y);
    [g setTranslation:CGPointMake(0, 0) inView:v.superview];
}
@end

static UIWindow *CK7KeyWindow(void) {
    for (UIScene *sc0 in [UIApplication sharedApplication].connectedScenes) {
        if (![sc0 isKindOfClass:[UIWindowScene class]]) continue;
        UIWindowScene *sc = (UIWindowScene *)sc0;
        if (sc.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *w in sc.windows)
                if (w.isKeyWindow) return w;
        }
    }
    for (UIScene *sc0 in [UIApplication sharedApplication].connectedScenes) {
        if (![sc0 isKindOfClass:[UIWindowScene class]]) continue;
        UIWindowScene *sc = (UIWindowScene *)sc0;
        for (UIWindow *w in sc.windows)
            if (w.isKeyWindow) return w;
    }
    return nil;
}

static void CK7MakeHUD(void) {
    if (g_hud) return;
    UIWindow *w = CK7KeyWindow();
    if (!w) return;
    UIControl *c = [[UIControl alloc] initWithFrame:CGRectMake(12, 54, 196, 26)];
    c.backgroundColor = [UIColor colorWithWhite:0 alpha:0.62];
    c.layer.cornerRadius = 13;
    UILabel *l = [[UILabel alloc] initWithFrame:c.bounds];
    l.textColor = [UIColor whiteColor];
    l.font = [UIFont monospacedDigitSystemFontOfSize:10.5 weight:UIFontWeightMedium];
    l.textAlignment = NSTextAlignmentCenter;
    l.adjustsFontSizeToFitWidth = YES;
    l.minimumScaleFactor = 0.6;
    l.text = CK7StatusLine();
    [c addSubview:l];
    [c addTarget:[CK7HudTarget shared] action:@selector(tapped)
        forControlEvents:UIControlEventTouchUpInside];
    UIPanGestureRecognizer *pan =
        [[UIPanGestureRecognizer alloc] initWithTarget:[CK7HudTarget shared]
                                                action:@selector(panned:)];
    [c addGestureRecognizer:pan];
    // v1.02: 长按 = 弹窗详情（单击已改为一键复制诊断）
    UILongPressGestureRecognizer *lp =
        [[UILongPressGestureRecognizer alloc] initWithTarget:[CK7HudTarget shared]
                                                      action:@selector(longPressed)];
    lp.minimumPressDuration = 0.6;
    [c addGestureRecognizer:lp];
    [w addSubview:c];
    g_hud = c;
    g_hudLabel = l;
    CKLog(@"HUD 已挂载");
}

#pragma mark - L5 看门狗

static void CK7Watchdog(void) {
    dispatch_queue_t q = dispatch_get_main_queue();
    dispatch_source_t t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(t, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                              2 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);
    __block long lastBeat = 0;
    dispatch_source_set_event_handler(t, ^{
        g_tick++;
        if (!CK7SwizzleAlive()) {
            CKLog(@"看门狗：swizzle 丢失，重挂");
            g_swizzled = NO;
            CK7InstallJSONSwizzle();
        }
        if (g_mode == CK7ModeApp) {
            if (!g_hud) CK7MakeHUD();
            if (g_hudLabel) g_hudLabel.text = CK7StatusLine();
            if (g_tick % 15 == 1) CK7ProbeSavedCfg();   // v1.01: 每30s探测已存配置
        }
        if (g_tick - lastBeat >= 15) {   // 30s 心跳
            lastBeat = g_tick;
            CKLog(@"心跳 %@ | L1=%ld L2=%ld L3=%ld L4=%ld/%ld link缓存=%@ swz=%d",
                  CK7StatusLine(), g_vipRewrite, g_replay, g_directStart,
                  g_cutBlocked, g_keepReplay, CK7CachedLink() ? @"有" : @"无",
                  (int)g_swizzled);
        }
    });
    g_timer = t;   // 静态持有，防 ARC 释放
    dispatch_resume(t);
}

#pragma mark - 构造函数

__attribute__((constructor)) static void CK7Ctor(void) {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
        if ([bid isEqualToString:@CK7_APP_BID]) {
            g_mode = CK7ModeApp;
        } else if ([bid isEqualToString:@CK7_TUNNEL_BID]) {
            g_mode = CK7ModeTunnel;
        } else {
            CKLog(@"非目标进程(%@)，保持惰性", bid);
            return;
        }
        CKLog(@"==== bypass7 注入 %@ (%@) UUID=%@ ====",
              bid, g_mode == CK7ModeApp ? @"主程序" : @"隧道", CK7UUIDHex());
        CK7InstallJSONSwizzle();
        if (g_mode == CK7ModeApp) {
            CK7InstallToastHook();
            CK7InstallMoreToastHooks();   // v1.04
            CK7InstallNEHooks();          // v1.04
            CK7InstallLabelHook();        // v1.04
            CKLog(@"link 缓存: %@ | keep 缓存: 不适用",
                  CK7CachedLink() ? @"已有" : @"空（需先成功连一次）");
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                CK7MakeHUD();
                CKLog(@"就绪：L1 会员改写 + L2 拒绝重放 + L3 直启兜底 + L5 看门狗");
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                CK7ProbeSavedCfg();   // v1.01: 启动即探测一次已存隧道配置
            });
        } else {
            CKLog(@"就绪：L4 保活免疫（connectionState=0 改写 + keep 重放）");
        }
        CK7Watchdog();
    }
}

