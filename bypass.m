// ============================================================
//  ace 靶场卡密验证绕过 dylib（课程作业版）
//  原理：ace 靶场用 SAMKeychain 判活 ——
//    q4(0x88734) 读取 passwordForService:account:
//      service  = com.apple.LSDocumentRegistry   (XOR 解密 0x39729c)
//      account  = com.apple.identitytoken.v4    (XOR 解密 0x3972b8)
//    读到的密码 length != 0  => 判定"已激活"，直接放行功能面板
//  本 dylib 把该读取 Hook 成永远返回非空串 => 卡密系统整体被攻破
// ============================================================
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>

// 返回给靶场的"假密码"：任意非空串即可通过 length!=0 判活
static NSString *BypassFakePassword(id self, SEL _cmd, NSString *service, NSString *account) {
    return @"ACTIVATED_BY_DOUBAO_BYPASS";
}

// q17 是 60 秒定时触发的"过期看门狗"（NSTimer → sel:q17，检查天卡/月卡时长）
// 直接替换成空实现，让过期检查永远不生效
static void BypassQ17Noop(id self, SEL _cmd) {
    return; // 什么都不做：跳过过期判断
}

// 在所有"实现 passwordForService:account: 类方法"的类上替换实现
// （老师提示版本不同类名可能不同，枚举类比写死类名更稳）
static void BypassHookKeychainReaders(void) {
    int count = objc_getClassList(NULL, 0);
    Class *buf = (Class *)malloc(sizeof(Class) * (count > 0 ? count : 1));
    objc_getClassList(buf, count);
    SEL sel = NSSelectorFromString(@"passwordForService:account:");
    SEL sel17 = NSSelectorFromString(@"q17");
    for (int i = 0; i < count; i++) {
        Class cls = buf[i];
        if (!cls) continue;
        Method m = class_getClassMethod(cls, sel);
        if (m) {
            method_setImplementation(m, (IMP)BypassFakePassword);
        }
        // 过期看门狗：任何实现 q17 的实例方法都替换为空实现
        Method m17 = class_getInstanceMethod(cls, sel17);
        if (m17) {
            method_setImplementation(m17, (IMP)BypassQ17Noop);
        }
    }
    free(buf);
}

// ===== 备份方案：网络授权响应伪造（老师 blue.dylib 同款思路）=====
// 有的版本卡密验证走 URLSession/NSData 拉取服务器 JSON（含 "sign" 字段），
// 这里对常用序列化入口做拦截，返回"已激活"形态的数据。

static NSData *(*orig_dataWithContentsOfURL)(id, SEL, NSURL *);
static NSData *Bypass_dataWithContentsOfURL(id self, SEL _cmd, NSURL *url) {
    return nil; // 直接不联网；本地 keychain 已判活
}

static NSData *(*orig_dataWithContentsOfURL_opts)(id, SEL, NSURL *, NSDataReadingOptions, NSError **);
static NSData *Bypass_dataWithContentsOfURL_opts(id self, SEL _cmd, NSURL *url,
                                                 NSDataReadingOptions o, NSError **e) {
    return nil;
}

static void BypassHookNetworking(void) {
    Method m = class_getClassMethod(objc_getClass("NSData"),
                                    NSSelectorFromString(@"dataWithContentsOfURL:"));
    if (m) { orig_dataWithContentsOfURL = (void *)method_getImplementation(m);
             method_setImplementation(m, (IMP)Bypass_dataWithContentsOfURL); }
    Method m2 = class_getClassMethod(objc_getClass("NSData"),
                                     NSSelectorFromString(@"dataWithContentsOfURL:options:error:"));
    if (m2) { orig_dataWithContentsOfURL_opts = (void *)method_getImplementation(m2);
              method_setImplementation(m2, (IMP)Bypass_dataWithContentsOfURL_opts); }
}

// 可选：直接把本设备的合法卡密写进 keychain，让最严格的重查也通过
// （卡密 = hex(sha256(model|systemVersion|resolution|udid|主密钥))）
__attribute__((unused))
static NSString *BypassComputeCardKey(void) {
    NSString *key = @"RfvxTVgxZteKf0QFXikk0m8AvKaDf+H1bcG2hRigPGI=";
    UIDevice *dev = [UIDevice currentDevice];
    NSString *model = [dev model] ?: @"unknown";
    NSString *sysver = [dev systemVersion] ?: @"0";
    CGRect b = [[UIScreen mainScreen] bounds];
    CGFloat scale = [[UIScreen mainScreen] scale];
    NSString *res = [NSString stringWithFormat:@"%.0fx%.0f", b.size.width * scale, b.size.height * scale];
    NSString *udid = [[[dev identifierForVendor] UUIDString] lowercaseString] ?: @"0";
    NSString *plain = [NSString stringWithFormat:@"%@|%@|%@|%@|%@", model, sysver, res, udid, key];
    NSData *d = [plain dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(d.bytes, (CC_LONG)d.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:64];
    for (int i = 0; i < 32; i++) [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

__attribute__((constructor))
static void BypassInit(void) {
    BypassHookKeychainReaders();
    BypassHookNetworking();
}
