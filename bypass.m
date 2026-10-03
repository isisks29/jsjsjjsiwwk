#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#import <Foundation/Foundation.h>
#import <libkern/OSCacheControl.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <signal.h>
#import <ucontext.h>
#import <sys/mman.h>
#import <string.h>
#import <mach/mach_vm.h>
static volatile int g_patchedDraw = 0;
static volatile uint32_t g_drawW0 = 0, g_drawW1 = 0;
static volatile int g_tick = 0;
static uintptr_t g_targetBase = 0;

static volatile int g_patchRet = 0;

// ===== 枚举 image =====
#define MAX_IMG 256
typedef struct { char name[256]; uintptr_t hdr; } ImgInfo;
static ImgInfo g_imgs[MAX_IMG];
static int g_nimg = 0;

static void enumerateAllImages(void){
    int cnt = _dyld_image_count();
    g_nimg = 0;
    for(int i=0;i<cnt && g_nimg<MAX_IMG;i++){
        const char* p  = _dyld_get_image_name(i);
        const struct mach_header* h = _dyld_get_image_header(i);
        if(!p || !h) continue;
        int j = 0;
        while(p[j] && j < 255){ g_imgs[g_nimg].name[j] = p[j]; j++; }
        g_imgs[g_nimg].name[j] = 0;
        g_imgs[g_nimg].hdr = (uintptr_t)h;
        g_nimg++;
    }
}
static uintptr_t findTargetBase(void){
    for(int i=0;i<g_nimg;i++){
        if(strcasestr(g_imgs[i].name, "ballsace")) return g_imgs[i].hdr;
    }
    for(int i=0;i<g_nimg;i++){
        if(strcasestr(g_imgs[i].name, "ace")) return g_imgs[i].hdr;
    }
    return 0;
}

static inline void *va(uintptr_t f){ return (void*)(g_targetBase+f); }
static inline void w64(uintptr_t f,uint64_t v){ *(volatile uint64_t*)va(f)=v; }
static inline void w32(uintptr_t f,uint32_t v){ *(volatile uint32_t*)va(f)=v; }
static inline uint64_t r64(uintptr_t f){ return *(volatile uint64_t*)va(f); }
static inline uint32_t r32(uintptr_t f){ return *(volatile uint32_t*)va(f); }

static volatile int g_popupCount = 0;
static volatile int g_hookPopup = 0;
static volatile int g_armDone = 0;
static volatile int g_patchedConnect = 0;
static volatile int g_called5c = 0;

static const uintptr_t kSessionBaseFile = 0x3ff000;
#define CFG_C   0xB75E8052BABD72A6ULL
#define MIX_K   0xD18DDB25u
#define MIX_K1  0x1767CEDCu
#define MIX_K2  0x5D41C293u
#define W_A     0x8E4B1395u
#define W_B     0x1F3D6A71u

static uint64_t boot_ms(void){
    mach_timebase_info_data_t tb; mach_timebase_info(&tb);
    return mach_absolute_time() * tb.numer / tb.denom / 1000000ULL;
}
static inline uint32_t mix(uint32_t x){
    x ^= x>>15; x *= W_B;
    x ^= x>>11; x *= W_A;
    x ^= x>>17; return x;
}
static void writeGateTriple(uintptr_t seedAddr){
    uint64_t x  = r64(seedAddr) ^ CFG_C;
    uint32_t lo = (uint32_t)x, hi = (uint32_t)(x>>32);
    uint32_t v1 = mix((lo^hi) ^ MIX_K);
    w32(seedAddr + 0x08, v1);
    uint32_t v2 = mix(v1 ^ MIX_K1) ^ lo;
    w32(seedAddr + 0x0C, v2);
    uint32_t v3 = mix(v2 ^ MIX_K2) ^ hi;
    w32(seedAddr + 0x10, v3);
}
static void* buildSessionObj(void){
    void *obj = calloc(1, 0x11c6);
    uint64_t b0=0x123456789abcdef0ULL, b8=0xfedcba9876543210ULL;
    uint32_t b16=0x11223344, b24=0x55667788, b32=0x99aabbcc;
    uint64_t *P = (uint64_t*)((uintptr_t)obj + 0x119a);
    P[0]=b0; P[1]=b8; P[2]=b16; P[3]=b24; P[4]=b32;
    uint32_t h = ((uint32_t)(b8>>32) ^ (uint32_t)b8) * 0x45D9F3B7u;
    h ^= b16; h *= W_A; h ^= b24; h *= W_B; h ^= b32; h ^= h>>16;
    *(uint32_t*)((uintptr_t)obj + 0x11c2) = h;
    *(uint32_t*)((uintptr_t)obj + 0x0)  = (b32 ^ (uint32_t)(b0>>19)) ^ 0x5F8A16E3u;
    *(uint64_t*)((uintptr_t)obj + 0x78) = b0 ^ b8 ^ 0xA5C3E1F7B6D2489AULL;
    *(uint32_t*)((uintptr_t)obj + 0x8e) = (b16 ^ (uint32_t)(b0>>7))  ^ 0x4A9B5206u;
    *(uint32_t*)((uintptr_t)obj + 0x92) = (b24 ^ (uint32_t)(b0>>13)) ^ 0x8C1A73E5u;
    return obj;
}
static void armFull(void){
    if(!g_targetBase) return;
    @try{
        uintptr_t g = kSessionBaseFile;
        uint64_t now_ms  = boot_ms();
        uint64_t now_sec = now_ms / 1000;
        w64(g+0x6a0, CFG_C ^ now_ms);
        writeGateTriple(g+0x6a0);
        w64(g+0x680, CFG_C ^ now_sec);
        writeGateTriple(g+0x680);
        w64(g+0x698, (uintptr_t)buildSessionObj());
        g_armDone = 1;
    }@catch(NSException*e){}
}
static void patchConnectFail(void){
    if(!g_targetBase) return;
    uint32_t *p = (uint32_t*)va(0xd28d0);
    if(p[0] == 0xB90B07FF) return;
    p[0] = 0xB90B07FF;
    sys_icache_invalidate(p, 4);
    g_patchedConnect = 1;
}

// ===== 你成功过的 hook =====
static id (*origPassword)(id, SEL, id, id);
static id hookPassword(id self, SEL _cmd, id svc, id acct) { return @"A"; }
static void (*origSetup)(id, SEL);
static void hookSetup(id self, SEL _cmd) {}
static IMP g_origPresent = NULL;
static void hookPresent(id self, SEL _cmd, UIViewController *vc, BOOL anim, void (^comp)(void)) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        g_popupCount++;
        if (comp) comp();
        return;
    }
    ((void (*)(id, SEL, UIViewController *, BOOL, void (^)(void)))g_origPresent)(self, _cmd, vc, anim, comp);
}
static void installHooks(void) {
    Class keychain = objc_getClass("_0xD5A13E79");
    Method mPass = keychain ? class_getClassMethod(keychain, sel_registerName("passwordForService:account:")) : NULL;
    if (mPass) {
        origPassword = (id(*)(id,SEL,id,id))method_getImplementation(mPass);
        method_setImplementation(mPass, (IMP)hookPassword);
    }
    Class popup = objc_getClass("_0x6D1C8F45");
    Method mSetup = popup ? class_getInstanceMethod(popup, sel_registerName("setupUI")) : NULL;
    if (mSetup) {
        origSetup = (void(*)(id,SEL))method_getImplementation(mSetup);
        method_setImplementation(mSetup, (IMP)hookSetup);
    }
    g_origPresent = class_getMethodImplementation([UIViewController class],
                                                   sel_registerName("presentViewController:animated:completion:"));
    if (g_origPresent) {
        Method mPres = class_getInstanceMethod([UIViewController class],
                                               sel_registerName("presentViewController:animated:completion:"));
        method_setImplementation(mPres, (IMP)hookPresent);
    }
    g_hookPopup = 1;
}

@interface BallTarget : NSObject
@property(nonatomic,strong) UILabel *lbl;
@end
@implementation BallTarget
// 全局（放在文件顶部，其他 static 旁边）


// 全局（放文件顶部）


- (void)refresh{
    g_tick++;
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"tick=%d\n", g_tick];
    [s appendFormat:@"base=%p\n", (void*)g_targetBase];
    [s appendFormat:@"arm=%d c5=%d\n", g_armDone, g_called5c];
    if(g_targetBase){
        [s appendFormat:@"348=%u\n", r32(0x3fc000+0x348)];
        [s appendFormat:@"v328=%p\n", (void*)r64(0x3fc000+0x328)];
        id metal = (__bridge id)(void*)r64(0x3fc000+0x328);
        if(metal){
            @try{
                UIView *v = (UIView*)metal;
                [s appendFormat:@"M h=%d a=%.2f\n", v.hidden, v.alpha];
            }@catch(NSException*e){}
        }
        [s appendFormat:@"d10=%08x\n", *(volatile uint32_t*)va(0x8d010)];
        [s appendFormat:@"t20=%08x\n", *(volatile uint32_t*)va(0x1210e0)];
        [s appendFormat:@"pat=%d\n", g_patchRet];
[s appendFormat:@"d10=%08x t20=%08x\n",
    *(volatile uint32_t*)va(0x8d010),
    *(volatile uint32_t*)va(0x1210e0)];
    }
    self.lbl.text = s;
}
- (void)tap{ [self refresh]; }
@end
static void spawnBall(void){
    @try{
        NSArray *wins = UIApplication.sharedApplication.windows;
        if(!wins || wins.count == 0){
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1*NSEC_PER_SEC)),
                           dispatch_get_main_queue(),^{ spawnBall(); });
            return;
        }
        UIWindow *w = wins[0];
        BallTarget *t = [BallTarget new];

        UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(5,40,180,100)];
        lbl.backgroundColor = [UIColor colorWithWhite:0 alpha:0.8];
        lbl.textColor = [UIColor whiteColor];
        lbl.font = [UIFont systemFontOfSize:8];
        lbl.numberOfLines = 0;
        lbl.text = @"init";
        lbl.userInteractionEnabled = YES;
        t.lbl = lbl;
        [w addSubview:lbl];
        [w bringSubviewToFront:lbl];

        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(5, 5, 36, 36);
        b.backgroundColor = [UIColor redColor];
        b.layer.cornerRadius = 27;
        [b addTarget:t action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
        [w addSubview:b];
        [w bringSubviewToFront:b];

        [t refresh];
    }@catch(NSException*e){}
}
__attribute__((constructor))
static void initBy(void){
    @autoreleasepool{
        enumerateAllImages();
        g_targetBase = findTargetBase();
        installHooks();

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{
            armFull();

            if(g_targetBase){
    uintptr_t addr = (uintptr_t)va(0x8d010);
    uintptr_t page0 = addr & ~0x3FFFULL;

    kern_return_t kr = vm_protect(mach_task_self(),
                                  (mach_vm_address_t)page0, 0x4000, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY | VM_PROT_EXECUTE);
    if(kr == KERN_SUCCESS){
        *(volatile uint32_t*)addr = 0xD503201F;
        sys_icache_invalidate((void*)addr, 4);
        vm_protect(mach_task_self(),
                   (mach_vm_address_t)page0, 0x4000, FALSE,
                   VM_PROT_READ | VM_PROT_EXECUTE);
        g_patchRet = 1;
    } else {
        g_patchRet = -kr;
    }
}

                typedef void(*fn_t)(void);
                fn_t f = (fn_t)va(0x11fa5c);
                if(f){ f(); g_called5c = 1; }
            }
            spawnBall();
        });
    }
}
