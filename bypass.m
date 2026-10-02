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

static const uintptr_t kSessionBaseFile = 0x3ff000;
static const uintptr_t k11ffb0File      = 0x11ffb0;

#define CFG_C   0xB75E8052BABD72A6ULL
#define MIX_K   0xD18DDB25u
#define MIX_K1  0x1767CEDCu
#define MIX_K2  0x5D41C293u
#define W_A     0x8E4B1395u
#define W_B     0x1F3D6A71u

static uintptr_t g_targetBase = 0;

// ===== 枚举所有 image =====
#define MAX_IMG 256
typedef struct { char name[256]; char inst[256]; uintptr_t hdr; } ImgInfo;
static ImgInfo g_imgs[MAX_IMG];
static volatile int g_nimg = 0;

static const char* image_install_name(const struct mach_header* h){
    const struct load_command* lc =
        (const struct load_command*)((const char*)h + sizeof(struct mach_header));
    for(uint32_t i=0;i<h->ncmds;i++){
        if(lc->cmd == LC_ID_DYLIB){
            const struct dylib_command* dc = (const struct dylib_command*)lc;
            return (const char*)dc + dc->dylib.name.offset;
        }
        lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
    }
    return NULL;
}
static void enumerateAllImages(void){
    int cnt = _dyld_image_count();
    for(int i=0;i<cnt && g_nimg<MAX_IMG;i++){
        const char* p  = _dyld_get_image_name(i);
        const struct mach_header* h = _dyld_get_image_header(i);
        if(!p || !h) continue;
        strncpy(g_imgs[g_nimg].name, p, 255); g_imgs[g_nimg].name[255]=0;
        const char* inst = image_install_name(h);
        if(inst){ strncpy(g_imgs[g_nimg].inst, inst, 255); g_imgs[g_nimg].inst[255]=0; }
        else g_imgs[g_nimg].inst[0] = 0;
        g_imgs[g_nimg].hdr = (uintptr_t)h;
        g_nimg++;
    }
}

static uintptr_t findTargetBase(void){
    for(int i=0;i<g_nimg;i++){
        if(strcasestr(g_imgs[i].inst, "ace") || strcasestr(g_imgs[i].inst, "balls"))
            return g_imgs[i].hdr;
        if(strcasestr(g_imgs[i].name, "ace") || strcasestr(g_imgs[i].name, "balls"))
            return g_imgs[i].hdr;
    }
    return 0;
}

static inline void *va(uintptr_t f){ return (void*)(g_targetBase+f); }
static inline void w64(uintptr_t f,uint64_t v){ *(volatile uint64_t*)va(f)=v; }
static inline void w32(uintptr_t f,uint32_t v){ *(volatile uint32_t*)va(f)=v; }
static inline uint64_t r64(uintptr_t f){ return *(volatile uint64_t*)va(f); }
static inline uint32_t r32(uintptr_t f){ return *(volatile uint32_t*)va(f); }

// ===== 状态 =====
static volatile int g_popupCount = 0;
static volatile int g_hookPopup = 0;
static volatile int g_refreshTick = 0;
static volatile int g_armDone = 0;
static volatile int g_patched11ffb0 = 0;
static volatile int g_patchedConnect = 0;
static volatile int g_mmapOK = 0;
static volatile int g_instrCount = 0;

// ===== 崩溃抓取 =====
static volatile uint64_t g_crashPC = 0, g_crashFAR = 0;
static volatile int g_crashed = 0;
static volatile int g_crashSig = 0;

static void sig_handler(int sig, siginfo_t *si, void *uctx){
    ucontext_t *uc = (ucontext_t *)uctx;
    g_crashPC  = uc->uc_mcontext->__ss.__pc;
    g_crashFAR = (uint64_t)si->si_addr;
    g_crashSig = sig;
    g_crashed  = 1;
}
static void installSigHandler(void){
    struct sigaction sa = {0};
    sa.sa_sigaction = sig_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
}

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

// ===== patch 0x11ffb0 =====
static void manualPatch11ffb0(void){
    if(!g_targetBase) return;
    uint32_t *p = (uint32_t*)va(k11ffb0File);

    if((p[0] & 0xFFC003FF) != 0xD10043FF) return;

    static uint32_t saved[8];
    for(int i=0;i<8;i++) saved[i] = p[i];

    uint32_t *tr = (uint32_t*)mmap(NULL, 0x1000,
                                   PROT_READ|PROT_WRITE|PROT_EXEC,
                                   0x1000|0x0002, -1, 0);
    if(tr == MAP_FAILED){ g_mmapOK = -1; return; }
    g_mmapOK = 1;

    uint64_t armAddr = (uint64_t)&armFull;
    uint64_t trAddr  = (uint64_t)tr;
    uint64_t trPC    = trAddr;
    uint64_t trPage  = trAddr & ~0xFFFULL;
    uint64_t back    = (uint64_t)va(k11ffb0File + 32);

    tr[0] = 0xA9BF7BFD;  // stp x29, x30, [sp, #-0x10]!
    uint64_t pc1 = trPC + 4;
    int64_t  off1 = ((int64_t)(armAddr - pc1)) >> 2;
    tr[1] = 0x94000000 | ((uint32_t)off1 & 0x03FFFFFF);  // bl armFull
    tr[2] = 0xA8C17BFD;  // ldp x29, x30, [sp], #0x10
    for(int i=0;i<8;i++) tr[3+i] = saved[i];
    uint64_t pc11 = trPC + 44;
    int64_t  off11 = ((int64_t)(back - pc11)) >> 2;
    tr[11] = 0x14000000 | ((uint32_t)off11 & 0x03FFFFFF);  // b 0x11ffd0

    uint64_t pcPage = (uint64_t)p & ~0xFFFULL;
    int64_t  adrpOff = ((int64_t)(trPage - pcPage)) >> 12;
    uint32_t addOff  = (uint32_t)(trAddr & 0xFFF);

    p[0] = 0x90000010 | (((uint32_t)adrpOff & 0x1FFFFF) << 5);
    p[1] = 0x91000210 | ((addOff & 0xFFF) << 10);
    p[2] = 0xD61F0200;
    p[3] = 0xD503201F;

    sys_icache_invalidate(p, 16);
    sys_icache_invalidate(tr, 48);

    g_patched11ffb0 = 1;
}

// ===== patch connect IP =====
static void patchConnectFail(void){
    if(!g_targetBase) return;
    uint32_t *p = (uint32_t*)va(0xd28d0);
    if(p[0] == 0xB90B07FF) return;
    p[0] = 0xB90B07FF;  // str wzr, [sp, #0xb04]
    sys_icache_invalidate(p, 4);
    g_patchedConnect = 1;
}

// ===== 弹窗 hook =====
static IMP g_origPresent = NULL;
static void hookPresent(id self, SEL _cmd, UIViewController *vc, BOOL anim, void (^comp)(void)){
    if([vc isKindOfClass:[UIAlertController class]]){
        g_popupCount++;
        return;
    }
    ((void(*)(id,SEL,UIViewController*,BOOL,void(^)(void)))g_origPresent)(self,_cmd,vc,anim,comp);
}
static void installPopupHook(void){
    Method m = class_getInstanceMethod([UIViewController class],
                                       sel_registerName("presentViewController:animated:completion:"));
    if(m){
        g_origPresent = method_getImplementation(m);
        method_setImplementation(m, (IMP)hookPresent);
        g_hookPopup = 1;
    }
}

// ===== 检条 =====
@interface BallTarget : NSObject
@property(nonatomic,strong) UILabel *dbgLabel;
@property(nonatomic,strong) UIButton *ballBtn;
@end
@implementation BallTarget
+ (NSString *)statusText{
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"base=%p\n", (void*)g_targetBase];
    [s appendFormat:@"tick=%d n=%d\n", g_refreshTick, g_nimg];
    if(g_targetBase){
        uintptr_t g = kSessionBaseFile;
        [s appendFormat:@"658=%u 348=%u\n",
            r32(g+0x658), r32(0x3fc000+0x348)];
        [s appendFormat:@"obj=%p\n", (void*)r64(g+0x698)];
        [s appendFormat:@"v330=%p v328=%p\n",
            (void*)r64(0x3fc000+0x330),
            (void*)r64(0x3fc000+0x328)];
    }
    [s appendFormat:@"wins=%lu\n",
        (unsigned long)UIApplication.sharedApplication.windows.count];
    if(g_crashed) [s appendFormat:@"C sig=%d pc=%llx\n", g_crashSig, g_crashPC];
    return s;
}
- (void)refresh{
    g_refreshTick++;
    self.dbgLabel.text = [BallTarget statusText];
}
- (void)tap{ [self refresh]; }
@end
static UIButton *ball = nil;

static void spawnBall(void){
    @try{
        NSArray *wins = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        wins = UIApplication.sharedApplication.windows;
#pragma clang diagnostic pop

        if(!wins || wins.count == 0){
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1*NSEC_PER_SEC)),
                           dispatch_get_main_queue(),^{ spawnBall(); });
            return;
        }
        UIWindow *w = wins[0];

        BallTarget *t = [BallTarget new];

        UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(10, 60, 320, 320)];
        lbl.backgroundColor = [UIColor colorWithWhite:0 alpha:0.7];
        lbl.textColor = [UIColor whiteColor];
        lbl.font = [UIFont systemFontOfSize:10];
        lbl.numberOfLines = 0;
        lbl.text = @"init";
        lbl.userInteractionEnabled = YES;
        t.dbgLabel = lbl;
        [w addSubview:lbl];
        [w bringSubviewToFront:lbl];

        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(w.bounds.size.width - 80, w.bounds.size.height - 150, 60, 60);
        b.backgroundColor = [UIColor redColor];
        b.layer.cornerRadius = 30;
        b.layer.borderWidth = 2;
        b.layer.borderColor = [UIColor whiteColor].CGColor;
        t.ballBtn = b;
        [b addTarget:t action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
        [w addSubview:b];
        [w bringSubviewToFront:b];

        [t refresh];

        __block BallTarget *bt = t;
        void (^tick)(void) = ^{
            [bt refresh];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1*NSEC_PER_SEC)),
                           dispatch_get_main_queue(), tick);
        };
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1*NSEC_PER_SEC)),
                       dispatch_get_main_queue(), tick);
    }@catch(NSException*e){}
}
__attribute__((constructor))
static void initBy(void){
    @autoreleasepool{
        spawnBall();
    }
}
