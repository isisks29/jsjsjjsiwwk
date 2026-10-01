#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
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

static uintptr_t findTargetBase(void){
    uint32_t n = _dyld_image_count();
    for(uint32_t i=0;i<n;i++){
        const char *name = _dyld_get_image_name(i);
        if(name && (strstr(name,"ace") || strstr(name,"ballsace")))
            return (uintptr_t)_dyld_get_image_header(i);
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
static volatile int g_ballAlive = 0;
static volatile int g_ballTried = 0;
static volatile int g_refreshTick = 0;
static volatile int g_armDone = 0;
static volatile int g_patched11ffb0 = 0;
static volatile int g_mmapOK = 0;
static volatile int g_instrCount = 0;
static UIButton *ball = nil;

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

// ===== 前置声明 =====
static void armFull_entry(void);

// ===== 手写 patch：入口换成跳板，先 arm 再执行原指令 =====
static void manualPatch11ffb0(void){
    if(!g_targetBase) return;
    uint32_t *p = (uint32_t*)va(k11ffb0File);

    // 检查是否已是 sub sp,sp,#0x150（0xD10043FF）
    if((p[0] & 0xFFC003FF) != 0xD10043FF) return;

    static uint32_t saved[8];
    for(int i=0;i<8;i++) saved[i] = p[i];

    // 使用数字常量：0x1000=MAP_ANON, 0x0002=MAP_PRIVATE
    uint32_t *tr = (uint32_t*)mmap(NULL, 0x1000,
                                   PROT_READ|PROT_WRITE|PROT_EXEC,
                                   0x1000|0x0002, -1, 0);
    if(tr == MAP_FAILED){
        g_mmapOK = -1;
        return;
    }
    g_mmapOK = 1;

    // trampoline 布局：
    // [0]  adrp x16, armFull_entry页
    // [1]  add  x16, x16, #offset
    // [2]  br   x16
    // [3..10] 原 8 条指令
    // [11] b 回 0x11ffb0+32
    uint64_t entryAddr = (uint64_t)&armFull_entry;
    uint64_t trAddr    = (uint64_t)tr;
    uint64_t trPage    = trAddr & ~0xFFFULL;
    int64_t  adrpImm   = ((int64_t)((entryAddr & ~0xFFFULL) - trPage)) >> 12;
    uint32_t addImm    = (uint32_t)(entryAddr & 0xFFF);

    tr[0] = 0x90000010 | (((uint32_t)adrpImm & 0x1FFFFF) << 5);
    tr[1] = 0x91000210 | ((addImm & 0xFFF) << 10);
    tr[2] = 0xD61F0200;

    for(int i=0;i<8;i++) tr[3+i] = saved[i];

    uint64_t back = (uint64_t)va(k11ffb0File + 32);
    uint64_t cur  = (uint64_t)&tr[11];
    int64_t  off  = ((int64_t)(back - cur)) >> 2;
    tr[11] = 0x14000000 | (off & 0x03FFFFFF);

    // 入口 patch：adrp x16,tr页 ; add x16,x16,off ; br x16 ; nop
    uint64_t pcPage  = (uint64_t)p & ~0xFFFULL;
    int64_t  trAdrp  = ((int64_t)(trPage - pcPage)) >> 12;
    uint32_t trAdd   = (uint32_t)(trAddr & 0xFFF);

    p[0] = 0x90000010 | (((uint32_t)trAdrp & 0x1FFFFF) << 5);
    p[1] = 0x91000210 | ((trAdd & 0xFFF) << 10);
    p[2] = 0xD61F0200;
    p[3] = 0xD503201F; // nop

    __builtin___clear_cache((char*)p, (char*)p + 32);
    __builtin___clear_cache((char*)tr, (char*)tr + 48);

    g_patched11ffb0 = 1;
}

// 跳板先执行这个 → arm 一次 → 再走原指令
static void armFull_entry(void){
    g_instrCount++;
    armFull();
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
@property(nonatomic,strong) UILabel *bar;
@end
@implementation BallTarget
- (void)refresh{
    g_refreshTick++;
    if(!g_targetBase){ self.bar.text = @"[NO BASE]"; return; }

    uintptr_t g = kSessionBaseFile;
    uint64_t obj = r64(g+0x698);
    uint64_t sc  = r64(0x3fc000+0x338);
    uint64_t tc  = r64(0x3fc000+0x340);

    NSString *ballStr;
    if(!g_ballTried) ballStr = @"未试";
    else if(!ball)   ballStr = @"NULL";
    else if(g_ballAlive) ballStr = @"YES";
    else             ballStr = @"NO";

    self.bar.text = [NSString stringWithFormat:
        @"658=%u 348=%u\n"
         "6a0=%llx 680=%llx\n"
         "6a8=%08x 688=%08x\n"
         "obj=%p\n"
         "sc=%llx tc=%llx\n"
         "hook=%d 弹=%d arm=%d\n"
         "pat=%d mm=%d ins=%d\n"
         "球=%@ tick=%d\n"
         "crash=%d pc=%llx\n"
         "far=%llx sig=%d",
        r32(g+0x658), r32(0x3fc000+0x348),
        r64(g+0x6a0), r64(g+0x680),
        r32(g+0x6a8), r32(g+0x688),
        (void*)obj,
        sc, tc,
        g_hookPopup, g_popupCount, g_armDone,
        g_patched11ffb0, g_mmapOK, g_instrCount,
        ballStr, g_refreshTick,
        g_crashed, g_crashPC,
        g_crashFAR, g_crashSig];
}
- (void)tap{
    armFull();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),
                   dispatch_get_main_queue(),^{ [self refresh]; });
}
@end

static UIWindow *findKeyWindow(void){
    UIApplication *app = UIApplication.sharedApplication;
    if(!app) return nil;
    for(UIScene *s in app.connectedScenes){
        if([s isKindOfClass:[UIWindowScene class]]){
            UIWindowScene *ws = (UIWindowScene*)s;
            for(UIWindow *w in ws.windows) if(w.isKeyWindow) return w;
            if(ws.windows.count > 0) return ws.windows.firstObject;
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if(app.keyWindow) return app.keyWindow;
    if(app.windows.count > 0) return app.windows.firstObject;
#pragma clang diagnostic pop
    return nil;
}

static void updateBallAlive(void){
    if(!ball){ g_ballAlive = 0; return; }
    g_ballAlive = (ball.window != nil || ball.superview != nil) ? 1 : 0;
}

static void spawnBall(void){
    g_ballTried = 1;
    @try{
        for(int i=0;i<600;i++){
            @autoreleasepool{
                UIWindow *win = findKeyWindow();
                if(win){
                    BallTarget *t = [BallTarget new];
                    ball = [UIButton buttonWithType:UIButtonTypeSystem];
                    ball.frame = CGRectMake(20,120,270,260);
                    ball.backgroundColor = [UIColor colorWithRed:0.1 green:0.6 blue:1 alpha:0.9];
                    ball.layer.cornerRadius = 12;
                    UILabel *bar = [[UILabel alloc] initWithFrame:ball.bounds];
                    bar.textColor = [UIColor whiteColor];
                    bar.font = [UIFont systemFontOfSize:9];
                    bar.numberOfLines = 0;
                    bar.text = @"—";
                    t.bar = bar;
                    [ball addSubview:bar];
                    [ball addTarget:t action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
                    [win addSubview:ball];
                    [win bringSubviewToFront:ball];
                    [t refresh];
                    __block BallTarget *bt = t;
                    void (^tick)(void) = ^{
                        [bt refresh];
                        updateBallAlive();
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1*NSEC_PER_SEC)),
                                       dispatch_get_main_queue(), tick);
                    };
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1*NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), tick);
                    return;
                }
            }
            usleep(500000);
        }
    }@catch(NSException*e){}
}

__attribute__((constructor))
static void initBy(void){
    @autoreleasepool{
        g_targetBase = findTargetBase();
        installSigHandler();
        installPopupHook();
        armFull();

        @try { manualPatch11ffb0(); }
        @catch(NSException *e) { }

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ spawnBall(); });
    }
}
