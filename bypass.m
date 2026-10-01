#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_time.h>

static const uintptr_t kSessionBaseFile = 0x3ff000;
static const uintptr_t kSub11fa5cFile   = 0x11fa5c;

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

// ===== 状态量 =====
typedef NS_ENUM(int, Stage){ S_INIT=0, S_ARM, S_CALL, S_OK };
static volatile int g_stage = S_INIT;
static volatile int g_popupCount = 0;
static volatile int g_hookPopup = 0;
static volatile int g_hookIcon = 0;
static volatile int g_callSub11fa5c = 0;
static volatile int g_ballAlive = 0;
static volatile int g_ballTried = 0;
static volatile int g_refreshTick = 0;
static UIButton *ball = nil;

static NSString *stageName(int s){
    switch(s){ case S_INIT:return @"INIT"; case S_ARM:return @"ARM";
               case S_CALL:return @"CALL"; case S_OK:return @"OK"; }
    return @"?";
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
        w32(g+0x658, 1);
        g_stage = S_ARM;
    }@catch(NSException*e){}
}

// ===== 弹窗 hook =====
static IMP g_origPresent = NULL;
static void hookPresent(id self, SEL _cmd, UIViewController *vc, BOOL anim, void (^comp)(void)){
    if([vc isKindOfClass:[UIAlertController class]]){
        g_popupCount++;
        if(comp) comp();
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
    uintptr_t g = kSessionBaseFile;
    uint32_t v658 = g_targetBase ? r32(g+0x658) : 0;
    uint64_t obj  = g_targetBase ? r64(g+0x698) : 0;
    uint32_t flag = g_targetBase ? r32(0x3fc000+0x348) : 0;

    NSString *ballStr;
    if(!g_ballTried) ballStr = @"球未试";
    else if(!ball)   ballStr = @"球NULL";
    else if(g_ballAlive) ballStr = @"球YES";
    else             ballStr = @"球NO";

    self.bar.text = [NSString stringWithFormat:
        @"[%@] 658=%u 348=%u\n"
         "obj=%p\n"
         "6a8=%08x 688=%08x\n"
         "hook P=%d I=%d\n"
         "弹窗=%d call5c=%d\n"
         "%@ tick=%d",
        stageName(g_stage), v658, flag, (void*)obj,
        r32(g+0x6a8), r32(g+0x688),
        g_hookPopup, g_hookIcon,
        g_popupCount, g_callSub11fa5c,
        ballStr, g_refreshTick];
}
- (void)tap{
    armFull();
    typedef void(*fn_t)(void);
    fn_t f = (fn_t)va(kSub11fa5cFile);
    if(f){ g_stage = S_CALL; g_callSub11fa5c++; f(); g_stage = S_OK; }
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
                    ball.frame = CGRectMake(20,120,270,200);
                    ball.backgroundColor = [UIColor colorWithRed:0.1 green:0.6 blue:1 alpha:0.9];
                    ball.layer.cornerRadius = 12;
                    UILabel *bar = [[UILabel alloc] initWithFrame:ball.bounds];
                    bar.textColor = [UIColor whiteColor];
                    bar.font = [UIFont systemFontOfSize:10];
                    bar.numberOfLines = 0;
                    bar.text = @"—";
                    t.bar = bar;
                    [ball addSubview:bar];
                    [ball addTarget:t action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
                    [win addSubview:ball];
                    [win bringSubviewToFront:ball];
                    [t refresh];
                    // 自动刷新
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
        installPopupHook();
        armFull();

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{
            typedef void(*fn_t)(void);
            fn_t f = (fn_t)va(kSub11fa5cFile);
            if(f){ g_stage = S_CALL; g_callSub11fa5c++; f(); }
        });

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ spawnBall(); });
    }
}
