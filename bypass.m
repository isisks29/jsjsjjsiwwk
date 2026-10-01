#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_time.h>

static const uintptr_t kSessionBaseFile = 0x3ff000;

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

static volatile int g_armDone = 0;

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

// ★★★ 测试版：只 arm 门卫，不 arm 会话对象 ★★★
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

        // w64(g+0x698, (uintptr_t)buildSessionObj());  // ← 暂时关掉

        g_armDone = 1;
    }@catch(NSException*e){}
}

// ===== 弹窗 hook =====
static IMP g_origPresent = NULL;
static volatile int g_popupCount = 0;
static volatile int g_hookPopup = 0;
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
static volatile int g_ballAlive = 0;
static volatile int g_ballTried = 0;
static volatile int g_refreshTick = 0;
static UIButton *ball = nil;

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
        @"658=%u 348=%u obj=%p\n"
         "sc=%llx tc=%llx\n"
         "6a0=%llx 680=%llx\n"
         "6a8=%08x 688=%08x\n"
         "hook=%d 弹窗=%d\n"
         "arm=%d 球=%@ tick=%d",
        r32(g+0x658), r32(0x3fc000+0x348), (void*)obj,
        sc, tc,
        r64(g+0x6a0), r64(g+0x680),
        r32(g+0x6a8), r32(g+0x688),
        g_hookPopup, g_popupCount,
        g_armDone, ballStr, g_refreshTick];
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
                    ball.frame = CGRectMake(20,120,270,220);
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
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{
            installPopupHook();
            armFull();
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(4*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ spawnBall(); });
    }
}
