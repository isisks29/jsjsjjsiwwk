#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <mach/mach.h>

// ============ 目标常量 ============
static const uintptr_t kBuildFnFile      = 0x109020;
static const uintptr_t kIconOnClickFile  = 0x111bd8;
static const uintptr_t kSessionBaseFile  = 0x3ff000;
static const uintptr_t kOffVerifyResult  = 0x658;
static const uintptr_t kOffSessionObj    = 0x698;

#define GATE0   0x0000000000000001ULL     // ← 小值，x20 会很大，时间窗大概率失败；先测其它关
#define MIX_K   0xD18DDB25u

static uintptr_t g_targetBase = 0;

static uintptr_t findTargetBase(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name,"ace") || strstr(name,"ballsace")))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}
static inline void *va(uintptr_t f){ return (void*)(g_targetBase+f); }
static inline void w64(uintptr_t f,uint64_t v){ *(volatile uint64_t*)va(f)=v; }
static inline void w32(uintptr_t f,uint32_t v){ *(volatile uint32_t*)va(f)=v; }
static inline uint64_t r64(uintptr_t f){ return *(volatile uint64_t*)va(f); }
static inline uint32_t r32(uintptr_t f){ return *(volatile uint32_t*)va(f); }

// ============ 检条状态 ============
typedef NS_ENUM(int, Stage) {
    S_INIT=0, S_ARM, S_GATE, S_SESSION, S_CLICK, S_BUILD, S_OK
};
static volatile int g_stage = S_INIT;
static NSString *stageName(int s){
    switch(s){
        case S_INIT: return @"INIT";
        case S_ARM: return @"ARM";
        case S_GATE: return @"GATE";
        case S_SESSION: return @"SESSION";
        case S_CLICK: return @"CLICK";
        case S_BUILD: return @"BUILD";
        case S_OK: return @"OK?";
    }
    return @"?";
}

// ============ 门卫公式 ============
static inline uint32_t mix(uint32_t x){
    x ^= x>>15; x *= 0x1F3D6A71u;
    x ^= x>>11; x *= 0x8E4B1395u;
    x ^= x>>17; return x;
}
static void writeGateBlock(uintptr_t g){
    uint64_t P   = r64(g+0x6a0);
    uint64_t x20 = 0xB75E8052BABD72A6ULL ^ P;
    uint32_t lo=(uint32_t)x20, hi=(uint32_t)(x20>>32);
    uint32_t v1 = mix((lo^hi) ^ MIX_K);
    w32(g+0x6a8, v1);
    uint32_t v2 = mix(v1 ^ 0x1767CEDCu) ^ lo;
    w32(g+0x6ac, v2);
    uint32_t v3 = mix(v2 ^ 0x5D41C293u) ^ hi;
    w32(g+0x6b0, v3);
    NSLog(@"[GATE] v1=%08x v2=%08x v3=%08x x20=%llx", v1,v2,v3,(unsigned long long)x20);
}

// ============ 会话对象 ============
static void* buildSessionObj(void){
    void *obj = calloc(1, 0x11c6);
    uint64_t b0=0x123456789abcdef0ULL, b8=0xfedcba9876543210ULL;
    uint32_t b16=0x11223344, b24=0x55667788, b32=0x99aabbcc;
    uint64_t *P=(uint64_t*)((uintptr_t)obj+0x119a);
    P[0]=b0; P[1]=b8; P[2]=b16; P[3]=b24; P[4]=b32;

    uint32_t h=((uint32_t)(b8>>32)^(uint32_t)b8)*0x45D9F3B7u;
    h^=b16; h*=0x8E4B1395u; h^=b24; h*=0x1F3D6A71u; h^=b32; h^=h>>16;
    *(uint32_t*)((uintptr_t)obj+0x11c2)=h;

    *(uint32_t*)((uintptr_t)obj+0x0)  = (b32^(uint32_t)(b0>>19))^0x5F8A16E3u;
    *(uint64_t*)((uintptr_t)obj+0x78) = b0^b8^0xA5C3E1F7B6D2489AULL;
    *(uint32_t*)((uintptr_t)obj+0x8e) = (b16^(uint32_t)(b0>>7)) ^0x4A9B5206u;
    *(uint32_t*)((uintptr_t)obj+0x92) = (b24^(uint32_t)(b0>>13))^0x8C1A73E5u;
    NSLog(@"[SESSION] obj=%p b40=%08x +0=%08x +78=%llx +8e=%08x +92=%08x",
          obj,h,
          *(uint32_t*)((uintptr_t)obj+0x0),
          *(unsigned long long*)((uintptr_t)obj+0x78),
          *(uint32_t*)((uintptr_t)obj+0x8e),
          *(uint32_t*)((uintptr_t)obj+0x92));
    return obj;
}

static void armFull(void){
    if(!g_targetBase){ NSLog(@"[ARM] no base"); return; }
    @try {
        uintptr_t g=kSessionBaseFile;

        w64(g+0x6a0, GATE0);
        writeGateBlock(g);
        g_stage = S_GATE;

        w64(g+0x698, (uintptr_t)buildSessionObj());
        g_stage = S_SESSION;

        w32(g+0x658, 1);
        NSLog(@"[ARM] done 658=1 6a0=%llx 698=%p",
              (unsigned long long)r64(g+0x6a0),
              (void*)r64(g+0x698));
    } @catch(NSException*e){ NSLog(@"[ARM] exc %@",e); }
}

// ============ hook ============
static void (*origIconClick)(id,SEL);
static void hookIconClick(id self,SEL _cmd){
    g_stage = S_CLICK;
    @try{ armFull(); }@catch(NSException*e){}
    if(origIconClick) origIconClick(self,_cmd);
    g_stage = S_OK;
}
static void installIconHook(void){
    Class menu=objc_getClass("_0xD4E9A3C7");
    Method m = menu?class_getInstanceMethod(menu,sel_registerName("iconOnClick")):NULL;
    if(m){
        origIconClick=(void(*)(id,SEL))method_getImplementation(m);
        method_setImplementation(m,(IMP)hookIconClick);
        NSLog(@"[ICON] hooked");
    } else NSLog(@"[ICON] class/method not found");
}

// ============ 检条视图 ============
@interface BallTarget : NSObject
@property(nonatomic,strong) UILabel *bar;
@end
@implementation BallTarget
- (void)refresh {
    uintptr_t g=kSessionBaseFile;
    uint32_t v658 = g_targetBase?r32(g+kOffVerifyResult):0;
    uint64_t obj  = g_targetBase?r64(g+kOffSessionObj):0;
    uint32_t g6a8 = g_targetBase?r32(g+0x6a8):0;
    uint32_t g6ac = g_targetBase?r32(g+0x6ac):0;
    uint32_t g6b0 = g_targetBase?r32(g+0x6b0):0;

    NSString *s = [NSString stringWithFormat:
        @"[%@]\n658=%u obj=%p\n6a8=%08x\n6ac=%08x\n6b0=%08x",
        stageName(g_stage), v658, (void*)obj, g6a8, g6ac, g6b0];
    self.bar.text = s;
    NSLog(@"[PROBE] stage=%d 658=%u obj=%p g6a8=%08x g6ac=%08x g6b0=%08x",
          g_stage, v658, (void*)obj, g6a8, g6ac, g6b0);
}
- (void)tap {
    @try {
        g_stage = S_ARM;
        armFull();
        // 主动调构建函数
        if(g_targetBase){
            typedef void(*fn_t)(void);
            fn_t fn=(fn_t)va(kBuildFnFile);
            if(fn){ g_stage=S_BUILD; fn(); }
        }
        [self refresh];
    } @catch(NSException*e){ NSLog(@"[BALL] %@",e); }
}
@end

static UIButton *ball=nil;
static void spawnBall(void){
    @try {
        for(int i=0;i<100;i++){
            @autoreleasepool{
                UIWindow *win = UIApplication.sharedApplication.keyWindow;
                if(win){
                    BallTarget *t=[BallTarget new];
                    ball=[UIButton buttonWithType:UIButtonTypeSystem];
                    ball.frame=CGRectMake(20,120,220,140);
                    ball.backgroundColor=[UIColor colorWithRed:0.1 green:0.6 blue:1 alpha:0.9];
                    ball.layer.cornerRadius=12;
                    UILabel *bar=[[UILabel alloc] initWithFrame:ball.bounds];
                    bar.textColor=[UIColor whiteColor];
                    bar.font=[UIFont systemFontOfSize:11];
                    bar.numberOfLines=0;
                    bar.text=@"—";
                    t.bar=bar;
                    [ball addSubview:bar];
                    [ball addTarget:t action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
                    [win addSubview:ball];
                    [t refresh];
                    return;
                }
            }
            usleep(300000);
        }
    } @catch(NSException*e){ NSLog(@"[BALL] spawn %@",e); }
}

__attribute__((constructor))
static void initBy(void){
    @autoreleasepool{
        g_targetBase = findTargetBase();
        NSLog(@"[BY] base=%p",(void*)g_targetBase);
        installIconHook();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ spawnBall(); });
    }
}
