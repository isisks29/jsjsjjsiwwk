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

static volatile int g_tick = 0;

// ===== 枚举 image =====
#define MAX_IMG 256
typedef struct { char name[256]; uintptr_t hdr; } ImgInfo;
static ImgInfo g_imgs[MAX_IMG];
static int g_nimg = 0;
static uintptr_t g_targetBase = 0;

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
        if(strcasestr(g_imgs[i].name, "ace") || strcasestr(g_imgs[i].name, "balls"))
            return g_imgs[i].hdr;
    }
    return 0;
}

// ===== 球 + label =====
@interface BallTarget : NSObject
@property(nonatomic,strong) UILabel *lbl;
@end
@implementation BallTarget
- (void)refresh{
    g_tick++;
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"tick=%d n=%d\n", g_tick, g_nimg];
    [s appendFormat:@"base=%p\n", (void*)g_targetBase];
    for(int i=0;i<g_nimg && i<12;i++){
        const char *bn = strrchr(g_imgs[i].name,'/');
        bn = bn ? bn+1 : g_imgs[i].name;
        [s appendFormat:@"%d %s\n", i, bn];
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

        UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(10,60,340,500)];
        lbl.backgroundColor = [UIColor colorWithWhite:0 alpha:0.7];
        lbl.textColor = [UIColor whiteColor];
        lbl.font = [UIFont systemFontOfSize:12];
        lbl.numberOfLines = 0;
        lbl.text = @"init";
        lbl.userInteractionEnabled = YES;
        t.lbl = lbl;
        [w addSubview:lbl];
        [w bringSubviewToFront:lbl];

        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(w.bounds.size.width-80, w.bounds.size.height-150, 60, 60);
        b.backgroundColor = [UIColor redColor];
        b.layer.cornerRadius = 30;
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
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{
            spawnBall();
        });
    }
}
