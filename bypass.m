#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

static volatile int g_tick = 0;

@interface BallTarget : NSObject
@property(nonatomic,strong) UILabel *lbl;
@end
@implementation BallTarget
- (void)tap{ g_tick++; self.lbl.text = [NSString stringWithFormat:@"tick=%d", g_tick]; }
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

        UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(10,60,300,200)];
        lbl.backgroundColor = [UIColor colorWithWhite:0 alpha:0.7];
        lbl.textColor = [UIColor whiteColor];
        lbl.font = [UIFont systemFontOfSize:12];
        lbl.numberOfLines = 0;
        lbl.text = @"tick=0";
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
    }@catch(NSException*e){}
}

__attribute__((constructor))
static void initBy(void){
    @autoreleasepool{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3*NSEC_PER_SEC)),
                       dispatch_get_main_queue(),^{ spawnBall(); });
    }
}
