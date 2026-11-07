// bypass.m —— 诊断用动态库（只读观察，不修改靶场任何逻辑）
//
// 作用：注入到含靶场的 App 后，自动收集以下几类运行时信息，并把一份
//       纯文本报告写进系统剪贴板，方便直接粘贴传回：
//         1. 靶场 dylib 的加载基址、混淆类名清单；
//         2. 所有 UIWindow / 视图树的类名、frame、hidden、alpha；
//         3. 靶场内部几个关键全局变量（悬浮容器、窗口、面板开关）的值；
//         4. 悬浮窗口 hitTest、图标点击、ImGui 渲染的调用计数与轨迹。
//
// 用法：GitHub Actions 编译成 bypass.dylib，和 qxt.dylib 一起注入同一个 ipa。
//       进入 App 后等 8 秒左右，报告会自动写入剪贴板（之后 16s / 30s 还会
//       再刷新一次）。中途点一下右上角图标区域，点击轨迹也会被记录进去。

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dispatch/dispatch.h>
#import <stdarg.h>
#import <string.h>

static NSMutableString *gLog = nil;
static NSLock        *gLock = nil;
static uintptr_t      gBase = 0;

static int gHitCount   = 0;   // 悬浮窗口 hitTest 调用次数
static int gClickCount = 0;   // 图标点击处理调用次数
static int gDrawCount  = 0;   // ImGui 渲染帧数
static int gTouchB     = 0;   // 图标 touchesBegan 次数
static int gTouchE     = 0;   // 图标 touchesEnded 次数
static int gKeyWin     = 0;   // canBecomeKeyWindow 次数

// ---------------------------------------------------------------- 日志

static void L(NSString *fmt, ...) {
    @autoreleasepool {
        va_list ap;
        va_start(ap, fmt);
        NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);
        [gLock lock];
        [gLog appendFormat:@"%@\n", line];
        [gLock unlock];
        NSLog(@"[QXTDIAG] %@", line);
    }
}

// ---------------------------------------------------------------- 基址

static uintptr_t baseFromIndex(uint32_t idx) {
    const struct mach_header_64 *h =
        (const struct mach_header_64 *)_dyld_get_image_header(idx);
    if (!h) return 0;
    intptr_t slide = _dyld_get_image_vmaddr_slide(idx);
    uintptr_t vmaddr = 0;
    const struct load_command *lc =
        (const struct load_command *)((const char *)h + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < h->ncmds && lc; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__TEXT") == 0) {
                vmaddr = (uintptr_t)sg->vmaddr;
                break;
            }
        }
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    return (uintptr_t)slide + vmaddr;
}

static uintptr_t findQxtBase(void) {
    // 优先：通过靶场窗口类所在镜像精确定位
    Class winCls = objc_getClass("_0x8C2F4D71");
    if (winCls) {
        const char *img = class_getImageName(winCls);
        if (img) {
            uint32_t n = _dyld_image_count();
            for (uint32_t i = 0; i < n; i++) {
                const char *nm = _dyld_get_image_name(i);
                if (nm && strcmp(nm, img) == 0) {
                    L(@"靶场镜像(按类定位): %s", nm);
                    return baseFromIndex(i);
                }
            }
        }
    }
    // 兜底：文件名里含 qxt
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "qxt") || strstr(nm, "QXT")) {
            L(@"靶场镜像(按文件名): %s", nm);
            return baseFromIndex(i);
        }
    }
    return 0;
}

static uintptr_t G(uintptr_t off) {
    if (!gBase) return 0;
    return *(uintptr_t *)(gBase + off);
}
static uint8_t GB(uintptr_t off) {
    if (!gBase) return 0;
    return *(uint8_t *)(gBase + off);
}

static BOOL looksLikeObject(id o) {
    uintptr_t p = (uintptr_t)(__bridge void *)o;
    return p > 0x100000000ULL && p < 0x00007FFFFFFFFFFFULL;
}

// ---------------------------------------------------------------- 描述对象

static NSString *descObj(id o) {
    if (!o) return @"nil";
    if (!looksLikeObject(o)) return [NSString stringWithFormat:@"(bad ptr %p)", (__bridge void *)o];
    @try {
        NSString *cn = NSStringFromClass(object_getClass(o));
        if ([o isKindOfClass:[UIView class]]) {
            UIView *v = (UIView *)o;
            return [NSString stringWithFormat:
                    @"<%@ %p> f=%@ h=%d a=%.2f win=%@ sub=%lu",
                    cn, (__bridge void *)o, NSStringFromCGRect(v.frame),
                    (int)v.hidden, v.alpha,
                    v.window ? NSStringFromClass([v.window class]) : @"nil",
                    (unsigned long)v.subviews.count];
        }
        return [NSString stringWithFormat:@"<%@ %p>", cn, (__bridge void *)o];
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"(desc error %@)", e.reason];
    }
}

static void dumpView(UIView *v, int depth, int *budget) {
    if (!v || *budget <= 0) return;
    (*budget)--;
    NSString *pad = [@"" stringByPaddingToLength:(NSUInteger)(depth * 2)
                                      withString:@" " startingAtIndex:0];
    L(@"%@%@ f=%@ h=%d a=%.2f tag=%ld win=%@ sup=%@",
      pad, NSStringFromClass([v class]), NSStringFromCGRect(v.frame),
      (int)v.hidden, v.alpha, (long)v.tag,
      v.window ? NSStringFromClass([v.window class]) : @"nil",
      v.superview ? NSStringFromClass([v.superview class]) : @"nil");
    if (depth >= 8) return;
    for (UIView *s in v.subviews) dumpView(s, depth + 1, budget);
}

// 视图祖先链（判断对象到底挂在哪个窗口上）
static NSString *parentChain(id o) {
    if (![o isKindOfClass:[UIView class]]) return @"(不是视图)";
    NSMutableArray *a = [NSMutableArray array];
    UIView *v = (UIView *)o;
    for (int i = 0; i < 12 && v; i++) {
        [a addObject:NSStringFromClass([v class])];
        v = v.superview;
    }
    return [a componentsJoinedByString:@" < "];
}

// 同时收集 app.windows 与 UIScene 场景窗口（iOS 13+ 某些 App 的 windows 为空）
static NSArray<UIWindow *> *allWindows(void) {
    NSMutableArray<UIWindow *> *arr = [NSMutableArray array];
    UIApplication *app = UIApplication.sharedApplication;
    for (UIWindow *w in app.windows) { if (![arr containsObject:w]) [arr addObject:w]; }
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in app.connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)sc).windows) {
                if (![arr containsObject:w]) [arr addObject:w];
            }
        }
    }
    return arr;
}

// ---------------------------------------------------------------- 类名清单

static void listObfuscatedClasses(void) {
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) return;
    Class *buf = (Class *)malloc(sizeof(Class) * (size_t)total);
    if (!buf) return;
    total = objc_getClassList(buf, total);
    NSMutableArray *names = [NSMutableArray array];
    for (int i = 0; i < total; i++) {
        NSString *n = NSStringFromClass(buf[i]);
        if ([n hasPrefix:@"_0x"]) [names addObject:n];
    }
    free(buf);
    L(@"混淆类(%lu个): %@", (unsigned long)names.count,
      [names componentsJoinedByString:@" "]);
}

// ---------------------------------------------------------------- 快照

static void snap(NSString *tag) {
    @autoreleasepool {
        L(@"---------- 快照 %@ ----------", tag);
        L(@"base=%p", (void *)gBase);

        L(@"全局 container(0x18581E0)=%@", descObj((__bridge id)(void *)G(0x18581E0)));
        L(@"  祖先链: %@", parentChain((__bridge id)(void *)G(0x18581E0)));
        L(@"全局 view(0x18581D8)=%@",      descObj((__bridge id)(void *)G(0x18581D8)));
        L(@"  祖先链: %@", parentChain((__bridge id)(void *)G(0x18581D8)));
        L(@"开关 0x1851CE0[0]=%u  0x1851F34=%u  0x1851CA0=%p  0x1851CA8=%p  0x1851CB0=%p",
          GB(0x1851CE0), GB(0x1851F34),
          (void *)G(0x1851CA0), (void *)G(0x1851CA8), (void *)G(0x1851CB0));

        NSArray<UIWindow *> *wins = allWindows();
        UIWindow *keyWin = nil;
        for (UIWindow *w in wins) { if (w.isKeyWindow) { keyWin = w; break; } }
        L(@"窗口数=%lu keyWindow=%@", (unsigned long)wins.count, descObj(keyWin));

        for (UIWindow *w in wins) {
            L(@"WIN <%@ %p> level=%.1f h=%d a=%.2f f=%@ rvc=%@",
              NSStringFromClass([w class]), (__bridge void *)w,
              (double)w.windowLevel, (int)w.hidden, w.alpha,
              NSStringFromCGRect(w.frame),
              w.rootViewController ? NSStringFromClass([w.rootViewController class]) : @"nil");
            int budget = 80;
            for (UIView *s in w.subviews) dumpView(s, 1, &budget);
        }

        L(@"计数: hitTest=%d keyWin=%d click=%d draw=%d touchB=%d touchE=%d",
          gHitCount, gKeyWin, gClickCount, gDrawCount, gTouchB, gTouchE);
    }
}

// ---------------------------------------------------------------- hook

static void swizzleMethod(Class c, SEL sel, IMP newImp, IMP *origOut) {
    if (!c || !sel) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) {
        L(@"  hook 跳过（无方法）: %@ %@", NSStringFromClass(c), NSStringFromSelector(sel));
        return;
    }
    if (origOut) *origOut = method_getImplementation(m);
    class_replaceMethod(c, sel, newImp, method_getTypeEncoding(m));
    L(@"  hook 成功: %@ %@", NSStringFromClass(c), NSStringFromSelector(sel));
}

static IMP origHitTest = NULL;
static IMP origCanKey  = NULL;
static IMP origClick   = NULL;
static IMP origTouchB  = NULL;
static IMP origTouchE  = NULL;
static IMP origDraw    = NULL;

static id diagHitTest(id self, SEL _cmd, CGPoint pt, UIEvent *ev) {
    id r = ((id (*)(id, SEL, CGPoint, UIEvent *))origHitTest)(self, _cmd, pt, ev);
    int n = __sync_add_and_fetch(&gHitCount, 1);
    if (n <= 50) {
        L(@"[hitTest#%d] %@ pt=(%.0f,%.0f) -> %@",
          n, NSStringFromClass([self class]), pt.x, pt.y,
          r ? NSStringFromClass([r class]) : @"nil");
    }
    return r;
}

static BOOL diagCanBecomeKey(id self, SEL _cmd) {
    BOOL r = ((BOOL (*)(id, SEL))origCanKey)(self, _cmd);
    int n = __sync_add_and_fetch(&gKeyWin, 1);
    if (n <= 30) L(@"[canBecomeKeyWindow#%d] -> %d", n, (int)r);
    return r;
}

static void diagClick(id self, SEL _cmd) {
    int n = __sync_add_and_fetch(&gClickCount, 1);
    L(@"[iconOnClick#%d] %@", n, NSStringFromClass([self class]));
    if (origClick) ((void (*)(id, SEL))origClick)(self, _cmd);
}

static void diagTouchB(id self, SEL _cmd, NSSet *touches, UIEvent *ev) {
    int n = __sync_add_and_fetch(&gTouchB, 1);
    if (n <= 30) L(@"[touchesBegan#%d] %@", n, NSStringFromClass([self class]));
    if (origTouchB) ((void (*)(id, SEL, NSSet *, UIEvent *))origTouchB)(self, _cmd, touches, ev);
}

static void diagTouchE(id self, SEL _cmd, NSSet *touches, UIEvent *ev) {
    int n = __sync_add_and_fetch(&gTouchE, 1);
    if (n <= 30) L(@"[touchesEnded#%d] %@", n, NSStringFromClass([self class]));
    if (origTouchE) ((void (*)(id, SEL, NSSet *, UIEvent *))origTouchE)(self, _cmd, touches, ev);
}

static void diagDraw(id self, SEL _cmd, id view) {
    int n = __sync_add_and_fetch(&gDrawCount, 1);
    if (n == 1 || (n % 120) == 0) L(@"[drawInMTKView#%d] %@", n, NSStringFromClass([self class]));
    if (origDraw) ((void (*)(id, SEL, id))origDraw)(self, _cmd, view);
}

static void installHooks(void) {
    Class winCls  = objc_getClass("_0x8C2F4D71");
    Class iconCls = objc_getClass("_0xD4E9A3C7");
    Class viewCls = objc_getClass("_0x1E6B7A93");
    L(@"目标类: win=%p icon=%p view=%p", (__bridge void *)winCls, (__bridge void *)iconCls, (__bridge void *)viewCls);

    if (winCls) {
        swizzleMethod(winCls, @selector(hitTest:withEvent:), (IMP)diagHitTest, &origHitTest);
        swizzleMethod(winCls, @selector(canBecomeKeyWindow), (IMP)diagCanBecomeKey, &origCanKey);
    }
    if (iconCls) {
        swizzleMethod(iconCls, NSSelectorFromString(@"iconOnClick"), (IMP)diagClick, &origClick);
        swizzleMethod(iconCls, @selector(touchesBegan:withEvent:), (IMP)diagTouchB, &origTouchB);
        swizzleMethod(iconCls, @selector(touchesEnded:withEvent:), (IMP)diagTouchE, &origTouchE);
    }
    if (viewCls) {
        swizzleMethod(viewCls, NSSelectorFromString(@"drawInMTKView:"), (IMP)diagDraw, &origDraw);
    }
}

// ---------------------------------------------------------------- 剪贴板

static void publish(void) {
    NSString *text = nil;
    [gLock lock];
    text = [gLog copy];
    [gLock unlock];
    if (text.length > 14000) text = [text substringToIndex:14000];
    dispatch_async(dispatch_get_main_queue(), ^{
        UIPasteboard.generalPasteboard.string = text;
        NSLog(@"[QXTDIAG] 报告已写入剪贴板：%lu 字符", (unsigned long)text.length);
    });
}

// ---------------------------------------------------------------- 入口

__attribute__((constructor))
static void qxtdiag_init(void) {
    @autoreleasepool {
        gLog  = [NSMutableString string];
        gLock = [NSLock new];
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            L(@"========== QXT 运行时诊断 ==========");
            L(@"时间: %@", [NSDate date]);
            gBase = findQxtBase();
            L(@"靶场 base=%p", (void *)gBase);
            listObfuscatedClasses();
            installHooks();

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ snap(@"3s"); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ snap(@"8s"); publish(); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(16 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ snap(@"16s"); publish(); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ snap(@"30s"); publish(); });
        }
    });
}
