// bypass.m —— 诊断用动态库（只在当前进程内存里做实验，不改动原文件）
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
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>
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
static int32_t GD(uintptr_t off) {
    if (!gBase) return 0;
    return *(int32_t *)(gBase + off);
}
static void SD(uintptr_t off, int32_t v) {
    if (!gBase) return;
    *(int32_t *)(gBase + off) = v;
}

static BOOL gForceShow = NO;

static void patchInsn(uintptr_t off, uint32_t expect, uint32_t newInsn) {
    if (!gBase) { L(@"改代码: base 为空"); return; }
    uintptr_t addr = gBase + off;
    uint32_t *p = (uint32_t *)addr;
    uint32_t old = *p;
    if (old == newInsn) { L(@"改代码[0x%lx]: 已是目标值", (unsigned long)off); return; }
    if (old != expect) {
        L(@"改代码[0x%lx]: 原值不符 old=0x%08x", (unsigned long)off, old);
        return;
    }
    uintptr_t page = addr & ~(uintptr_t)0xFFF;
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x1000, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        L(@"改代码[0x%lx]: 无写权限 权限=%d，跳过", (unsigned long)off, (int)kr);
        return;
    }
    *p = newInsn;
    sys_icache_invalidate((void *)addr, 4);
    L(@"改代码[0x%lx]: 0x%08x -> 0x%08x 权限=%d 读回=0x%08x",
      (unsigned long)off, old, newInsn, (int)kr, *p);
}

static BOOL looksLikeObject(id o) {
    uintptr_t p = (uintptr_t)(__bridge void *)o;
    return p > 0x100000000ULL && p < 0x00007FFFFFFFFFFFULL;
}

// 说明：不要再通过 _0xE4C8719B 去读面板「开关对象」。
// 实测该返回值不是可安全解引用的对象，读取会直接 EXC_BAD_ACCESS。

// ---------------------------------------------------------------- 描述对象

static NSString *descObj(id o) {
    if (!o) return @"nil";
    if (!looksLikeObject(o)) return [NSString stringWithFormat:@"(bad ptr %p)", (__bridge void *)o];
    @try {
        NSString *cn = NSStringFromClass(object_getClass(o));
        if ([o isKindOfClass:[UIImageView class]]) {
            UIImageView *iv = (UIImageView *)o;
            UIImage *img = iv.image;
            return [NSString stringWithFormat:
                    @"<%@ %p> f=%@ h=%d a=%.2f img=%@ 交互=%d",
                    cn, (__bridge void *)o, NSStringFromCGRect(iv.frame),
                    (int)iv.hidden, iv.alpha,
                    img ? NSStringFromCGSize(img.size) : @"nil",
                    (int)iv.userInteractionEnabled];
        }
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
    NSString *extra = @"";
    if ([v isKindOfClass:[UIImageView class]]) {
        UIImage *im = ((UIImageView *)v).image;
        extra = [NSString stringWithFormat:@" img=%@",
                 im ? NSStringFromCGSize(im.size) : @"nil"];
    }
    L(@"%@%@ f=%@ h=%d a=%.2f tag=%ld win=%@ sup=%@%@",
      pad, NSStringFromClass([v class]), NSStringFromCGRect(v.frame),
      (int)v.hidden, v.alpha, (long)v.tag,
      v.window ? NSStringFromClass([v.window class]) : @"nil",
      v.superview ? NSStringFromClass([v.superview class]) : @"nil", extra);
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

// ---------------------------------------------------------------- 镜像清单

static void listImages(void) {
    uint32_t n = _dyld_image_count();
    int shown = 0;
    for (uint32_t i = 0; i < n && shown < 80; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "/System/") || strstr(nm, "/usr/lib/")) continue;
        if (!strstr(nm, ".dylib") && !strstr(nm, ".framework")) continue;
        L(@"镜像[%u]: %s", i, nm);
        shown++;
    }
}

// ---------------------------------------------------------------- 类名清单

static void listObfuscatedClasses(void) {
    static BOOL listed = NO;
    if (listed) return;
    listed = YES;
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

// ---------------------------------------------------------------- 方法清单

static void dumpMethods(Class c, const char *label) {
    if (!c) { L(@"方法清单 %s: （类不存在）", label); return; }
    Class sup = class_getSuperclass(c);
    L(@"方法 %s = %@  父类=%@", label, NSStringFromClass(c),
      sup ? NSStringFromClass(sup) : @"nil");
    unsigned int n = 0;
    Method *ms = class_copyMethodList(c, &n);
    NSMutableArray *im = [NSMutableArray array];
    for (unsigned int i = 0; i < n; i++) {
        [im addObject:NSStringFromSelector(method_getName(ms[i]))];
    }
    free(ms);
    NSString *imj = [im componentsJoinedByString:@" "];
    if (imj.length > 3000) imj = [imj substringToIndex:3000];
    L(@"  实例方法(%u): %@", n, imj);
    unsigned int cn = 0;
    Method *cms = class_copyMethodList(object_getClass(c), &cn);
    NSMutableArray *cm = [NSMutableArray array];
    for (unsigned int i = 0; i < cn; i++) {
        [cm addObject:NSStringFromSelector(method_getName(cms[i]))];
    }
    free(cms);
    NSString *cmj = [cm componentsJoinedByString:@" "];
    if (cmj.length > 2000) cmj = [cmj substringToIndex:2000];
    L(@"  类方法(%u): %@", cn, cmj);
}

// ---------------------------------------------------------------- 图标定位

static void placeIconTopRight(NSString *why) {
    uintptr_t p = G(0x18581E0);
    if (!p) { L(@"定位[%@]: 图标不存在", why); return; }
    id o = (__bridge id)(void *)p;
    if (![o isKindOfClass:[UIView class]]) { L(@"定位[%@]: 不是视图", why); return; }
    UIView *v = (UIView *)o;
    UIView *host = v.superview;
    CGFloat W = 1080;
    if (host) W = host.bounds.size.width;
    else if (v.window) W = v.window.bounds.size.width;
    CGRect old = v.frame;
    CGFloat x = W - old.size.width - 20;
    if (x < 0) x = W - old.size.width;
    v.frame = CGRectMake(x, 58, old.size.width, old.size.height);
    L(@"定位[%@]: 原=%@ 新=%@ 宿主=%@",
      why, NSStringFromCGRect(old), NSStringFromCGRect(v.frame),
      host ? NSStringFromClass([host class]) : @"nil");
}

static void logPanelState(NSString *tag) {
    uintptr_t p = G(0x18581D8);
    if (!p) { L(@"面板[%@]: 不存在", tag); return; }
    id o = (__bridge id)(void *)p;
    if (![o isKindOfClass:[UIView class]]) { L(@"面板[%@]: 不是视图", tag); return; }
    UIView *v = (UIView *)o;
    L(@"面板[%@]: hidden=%d alpha=%.2f 窗口=%@ 开关F34=%u",
      tag, (int)v.hidden, v.alpha,
      v.window ? NSStringFromClass([v.window class]) : @"nil",
      (unsigned)GB(0x1851F34));
}

static void makeIconVisible(void) {
    uintptr_t p = G(0x18581E0);
    if (!p) { L(@"图标配色: 图标不存在"); return; }
    id o = (__bridge id)(void *)p;
    if (![o isKindOfClass:[UIView class]]) { L(@"图标配色: 不是视图"); return; }
    UIView *icon = (UIView *)o;
    UIImageView *iv = nil;
    for (UIView *sv in icon.subviews) {
        if ([sv isKindOfClass:[UIImageView class]]) { iv = (UIImageView *)sv; break; }
    }
    if (!iv) { L(@"图标配色: 没有图片子视图"); return; }
    if (iv.image) {
        L(@"图标配色: 已有图片 %@", NSStringFromCGSize(iv.image.size));
        return;
    }
    UIGraphicsImageRenderer *r =
        [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(45, 45)];
    UIImage *img = [r imageWithActions:^(UIGraphicsImageRendererContext *ctx) {
        [[UIColor redColor] setFill];
        [ctx fillRect:CGRectMake(0, 0, 45, 45)];
    }];
    iv.image = img;
    iv.hidden = NO;
    iv.alpha = 1.0;
    icon.hidden = NO;
    icon.alpha = 1.0;
    L(@"图标配色: 已填入红色占位图，图标hidden=%d alpha=%.2f", (int)icon.hidden, icon.alpha);
}

static void forcePanelVisible(NSString *tag) {
    uintptr_t p = G(0x18581D8);
    if (!p) { L(@"强制显示[%@]: 面板不存在", tag); return; }
    id o = (__bridge id)(void *)p;
    if (![o isKindOfClass:[UIView class]]) { L(@"强制显示[%@]: 不是视图", tag); return; }
    UIView *v = (UIView *)o;
    L(@"强制显示[%@]: hidden %d -> 0", tag, (int)v.hidden);
    v.hidden = NO;
    v.alpha = 1.0;
    logPanelState(tag);
}

// 静默把当前日志写进剪贴板（不弹窗）。用于每个阶段结束时，
// 这样即使 App 崩在后面某一步，崩溃前的现场也已经留在剪贴板里。
static void saveClip(void) {
    NSString *text = nil;
    [gLock lock];
    text = [gLog copy];
    [gLock unlock];
    if (text.length > 120000) text = [text substringToIndex:120000];
    UIPasteboard.generalPasteboard.string = text;
}

// ---------------------------------------------------------------- 快照

static void snap(NSString *tag) {
    @autoreleasepool {
        L(@"---------- 快照 %@ ----------", tag);
        L(@"base=%p 宿主=%@", (void *)gBase, NSBundle.mainBundle.bundleIdentifier);
        L(@"屏幕=%@ scale=%.1f", NSStringFromCGRect(UIScreen.mainScreen.bounds),
          (double)UIScreen.mainScreen.scale);

        L(@"全局 container(0x18581E0)=%@", descObj((__bridge id)(void *)G(0x18581E0)));
        L(@"  祖先链: %@", parentChain((__bridge id)(void *)G(0x18581E0)));
        L(@"全局 view(0x18581D8)=%@",      descObj((__bridge id)(void *)G(0x18581D8)));
        L(@"  祖先链: %@", parentChain((__bridge id)(void *)G(0x18581D8)));
        L(@"指针 0x1851CA0=%p 0x1851CA8=%p 0x1851CB0=%p 0x1852128=%p",
          (void *)G(0x1851CA0), (void *)G(0x1851CA8),
          (void *)G(0x1851CB0), (void *)G(0x1852128));
        L(@"开关 0x1851CE0[0]=%u  0x1851F34=%u  0x1851CA0=%p  0x1851CA8=%p  0x1851CB0=%p",
          (unsigned)GB(0x1851CE0), (unsigned)GB(0x1851F34),
          (void *)G(0x1851CA0), (void *)G(0x1851CA8), (void *)G(0x1851CB0));
        L(@"绘制门槛 0x185ACB8=%d", GD(0x185ACB8));

        NSArray<UIWindow *> *wins = allWindows();
        UIWindow *keyWin = nil;
        for (UIWindow *w in wins) { if (w.isKeyWindow) { keyWin = w; break; } }
        L(@"窗口数=%lu keyWindow=%@", (unsigned long)wins.count, descObj(keyWin));
        if (keyWin) L(@"  keyWindow safeArea=%@", NSStringFromUIEdgeInsets(keyWin.safeAreaInsets));

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

static IMP origSetHidden = NULL;

static void diagSetHidden(id self, SEL _cmd, BOOL hidden) {
    if (hidden) {
        Class pc = objc_getClass("_0x1E6B7A93");
        if (pc && [self isKindOfClass:pc]) {
            static int cnt = 0;
            cnt++;
            if (cnt <= 6) {
                NSArray *bt = [NSThread callStackSymbols];
                L(@"[隐藏面板#%d] 调用栈: %@", cnt, [bt componentsJoinedByString:@" | "]);
            }
        }
    }
    if (origSetHidden) ((void (*)(id, SEL, BOOL))origSetHidden)(self, _cmd, hidden);
}

static void diagDraw(id self, SEL _cmd, id view) {
    int n = __sync_add_and_fetch(&gDrawCount, 1);
    if (n == 1 || (n % 120) == 0) L(@"[drawInMTKView#%d] %@", n, NSStringFromClass([self class]));
    if (gForceShow) SD(0x185ACB8, -1);
    if (origDraw) ((void (*)(id, SEL, id))origDraw)(self, _cmd, view);
    if (gForceShow && [self isKindOfClass:[UIView class]]) {
        UIView *v = (UIView *)self;
        if (v.hidden || v.alpha < 0.99) {
            static int fixedCount = 0;
            fixedCount++;
            if (fixedCount <= 3) {
                L(@"[实验] 绘制后恢复显示(第%d次)", fixedCount);
            }
            v.hidden = NO;
            v.alpha = 1.0;
        }
    }
}

static void installHooks(void) {
    static BOOL hooked = NO;
    if (hooked) return;
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
    swizzleMethod([UIView class], @selector(setHidden:), (IMP)diagSetHidden, &origSetHidden);

    dumpMethods(winCls, "窗口类");
    dumpMethods(iconCls, "图标类");
    dumpMethods(viewCls, "渲染视图类");

    if (winCls || iconCls || viewCls) hooked = YES;
}

// ---------------------------------------------------------------- 变化监视

static void scheduleWatch(void);

static void watchTick(void) {
    if (!gBase) {
        gBase = findQxtBase();
        if (gBase) {
            L(@"watch: 延迟拿到 base=%p", (void *)gBase);
            listObfuscatedClasses();
            installHooks();
        }
        return;
    }

    static BOOL firstTick = YES;
    static uint8_t  lf34, lce0;
    static uintptr_t lc0, lc8, lb0, le0, ld8, lw2128;
    static int lwin;

    uint8_t  f34  = GB(0x1851F34);
    uint8_t  ce0  = GB(0x1851CE0);
    uintptr_t c0  = G(0x1851CA0);
    uintptr_t c8  = G(0x1851CA8);
    uintptr_t b0  = G(0x1851CB0);
    uintptr_t e0  = G(0x18581E0);
    uintptr_t d8  = G(0x18581D8);
    uintptr_t w2128 = G(0x1852128);
    int wc = (int)allWindows().count;

    if (firstTick) {
        firstTick = NO;
        lf34 = f34; lce0 = ce0; lc0 = c0; lc8 = c8; lb0 = b0;
        le0 = e0; ld8 = d8; lw2128 = w2128; lwin = wc;
        L(@"[初值] 0x1851F34=%u 0x1851CE0=%u 0x1851CA0=%p 0x1851CA8=%p 0x1851CB0=%p",
          (unsigned)f34, (unsigned)ce0, (void *)c0, (void *)c8, (void *)b0);
        L(@"[初值] container=%p view=%p win2128=%p 窗口数=%d",
          (void *)e0, (void *)d8, (void *)w2128, wc);
        return;
    }

    if (f34 != lf34) { L(@"[变化] 0x1851F34: %u -> %u", (unsigned)lf34, (unsigned)f34); lf34 = f34; }
    if (ce0 != lce0) { L(@"[变化] 0x1851CE0: %u -> %u", (unsigned)lce0, (unsigned)ce0); lce0 = ce0; }
    if (c0  != lc0)  { L(@"[变化] 0x1851CA0: %p -> %p", (void *)lc0, (void *)c0); lc0 = c0; }
    if (c8  != lc8)  { L(@"[变化] 0x1851CA8: %p -> %p", (void *)lc8, (void *)c8); lc8 = c8; }
    if (b0  != lb0)  { L(@"[变化] 0x1851CB0: %p -> %p", (void *)lb0, (void *)b0); lb0 = b0; }
    if (e0  != le0)  { L(@"[变化] container(0x18581E0): %p -> %p", (void *)le0, (void *)e0); le0 = e0; }
    if (d8  != ld8)  { L(@"[变化] view(0x18581D8): %p -> %p", (void *)ld8, (void *)d8); ld8 = d8; }
    if (w2128 != lw2128) { L(@"[变化] win(0x1852128): %p -> %p", (void *)lw2128, (void *)w2128); lw2128 = w2128; }
    if (wc != lwin) { L(@"[变化] 窗口数: %d -> %d", lwin, wc); lwin = wc; }

    if (gForceShow) {
        int32_t gate = GD(0x185ACB8);
        if (gate != -1) {
            SD(0x185ACB8, -1);
            L(@"[实验] 绘制门槛 0x185ACB8: %d -> -1", gate);
        }
        uintptr_t pv = G(0x18581D8);
        if (pv) {
            id po = (__bridge id)(void *)pv;
            if ([po isKindOfClass:[UIView class]]) {
                UIView *v = (UIView *)po;
                if (v.hidden || v.alpha < 0.99) {
                    L(@"[实验] 面板被隐藏(hidden=%d alpha=%.2f)，已重新显示", (int)v.hidden, v.alpha);
                    v.hidden = NO;
                    v.alpha = 1.0;
                }
            }
        }
    }
}

static void scheduleWatch(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        watchTick();
        scheduleWatch();
    });
}

// ---------------------------------------------------------------- 剪贴板

static void publish(void) {
    NSString *text = nil;
    [gLock lock];
    text = [gLog copy];
    [gLock unlock];
    if (text.length > 120000) text = [text substringToIndex:120000];
    dispatch_async(dispatch_get_main_queue(), ^{
        UIPasteboard.generalPasteboard.string = text;
        NSLog(@"[QXTDIAG] 报告已写入剪贴板：%lu 字符", (unsigned long)text.length);
        static BOOL notified = NO;
        if (notified) return;
        notified = YES;
        UIWindow *kw = nil;
        NSArray<UIWindow *> *ws = allWindows();
        for (UIWindow *w in ws) { if (w.isKeyWindow) { kw = w; break; } }
        if (!kw) for (UIWindow *w in ws) {
            if (!w.hidden && w.windowLevel < 100) { kw = w; break; }
        }
        UIViewController *vc = kw.rootViewController;
        if (!vc) return;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        UIAlertController *ac = [UIAlertController
            alertControllerWithTitle:@"诊断完成"
            message:[NSString stringWithFormat:@"报告已复制到剪贴板（%lu 字符），可直接粘贴发送。",
                     (unsigned long)text.length]
            preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"好"
                                               style:UIAlertActionStyleDefault
                                             handler:nil]];
        [vc presentViewController:ac animated:YES completion:nil];
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
            listImages();
            listObfuscatedClasses();
            installHooks();
            saveClip();

            scheduleWatch();

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ snap(@"3s"); saveClip(); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ placeIconTopRight(@"3.5s"); saveClip(); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ makeIconVisible(); saveClip(); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                // 不再自动点图标：实测在卡密未通过时点它会让靶场直接崩。
                L(@"5s: 图标保持可见，未自动点击");
                logPanelState(@"5s");
                saveClip();
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                L(@"[实验] 修改两处面板显示逻辑");
                patchInsn(0xAE4A0, 0x52800022, 0x52800002);
                patchInsn(0xCD35C0, 0x54002B41, 0xD503201F);
                saveClip();
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ forcePanelVisible(@"7s"); saveClip(); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                L(@"指针(4.5s): 图标=%p 面板=%p 窗口=%p",
                  (void *)G(0x18581E0), (void *)G(0x18581D8), (void *)G(0x1852128));
                saveClip();
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                gForceShow = YES;
                L(@"[实验] 开始持续强制显示面板并打开绘制门槛");
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                L(@"指针复查(10s): 面板=%p 图标=%p 窗口=%p",
                  (void *)G(0x18581D8), (void *)G(0x18581E0), (void *)G(0x1852128));
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ placeIconTopRight(@"6s"); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ snap(@"8s"); publish(); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(16 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ snap(@"16s"); publish(); });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ snap(@"30s"); publish(); });
        }
    });
}
