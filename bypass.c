#include <stdio.h>
#include <dlfcn.h>
#include <objc/runtime.h>

typedef void (*jh_install_memory_hook_t)(void);
typedef void (*jh_enable_fullview_t)(int);
typedef void (*jh_activate_camera_patch_t)(void);

__attribute__((constructor))
void init_bypass(void) {
    void* handle = dlopen("@rpath/bsphp.framework/bsphp", RTLD_NOW);
    if(!handle){
        printf("[bypass] dlopen fail\n");
        return;
    }

    jh_install_memory_hook_t hook_mem = dlsym(handle, "_jh_install_memory_hook");
    jh_enable_fullview_t hook_full = dlsym(handle, "_jh_enable_fullview");
    jh_activate_camera_patch_t hook_cam = dlsym(handle, "_jh_activate_camera_patch");

    if(hook_mem) hook_mem();
    if(hook_full) hook_full(1);
    if(hook_cam) hook_cam();

    printf("[bypass] 全部功能已调用\n");
    dlclose(handle);
}
