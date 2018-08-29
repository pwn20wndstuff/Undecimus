//
//  main.m
//  Rollectra
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#include <dlfcn.h>
#import <UIKit/UIKit.h>
#import "AppDelegate.h"

/* Set platform binary flag */
#define FLAG_PLATFORMIZE (1 << 1)

void patch_setuidandplatformize() {
    void* handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);
    if (!handle) return;
    
    // Reset errors
    dlerror();
    
    typedef void (*fix_setuid_prt_t)(pid_t pid);
    fix_setuid_prt_t setuidptr = (fix_setuid_prt_t)dlsym(handle, "jb_oneshot_fix_setuid_now");
    
    typedef void (*fix_entitle_prt_t)(pid_t pid, uint32_t what);
    fix_entitle_prt_t entitleptr = (fix_entitle_prt_t)dlsym(handle, "jb_oneshot_entitle_now");
    
    setuidptr(getpid());
    
    setuid(0);
    
    const char *dlsym_error = dlerror();
    if (dlsym_error) {
        return;
    }
    
    entitleptr(getpid(), FLAG_PLATFORMIZE);
}

int main(int argc, char * argv[]) {
#ifdef WANT_CYDIA
    patch_setuidandplatformize();
    setuid(0);
#endif    /* !WANT_CYDIA */
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
