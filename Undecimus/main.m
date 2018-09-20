//
//  main.m
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#include <dlfcn.h>
#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#include "SettingsTableViewController.h"

#define LOG_FILE [[NSString stringWithFormat:@"%@/Documents/log_file.txt", NSHomeDirectory()] UTF8String]

int (*dsystem)(const char *) = 0;

int main(int argc, char * argv[]) {
    /*
    freopen(LOG_FILE, "a+", stderr);
    freopen(LOG_FILE, "a+", stdout);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    */
    @autoreleasepool {
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@K_TWEAK_INJECTION] == nil) {
            [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@K_TWEAK_INJECTION];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@K_LOAD_DAEMONS] == nil) {
            [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@K_LOAD_DAEMONS];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@K_DUMP_APTICKET] == nil) {
            [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@K_DUMP_APTICKET];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@K_REFRESH_ICON_CACHE] == nil) {
            [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@K_REFRESH_ICON_CACHE];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE] == nil) {
            [[NSUserDefaults standardUserDefaults] setObject:@"0x292dd10b56d87a3a" forKey:@K_BOOT_NONCE];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@K_EXPLOIT] == nil) {
            [[NSUserDefaults standardUserDefaults] setInteger:0 forKey:@K_EXPLOIT];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@K_DISABLE_AUTO_UPDATES] == nil) {
            [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@K_DISABLE_AUTO_UPDATES];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        dsystem = dlsym(RTLD_DEFAULT,"system");
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}

