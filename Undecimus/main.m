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
        dsystem = dlsym(RTLD_DEFAULT,"system");
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}

