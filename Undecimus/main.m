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

int (*_system)(const char *) = 0;

int main(int argc, char * argv[]) {
    @autoreleasepool {
        _system = dlsym(RTLD_DEFAULT,"system");
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}

