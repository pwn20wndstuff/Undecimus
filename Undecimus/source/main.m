//
//  main.m
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#include <dlfcn.h>
#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#include "utils.h"

int main(int argc, char * argv[]) {
    @autoreleasepool {
        enableLogging();
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}

