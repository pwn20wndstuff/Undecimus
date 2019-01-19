//
//  AppDelegate.h
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;
@property (strong, atomic) NSPipe *combinedPipe;
@property (assign) int orig_stderr;
@property (assign) int orig_stdout;

@end

