//
//  AppDelegate.m
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import "AppDelegate.h"
#include "ViewController.h"

@interface AppDelegate ()

@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Override point for customization after application launch.
    [self SetUpShortcuts];
    return YES;
}

- (void)SetUpShortcuts {
    NSMutableArray *ShortcutItems = [[NSMutableArray alloc] init];
    UIApplicationShortcutIcon *JailbreakIcon = [UIApplicationShortcutIcon iconWithTemplateImageName:@"maintenance"];
    UIApplicationShortcutItem *JailbreakShortcut = [[UIApplicationShortcutItem alloc] initWithType:@"1" localizedTitle:@"Jailbreak" localizedSubtitle:nil icon:JailbreakIcon userInfo:nil];
    [ShortcutItems addObject:JailbreakShortcut];
    [[UIApplication sharedApplication] setShortcutItems:ShortcutItems];
}

- (void)application:(UIApplication *)application performActionForShortcutItem:(UIApplicationShortcutItem *)shortcutItem completionHandler:(void (^)(BOOL))completionHandler {
    switch ([[shortcutItem type] integerValue]) {
        case 1: {
            [[ViewController sharedController] performSelectorOnMainThread:@selector(tappedOnJailbreak:) withObject:nil waitUntilDone:YES];
            break;
        }
        default:
            break;
    }
}

- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary <UIApplicationOpenURLOptionsKey, id> *)options {
    if ([[url scheme] isEqualToString:@"jailbreak"]) {
        [[ViewController sharedController] performSelectorOnMainThread:@selector(tappedOnJailbreak:) withObject:nil waitUntilDone:YES];
        return YES;
    }
    return NO;
}

- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
}


- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}


- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
}


- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}


- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}


@end
