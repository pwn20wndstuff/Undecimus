//
//  ViewController.h
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>
#include <common.h>

#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

static NSString *message = nil;
#define SETMESSAGE(msg) (message = msg)

#define _assert(test, message, fatal) do \
    if (!(test)) { \
        LOG("__assert(%d:%s)@%s:%u[%s]", errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
        if (message != nil) \
            showAlert(fatal ? @"Error (Fatal)" : @"Error (Nonfatal)", [NSString stringWithFormat:@"Errno: %d\nTest: %s\nFilename: %s\nLine: %d\nFunction: %s\nDescription: %@", errno, #test, __FILENAME__, __LINE__, __FUNCTION__, message], true, false); \
        else \
            showAlert(fatal ? @"Error (Fatal)" : @"Error (Nonfatal)", [NSString stringWithFormat:@"Errno: %d\nTest: %s\nFilename: %s\nLine: %d\nFunction: %s", errno, #test, __FILENAME__, __LINE__, __FUNCTION__], true, false); \
        if (fatal) \
            exit(EXIT_FAILURE); \
    } \
while (false)

#define NOTICE(msg, wait, destructive) showAlert(@"Notice", msg, wait, destructive)

static inline void showAlert(NSString *title, NSString *message, Boolean wait, Boolean destructive) {
    dispatch_semaphore_t semaphore;
    if (wait)
        semaphore = dispatch_semaphore_create(0);
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [[[[[UIApplication sharedApplication] delegate] window] rootViewController] dismissViewControllerAnimated:YES completion:nil];
        UIAlertController *alertController = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *OK = [UIAlertAction actionWithTitle:@"OK" style:destructive ? UIAlertActionStyleDestructive : UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            if (wait)
                dispatch_semaphore_signal(semaphore);
        }];
        [alertController addAction:OK];
        [alertController setPreferredAction:OK];
        [[[[[UIApplication sharedApplication] delegate] window] rootViewController] presentViewController:alertController animated:YES completion:nil];
    });
    if (wait)
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
}

@interface ViewController : UIViewController
@property (weak, nonatomic) IBOutlet UIButton *goButton;

double uptime(void);
int necp_die(void);

NSString *hexFromInt(NSInteger val);

- (IBAction)tappedOnJailbreak:(id)sender;
+(ViewController*)sharedController;

@end

