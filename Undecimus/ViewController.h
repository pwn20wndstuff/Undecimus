//
//  ViewController.h
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>

#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define _assert(test) do \
    if (!(test)) { \
        fprintf(stderr, "__assert(%d:%s)@%s:%u[%s]\n", errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
        dispatch_semaphore_t semaphore; \
        semaphore = dispatch_semaphore_create(0); \
        dispatch_async(dispatch_get_main_queue(), ^{ \
            [[ViewController sharedController] dismissViewControllerAnimated:YES completion:nil]; \
            UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Error" message:[NSString stringWithFormat:@"Errno: %d\nTest: %s\nFilename: %s\nLine: %d\nFunction: %s", errno, #test, __FILENAME__, __LINE__, __FUNCTION__] preferredStyle:UIAlertControllerStyleAlert]; \
            UIAlertAction *OK = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) { \
                dispatch_semaphore_signal(semaphore); \
            }]; \
            [alertController addAction:OK]; \
            [alertController setPreferredAction:OK]; \
            [[[[[UIApplication sharedApplication] delegate] window] rootViewController] presentViewController:alertController animated:YES completion:nil];; \
        }); \
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER); \
        exit(1); \
    } \
while (false)

#define NOTICE(msg) do { \
    dispatch_async(dispatch_get_main_queue(), ^{ \
        [[ViewController sharedController] dismissViewControllerAnimated:YES completion:nil]; \
        UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Notice" message:@(msg) preferredStyle:UIAlertControllerStyleAlert]; \
        UIAlertAction *OK = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]; \
        [alertController addAction:OK]; \
        [alertController setPreferredAction:OK]; \
        [[[[[UIApplication sharedApplication] delegate] window] rootViewController] presentViewController:alertController animated:YES completion:nil];; \
    }); \
} while (false)

#define WAIT_NOTICE(msg) do { \
    dispatch_semaphore_t semaphore; \
    semaphore = dispatch_semaphore_create(0); \
    dispatch_async(dispatch_get_main_queue(), ^{ \
        [[ViewController sharedController] dismissViewControllerAnimated:YES completion:nil]; \
        UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Notice" message:@(msg) preferredStyle:UIAlertControllerStyleAlert]; \
        UIAlertAction *OK = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) { \
            dispatch_semaphore_signal(semaphore); \
        }]; \
        [alertController addAction:OK]; \
        [alertController setPreferredAction:OK]; \
        [[[[[UIApplication sharedApplication] delegate] window] rootViewController] presentViewController:alertController animated:YES completion:nil];; \
    }); \
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER); \
} while (false)

@interface ViewController : UIViewController
@property (weak, nonatomic) IBOutlet UIButton *goButton;

- (IBAction)tappedOnJailbreak:(id)sender;
+(ViewController*)sharedController;

@end

