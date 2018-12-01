//
//  ViewController.h
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>

#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

static const char *message = NULL;
#define SETMESSAGE(msg) (message = msg)

#define _assert(test, message) do \
    if (!(test)) { \
        fprintf(stderr, "__assert(%d:%s)@%s:%u[%s]\n", errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
        if (message) \
            showAlert(@"Error", [NSString stringWithFormat:@"Errno: %d\nTest: %s\nFilename: %s\nLine: %d\nFunction: %s\nDescription: %s", errno, #test, __FILENAME__, __LINE__, __FUNCTION__, message], 1, 0); \
        else \
            showAlert(@"Error", [NSString stringWithFormat:@"Errno: %d\nTest: %s\nFilename: %s\nLine: %d\nFunction: %s", errno, #test, __FILENAME__, __LINE__, __FUNCTION__], 1, 0); \
        exit(1); \
    } \
while (false)

#define NOTICE(msg, wait, destructive) showAlert(@"Notice", @(msg), wait, destructive)

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

enum {
    EMPTY_LIST = 0,
    MULTI_PATH = 1,
    ASYNC_WAKE = 2,
    DEJA_XNU = 3,
    NECP = 4,
};

double uptime(void);
int isJailbroken(void);
int isSupportedByExploit(int exploit);
int hasMPTCP(void);
int selectJailbreakExploit(void);
int isSupportedByJailbreak(void);
int selectRestartExploit(void);
int isSupportedByRestart(void);
int selectRespringExploit(void);
int isSupportedByRespring(void);

void setPreference(NSString *key, id object);
NSString *hexFromInt(NSInteger val);

- (IBAction)tappedOnJailbreak:(id)sender;
+(ViewController*)sharedController;

@end

