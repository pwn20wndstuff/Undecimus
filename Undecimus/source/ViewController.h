//
//  ViewController.h
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
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
@property (weak, nonatomic) IBOutlet UIView *mainView;
@property (weak, nonatomic) IBOutlet UIView *jailbreakView;
@property (weak, nonatomic) IBOutlet UILabel *swipeUpLabel;
@property (weak, nonatomic) IBOutlet UILabel *uOLabel;
@property (weak,nonatomic) IBOutlet UIView *settingsButtonView;
@property (weak, nonatomic) IBOutlet UIView *creditsButtonView;
@property (weak, nonatomic) IBOutlet UIView *settingsTransitionView;
@property (weak, nonatomic) IBOutlet UIView *creditsTransitionView;
@property (weak,nonatomic) IBOutlet UINavigationBar *settingsNavBar;
@property (weak,nonatomic) IBOutlet UINavigationBar *creditsNavBar;
@property (weak,nonatomic) IBOutlet UIVisualEffectView *initalErrorView;
@property (weak,nonatomic) IBOutlet UITextView *errorMessage;
@property (weak,nonatomic) IBOutlet UILabel *errorStatus;
@property (weak,nonatomic) IBOutlet UIProgressView *jailbreakProgressView;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *mainViewTopConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *mainViewBottomConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *settingsViewTopConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *settingsViewBottomConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *creditsViewTopConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *creditsViewBottomConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *jailbreakViewTopConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *jailbreakViewBottomConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *creditsHapticTouchBottomConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *settingssHapticTouchBottomConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *initialErrorViewTopConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *initialErrorViewBottomConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *initialErrorViewLabelTopConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *initialErrorViewButtonBottomConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *swipeUpLabelBottomConstraint;



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
void crashKernel(void);

void setPreference(NSString *key, id object);
NSString *hexFromInt(NSInteger val);

- (IBAction)tappedOnJailbreak:(id)sender;
+(ViewController*)sharedController;

@end

