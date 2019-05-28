//
//  JailbreakViewController.h
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <UIProgressHUD.h>
#import <AudioToolbox/AudioToolbox.h>
#import "common.h"

#define _assert(test, message, fatal) do \
    if (!(test)) { \
        int saved_errno = errno; \
        LOG("_assert(%d:%s)@%s:%u[%s]", saved_errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
        if (message != nil) \
            showAlert(fatal ? @"Error (Fatal)" : @"Error (Nonfatal)", [NSString stringWithFormat:@"Errno: %d\nTest: %s\nFilename: %s\nLine: %d\nFunction: %s\nDescription: %@", saved_errno, #test, __FILENAME__, __LINE__, __FUNCTION__, message], true, false); \
        else \
            showAlert(fatal ? @"Error (Fatal)" : @"Error (Nonfatal)", [NSString stringWithFormat:@"Errno: %d\nTest: %s\nFilename: %s\nLine: %d\nFunction: %s", saved_errno, #test, __FILENAME__, __LINE__, __FUNCTION__], true, false); \
        if (fatal) { \
            if ([[JailbreakViewController sharedController] canExit]) {\
                exit(EXIT_FAILURE); \
            } else { \
                return; \
            } \
        errno = saved_errno; \
        } \
    } \
while (false)

#define notice(msg, wait, destructive) showAlert(@"Notice", msg, wait, destructive)

#define status(msg, btnenbld, tbenbld) do { \
    LOG("Status: %@", msg); \
    dispatch_async(dispatch_get_main_queue(), ^{ \
        [UIView performWithoutAnimation:^{ \
            [[[JailbreakViewController sharedController] goButton] setEnabled:btnenbld]; \
            [[[[JailbreakViewController sharedController] tabBarController] tabBar] setUserInteractionEnabled:tbenbld]; \
            [[[JailbreakViewController sharedController] goButton] setTitle:msg forState: btnenbld ? UIControlStateNormal : UIControlStateDisabled]; \
            [[[JailbreakViewController sharedController] goButton] layoutIfNeeded]; \
        }]; \
    }); \
} while (false)

@interface JailbreakViewController : UIViewController
@property (weak, nonatomic) IBOutlet UIButton *goButton;
@property (weak, nonatomic) IBOutlet UITextView *outputView;
@property (readonly) JailbreakViewController *sharedController;
@property (weak, nonatomic) IBOutlet NSLayoutConstraint *goButtonSpacing;
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
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *swipeUpLabelBottomConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *undecimusLogoCentreConstraint;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *jailbreakButtonLeftSpacing;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *jailbreakButttonRightSpacing;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *consoleLogLeftSpacing;
@property (weak,nonatomic) IBOutlet NSLayoutConstraint *consoleLogRightSpacing;
@property (weak,nonatomic) IBOutlet UILabel *uncoverDescriptionLabel;
@property (weak,nonatomic) IBOutlet UILabel *byLabel;
@property (weak,nonatomic) IBOutlet UILabel *firstAndLabel;
@property (weak,nonatomic) IBOutlet UILabel *uiByLabel;
@property (weak,nonatomic) IBOutlet UILabel *secondAndLabel;
@property (weak,nonatomic) IBOutlet UILabel *thirdAndLabel;
@property (weak,nonatomic) IBOutlet UILabel *jailbreakViewUOLabel;
@property (weak,nonatomic) IBOutlet UIActivityIndicatorView *jailbreakActivityIndicator;


@property (assign) BOOL canExit;

double uptime(void);

NSString *hexFromInt(NSInteger val);

- (IBAction)tappedOnJailbreak:(id)sender;
+(JailbreakViewController*)sharedController;
- (void)appendTextToOutput:(NSString*)text;
- (void)updateStatus;

@end

static inline UIProgressHUD *addProgressHUD() {
    __block UIProgressHUD *hud = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_main_queue(), ^{
        hud = [[UIProgressHUD alloc] init];
        [hud setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
        UIView *view = [[JailbreakViewController sharedController] view];
        [hud showInView:view];
        dispatch_semaphore_signal(semaphore);
    });
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return hud;
}

static inline void removeProgressHUD(UIProgressHUD *hud) {
    if (hud == nil) {
        return;
    }
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_main_queue(), ^{
        [hud hide];
        [hud done];
        dispatch_semaphore_signal(semaphore);
    });
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
}

static inline void updateProgressHUD(UIProgressHUD *hud, NSString *msg) {
    if (hud == nil) {
        return;
    }
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_main_queue(), ^{
        [hud setText:msg];
        dispatch_semaphore_signal(semaphore);
    });
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
}

static inline void showAlertWithCancel(NSString *title, NSString *message, Boolean wait, Boolean destructive, NSString *cancel) {
    dispatch_semaphore_t semaphore;
    if (wait)
        semaphore = dispatch_semaphore_create(0);
    
    dispatch_async(dispatch_get_main_queue(), ^{
        JailbreakViewController *controller = [JailbreakViewController sharedController];
        [controller dismissViewControllerAnimated:YES completion:nil];
        UIAlertController *alertController = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *OK = [UIAlertAction actionWithTitle:@"OK" style:destructive ? UIAlertActionStyleDestructive : UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            controller.canExit = YES;
            if (wait)
                dispatch_semaphore_signal(semaphore);
        }];
        [alertController addAction:OK];
        [alertController setPreferredAction:OK];
        if (cancel) {
            UIAlertAction *abort = [UIAlertAction actionWithTitle:cancel style:destructive ? UIAlertActionStyleDestructive : UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                controller.canExit = NO;
                if (wait)
                    dispatch_semaphore_signal(semaphore);
            }];
            [alertController addAction:abort];
            [alertController setPreferredAction:abort];
        }
        [controller presentViewController:alertController animated:YES completion:nil];
    });
    if (wait)
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
}

static inline void showAlert(NSString *title, NSString *message, Boolean wait, Boolean destructive) {
    __block bool outputIsHidden;
    dispatch_block_t checkOutput = ^{
        outputIsHidden = [[[JailbreakViewController sharedController] outputView] isHidden];
    };

    if ([[NSThread currentThread] isMainThread]) {
        checkOutput();
    } else {
        dispatch_sync(dispatch_get_main_queue(), checkOutput);
    }
    showAlertWithCancel(title, message, wait, destructive, outputIsHidden?nil:@"View Log");
}
