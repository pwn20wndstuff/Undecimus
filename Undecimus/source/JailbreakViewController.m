//
//  JailbreakViewController.m
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#include <common.h>
#include <sys/time.h>
#import "JailbreakViewController.h"
#import "SettingsTableViewController.h"
#import "CreditsTableViewController.h"
#include "jailbreak.h"
#include "prefs.h"
#include "utils.h"

@interface JailbreakViewController ()

@end

@implementation JailbreakViewController
static JailbreakViewController *sharedController = nil;
static NSMutableString *output = nil;
static NSString *bundledResources = nil;
static BOOL notchedDevice = NO;
static CGFloat movementConstant = 0;
static BOOL up = NO;
static NSTimer *swipeUpTimer = nil;
static BOOL showSwipeUpGesture = NO;
static CGFloat initialYLocation = 0;
static CGFloat moveOnValidNumber = 0;
static CGFloat largestLengthScreen = 0;

- (IBAction)tappedOnJailbreak:(id)sender
{
    status(localize(@"Jailbreak"), false, false);
    void (^const block)(void) = ^(void) {
        _assert(bundledResources != nil, localize(@"Bundled Resources version missing."), true);
        if (!jailbreakSupported()) {
            status(localize(@"Unsupported"), false, true);
            return;
        }
        jailbreak();
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (void)updateStatus {
    prefs_t *prefs = copy_prefs();
    if (!jailbreakSupported()) {
        status(localize(@"Unsupported"), false, true);
        self.swipeUpLabel.text = localize(@"Unsupported Device");
    } else if (prefs->restore_rootfs) {
        status(localize(@"Restore RootFS"), true, true);
        self.swipeUpLabel.text = localize(@"Swipe up to restore root filesystem");
    } else if (jailbreakEnabled()) {
        status(localize(@"Re-Jailbreak"), true, true);
        self.swipeUpLabel.text = localize(@"Swipe up to re-jailbreak");
    } else {
        status(localize(@"Jailbreak"), true, true);
        self.swipeUpLabel.text = localize(@"Swipe up to jailbreak");
    }
    release_prefs(&prefs);
}

-(void)darkMode {
    self.mainView.backgroundColor = [UIColor.blackColor colorWithAlphaComponent:0.9];
    self.settingsTransitionView.backgroundColor = [UIColor.blackColor colorWithAlphaComponent:0.9];
    self.creditsTransitionView.backgroundColor = [UIColor.blackColor colorWithAlphaComponent:0.9];
    self.jailbreakView.backgroundColor = [UIColor.blackColor colorWithAlphaComponent:0.9];
    self.uOLabel.textColor = UIColor.whiteColor;
    self.swipeUpLabel.textColor = UIColor.whiteColor;
    
    [self.settingsNavBar setTintColor:[UIColor whiteColor]];
    [self.settingsNavBar setLargeTitleTextAttributes:@{NSForegroundColorAttributeName : [UIColor whiteColor]}];
    [self.creditsNavBar setTintColor:[UIColor whiteColor]];
    [self.creditsNavBar setLargeTitleTextAttributes:@{NSForegroundColorAttributeName : [UIColor whiteColor]}];
    
    self.uncoverDescriptionLabel.textColor = UIColor.whiteColor;
    self.byLabel.textColor = UIColor.whiteColor;
    self.firstAndLabel.textColor = UIColor.whiteColor;
    self.uiByLabel.textColor = UIColor.whiteColor;
    self.secondAndLabel.textColor = UIColor.whiteColor;
    self.thirdAndLabel.textColor = UIColor.whiteColor;
    self.jailbreakViewUOLabel.textColor = UIColor.whiteColor;
    self.jailbreakActivityIndicator.activityIndicatorViewStyle = UIActivityIndicatorViewStyleWhite;
    self.jailbreakProgressView.progressTintColor = UIColor.whiteColor;
}



- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    
    [self updateStatus];
    
    if ((UIScreen.mainScreen.bounds.size.width < UIScreen.mainScreen.bounds.size.height) && (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad)) {
        movementConstant = UIScreen.mainScreen.bounds.size.height;
        largestLengthScreen = UIScreen.mainScreen.bounds.size.height;
    } else {
        movementConstant = UIScreen.mainScreen.bounds.size.width;
        largestLengthScreen = UIScreen.mainScreen.bounds.size.width;
    }
    
    self.settingsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, movementConstant, 0);
    self.creditsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, -movementConstant, 0);
    
    if (@available(iOS 11.0, *)) {
        UIWindow *mainWindow = [[[UIApplication sharedApplication] delegate] window];
        
        if (mainWindow.safeAreaInsets.top > 24.0) {
            notchedDevice = YES;
            self.swipeUpLabelBottomConstraint.constant = self.swipeUpLabelBottomConstraint.constant + 44;
            self.mainViewTopConstraint.constant = -44;
            self.mainViewBottomConstraint.constant = -44;
            self.settingsViewTopConstraint.constant = 44;
            self.settingsViewBottomConstraint.constant = -44;
            self.creditsViewTopConstraint.constant = 44;
            self.creditsViewBottomConstraint.constant = -44;
        
            self.jailbreakViewTopConstraint.constant = -44;
            self.jailbreakViewBottomConstraint.constant = 44;
            self.creditsHapticTouchBottomConstraint.constant = self.creditsHapticTouchBottomConstraint.constant + 44;
            self.settingssHapticTouchBottomConstraint.constant = self.settingssHapticTouchBottomConstraint.constant + 44;
        }
    }
}

- (void)swipeUpAnimation:(NSTimer *)timer {
    if (up) {
        [UIView animateWithDuration:1.6 delay:0.4 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            self.swipeUpLabel.alpha = 0;
        } completion:nil];
        
        [UIView animateWithDuration:0.1 delay:1.6 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            self.swipeUpLabel.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, 0);
        } completion:nil];
    } else {
        [UIView animateWithDuration:1.6 delay:0.4 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            self.swipeUpLabel.alpha = 1;
            self.swipeUpLabel.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, -50);
        } completion:nil];
    }
    up = !up;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.canExit = YES;
    
    if (UIScreen.mainScreen.bounds.size.height == 568) {
        self.goButton.titleLabel.font = [UIFont systemFontOfSize:13];
    }

    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        self.jailbreakButtonLeftSpacing.constant = 220;
        self.jailbreakButttonRightSpacing.constant = 220;
    }
    
    self.creditsTransitionView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.25, 0.25);
    self.settingsTransitionView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.25, 0.25);
    self.settingsButtonView.layer.cornerRadius = 30;
    self.settingsButtonView.clipsToBounds = YES;
    self.jailbreakView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 3, 3);
    self.jailbreakView.alpha = 0;
    self.creditsButtonView.layer.cornerRadius = 30;
    self.creditsButtonView.clipsToBounds = YES;
    self.outputView.layer.cornerRadius = 10;
    self.outputView.clipsToBounds = YES;
    
    
    [self.settingsNavBar setBackgroundImage:[UIImage new] forBarMetrics:UIBarMetricsDefault];
    [self.settingsNavBar setShadowImage:[UIImage new]];
    
    [self.creditsNavBar setBackgroundImage:[UIImage new] forBarMetrics:UIBarMetricsDefault];
    [self.creditsNavBar setShadowImage:[UIImage new]];
    self.swipeUpLabel.alpha = 0;
    
    prefs_t *prefs = copy_prefs();
    
    if (prefs->hide_log_window) {
        self.outputView.hidden = YES;
        self.outputView = nil;
        self.goButton.hidden = YES;
        showSwipeUpGesture = YES;
        swipeUpTimer = [NSTimer scheduledTimerWithTimeInterval:1.6 target:self selector:@selector(swipeUpAnimation:) userInfo:nil repeats:YES];
        self.undecimusLogoCentreConstraint.constant = -70;
    }
    
    if (prefs->dark_mode) {
        [self darkMode];
    }
    
    release_prefs(&prefs);
    
    sharedController = self;
    bundledResources = bundledResourcesVersion();
    LOG("unc0ver Version: %@", appVersion());
    printOSDetails();
    LOG("Bundled Resources Version: %@", bundledResources);
    if (bundledResources == nil) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
            showAlert(localize(@"Error"), localize(@"Bundled Resources version is missing. This build is invalid."), false, false);
        });
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    prefs_t *prefs = copy_prefs();
    
    if (prefs->dark_mode) {
        return UIStatusBarStyleLightContent;
    } else {
        return UIStatusBarStyleDefault;
    }
}

-(void)hapticTouchFeedback {
    if ([[[UIDevice currentDevice] valueForKey:@"_feedbackSupportLevel"] intValue] == 2) {
        UIImpactFeedbackGenerator *generator = [[UIImpactFeedbackGenerator alloc] initWithStyle: UIImpactFeedbackStyleLight];
        [generator prepare];
        [generator impactOccurred];
    } else {
        AudioServicesPlaySystemSound(1519);
    }
}

-(void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *touch = [touches anyObject];
    CGPoint secondaryLocation = [touch locationInView:self.mainView];
    CGFloat yLocation = secondaryLocation.y;
    
    if (touch.view == self.mainView && showSwipeUpGesture && jailbreakSupported()) {
        initialYLocation = yLocation;
    } else if (touch.view == self.creditsButtonView) {
        [self touchBeganHapticTouchButtons:self.creditsButtonView];
        self.creditsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, -movementConstant, 0);
    } else if (touch.view == self.settingsButtonView) {
        [self touchBeganHapticTouchButtons:self.settingsButtonView];
        self.settingsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, movementConstant, 0);
    }
}

-(void)touchBeganHapticTouchButtons:(UIView *)buttonView {
    [UIView animateWithDuration:0.3 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        buttonView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1.5, 1.5);
    } completion:nil];
    [self hapticTouchFeedback];
    movementConstant = UIScreen.mainScreen.bounds.size.width;
}

-(void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *touch = [touches anyObject];
    CGPoint secondaryLocation = [touch locationInView:self.mainView];
    CGFloat yLocation = secondaryLocation.y;
    if (touch.view == self.mainView && showSwipeUpGesture) {
        moveOnValidNumber = ((initialYLocation - yLocation) / 280) + 1;
        if (moveOnValidNumber > (CGFloat)1.0) {
            self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, ((initialYLocation - yLocation) / 280) + 1, (( initialYLocation - yLocation) / 280) + 1);
            self.mainView.alpha = 2 -  (((initialYLocation - yLocation) / 280) + 1);
        }
    }
}

-(void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event  {
    UITouch *touch = [touches anyObject];
    if (touch.view == self.mainView && showSwipeUpGesture) {
        if (moveOnValidNumber > 2.0 && jailbreakSupported()) {
            [self tappedOnJailbreak:nil];
            [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
                self.jailbreakView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
                self.jailbreakView.alpha = 1;
            } completion:nil];
            self.mainView.alpha = 0;
        } else if (moveOnValidNumber < 2.0 || !jailbreakSupported())  {
            [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
                self.mainView.alpha = 1;
                self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
                self.jailbreakView.transform = CGAffineTransformScale(CGAffineTransformIdentity,3, 3);
                self.jailbreakView.alpha = 0;
            } completion:nil];
        }
    } else if (touch.view == self.settingsButtonView) {
        [self openOtherMenus:self.settingsTransitionView: self.settingsButtonView: -movementConstant];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^(void){
            self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, -largestLengthScreen, 0);
        });
    } else if (touch.view == self.creditsButtonView) {
        [self openOtherMenus:self.creditsTransitionView: self.creditsButtonView: movementConstant];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^(void){
            self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, largestLengthScreen, 0);
        });
    }
}

- (IBAction)doneSettings:(id)sender {
    movementConstant = UIScreen.mainScreen.bounds.size.width;
    self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, -movementConstant, 0);
    [self closeOtherMenus:self.settingsTransitionView : movementConstant];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^(void){
        self.settingsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, largestLengthScreen, 0);
    });
}

- (IBAction)doneCredits:(id)sender {
    movementConstant = UIScreen.mainScreen.bounds.size.width;
    self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, movementConstant, 0);
    [self closeOtherMenus:self.creditsTransitionView : -movementConstant];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^(void){
        self.creditsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, -largestLengthScreen, 0);
    });
}

-(void)openOtherMenus:(UIView *)viewToOpen :(UIView *) buttonToOpen : (CGFloat) movementConstant  {
    
    [UIView animateWithDuration:0.3 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        buttonToOpen.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
    } completion:nil];
    [self hapticTouchFeedback];
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        viewToOpen.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        viewToOpen.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, 0);
        self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, movementConstant, 0);
    } completion:nil];
}

-(void)closeOtherMenus:(UIView *)viewToClose : (CGFloat)viewCloseValue {
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        viewToClose.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        viewToClose.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, viewCloseValue, 0);
        self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, 0);
    } completion:nil];
}

- (IBAction)tappedOnPwn:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"Pwn20wnd"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnDennis:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"DennisBednarz"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnSamB:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"sbingner"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnSamG:(id)sender{
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://reddit.com/u/Samg_is_a_Ninja"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnJoonwoo:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"iOS_App_Dev"] options:@{} completionHandler:nil];
}

// This intentionally returns nil if called before it's been created by a proper init
+(JailbreakViewController *)sharedController {
    return sharedController;
}

-(void)updateOutputView {
    [self updateOutputViewFromQueue:@NO];
}

-(void)updateOutputViewFromQueue:(NSNumber*)fromQueue {
    static BOOL updateQueued = NO;
    static struct timeval last = {0,0};
    static dispatch_queue_t updateQueue;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        updateQueue = dispatch_queue_create("updateView", NULL);
    });
    
    dispatch_async(updateQueue, ^{
        struct timeval now;

        if (fromQueue.boolValue) {
            updateQueued = NO;
        }
        
        if (updateQueued) {
            return;
        }
        
        if (gettimeofday(&now, NULL)) {
            LOG("gettimeofday failed");
            return;
        }
        
        uint64_t elapsed = (now.tv_sec - last.tv_sec) * 1000000 + now.tv_usec - last.tv_usec;
        // 30 FPS
        if (elapsed > 1000000/30) {
            updateQueued = NO;
            gettimeofday(&last, NULL);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.outputView.text = output;
                [self.outputView scrollRangeToVisible:NSMakeRange(self.outputView.text.length, 0)];
            });
        } else {
            NSTimeInterval waitTime = ((1000000/30) - elapsed) / 1000000.0;
            updateQueued = YES;
            dispatch_async(dispatch_get_main_queue(), ^{
                [self performSelector:@selector(updateOutputViewFromQueue:) withObject:@YES afterDelay:waitTime];
            });
        }
    });
}

-(void)appendTextToOutput:(NSString *)text {
    if (_outputView == nil) {
        return;
    }
    static NSRegularExpression *remove = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        remove = [NSRegularExpression regularExpressionWithPattern:@"^\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2}\\.\\d+[-\\d\\s]+\\S+\\[\\d+:\\d+\\]\\s+"
                                                           options:NSRegularExpressionAnchorsMatchLines error:nil];
        output = [NSMutableString new];
    });
    
    text = [remove stringByReplacingMatchesInString:text options:0 range:NSMakeRange(0, text.length) withTemplate:@""];

    @synchronized (output) {
        [output appendString:text];
    }
    [self updateOutputView];
}

- (id)initWithCoder:(NSCoder *)aDecoder {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super initWithCoder:aDecoder];
        }
    }
    self = sharedController;
    return self;
}

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
        }
    }
    self = sharedController;
    return self;
}

- (id)init {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super init];
        }
    }
    self = sharedController;
    return self;
}

@end
