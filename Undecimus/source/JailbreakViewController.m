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

- (IBAction)tappedOnJailbreak:(id)sender
{
    status(localize(@"Jailbreak"), false, false);
    auto const block = ^(void) {
        _assert(bundledResources != nil, localize(@"Bundled Resources version missing."), true);
        if (!jailbreakSupported()) {
            status(localize(@"Unsupported"), false, true);
            return;
        }
        jailbreak();
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

BOOL notchedDevice = NO;

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    auto prefs = copy_prefs();
    if (!jailbreakSupported()) {
        status(localize(@"Unsupported"), false, true);
    } else if (prefs->restore_rootfs) {
        status(localize(@"Restore RootFS"), true, true);
    } else if (jailbreakEnabled()) {
        status(localize(@"Re-Jailbreak"), true, true);
    } else {
        status(localize(@"Jailbreak"), true, true);
    }
    
    self.initalErrorView.alpha = 0;
    self.settingsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, [UIScreen mainScreen].bounds.size.height, 0);
    self.creditsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, -[UIScreen mainScreen].bounds.size.height, 0);
    
    if (@available(iOS 11.0, *)) {
        UIWindow *mainWindow = [[[UIApplication sharedApplication] delegate] window];
        if (mainWindow.safeAreaInsets.top > 24.0) {
            notchedDevice = YES;
            _swipeUpLabelBottomConstraint.constant = _swipeUpLabelBottomConstraint.constant + 44;
            _mainViewTopConstraint.constant = -44;
            _mainViewBottomConstraint.constant = -44;
            _settingsViewTopConstraint.constant = -44;
            _settingsViewBottomConstraint.constant = 44;
            _creditsViewTopConstraint.constant = -44;
            _creditsViewBottomConstraint.constant = 44;
            _jailbreakViewTopConstraint.constant = -44;
            _jailbreakViewBottomConstraint.constant = 44;
            _creditsHapticTouchBottomConstraint.constant = _creditsHapticTouchBottomConstraint.constant + 44;
            _settingssHapticTouchBottomConstraint.constant = _settingssHapticTouchBottomConstraint.constant + 44;
            _initialErrorViewTopConstraint.constant = -44;
            _initialErrorViewBottomConstraint.constant = 44;
            _initialErrorViewLabelTopConstraint.constant = _initialErrorViewLabelTopConstraint.constant + 44;
            _initialErrorViewButtonBottomConstraint.constant = _initialErrorViewButtonBottomConstraint.constant + 44;
        }
    }
    
    
    release_prefs(&prefs);
}


bool up = NO;
bool down = YES;
NSTimer *swipeUpTimer;
- (void) swipeUpAnimation:(NSTimer *)timer {
    if ((up == NO) && (down == YES)) {
        
        [UIView animateWithDuration:1.6 delay:0.4 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            
            self.swipeUpLabel.alpha = 1;
            self.swipeUpLabel.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, -50);
            
        } completion:nil];
        
        up = YES;
        down = NO;
        
    }else if ((up == YES) && (down == NO)) {
        
        [UIView animateWithDuration:1.6 delay:0.4 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            
            self.swipeUpLabel.alpha = 0;
        } completion:nil];
        
        [UIView animateWithDuration:0.1 delay:1.6 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            self.swipeUpLabel.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, 0);
        } completion:nil];
        
        
        up = NO;
        down = YES;
        
    }
    
    /*
    if (__COUNTER__ == vcmaxstage) {
        
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@K_TWEAK_INJECTION] == false) {
            
            [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
                
                self.mainView.alpha = 1;
                self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
                self.jailbreakView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 3, 3);
                self.jailbreakView.alpha = 0;
                
            } completion:nil];
        }
    }*/
    
    
    
}

BOOL showSwipeUpGesture = NO;

- (void)viewDidLoad {
    [super viewDidLoad];
    _canExit = YES;
    
    

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
    
    // Do any additional setup after loading the view, typically from a nib.
    auto prefs = copy_prefs();
    if (prefs->hide_log_window) {
        _outputView.hidden = YES;
        _outputView = nil;
        _goButton.hidden = YES;
        _swipeUpLabel.alpha = 1;
        showSwipeUpGesture = YES;
        swipeUpTimer = [NSTimer scheduledTimerWithTimeInterval:1.6 target:self selector:@selector(swipeUpAnimation:) userInfo:nil repeats:YES];
        _undecimusLogoCentreConstraint.constant = -70;
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
    return UIStatusBarStyleDefault;
}



CGFloat initialYLocation;
CGFloat moveOnValidNumber;

-(void)hapticTouchFeedback {
    if ([[UIDevice currentDevice] valueForKey:@"_feedbackSupportLevel"] == 2) {
        UIImpactFeedbackGenerator *generator = [[UIImpactFeedbackGenerator alloc] initWithStyle: UIImpactFeedbackStyleLight];
        [generator prepare];
        [generator impactOccurred];
        generator = nil;
        
    } else {
        AudioServicesPlaySystemSound(1519);
    }
}


-(void)noHaptic {
    
    AudioServicesPlaySystemSound(1519);
    dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, 0.15 * NSEC_PER_SEC);
    dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
        
        AudioServicesPlaySystemSound(1519);
        
    });
}



-(void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *touch = [touches anyObject];
    CGPoint secondaryLocation = [touch locationInView: _mainView];
    
    CGFloat yLocation = secondaryLocation.y;
    
    if (([touch view] == _mainView) && (showSwipeUpGesture == YES)) {
        initialYLocation = yLocation;
        
        if (!jailbreakSupported()) {
            
            [self noHaptic];
            
            [UIView animateWithDuration:0.3 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
                self.initalErrorView.alpha = 1;
            } completion:nil];
        } 
        
    } else if ([touch view] == _creditsButtonView) {
        [UIView animateWithDuration:0.3 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            self->_creditsButtonView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1.5, 1.5);
        } completion:nil];
        
        [self hapticTouchFeedback];
        
    } else if ([touch view] == _settingsButtonView) {
        
        [UIView animateWithDuration:0.3 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            self->_settingsButtonView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1.5, 1.5);
        } completion:nil];
        
        [self hapticTouchFeedback];
        
        
    }
    
}




-(void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *touch = [touches anyObject];
    CGPoint secondaryLocation = [touch locationInView: _mainView];
    CGFloat yLocation = secondaryLocation.y;
    
    if (([touch view] == _mainView) && (showSwipeUpGesture == YES)) {
        
        
        
        moveOnValidNumber = ((initialYLocation - yLocation) / 280) + 1;
        
        if (moveOnValidNumber > (CGFloat)1.0) {
            
            
            self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity,
                                                             (( initialYLocation - yLocation) / 280) + 1, (( initialYLocation - yLocation) / 280) + 1);
            self.mainView.alpha = 2 -  ((( initialYLocation - yLocation) / 280) + 1);
            
            
            
        }
        
    }
}

-(void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event  {
    
    UITouch *touch = [touches anyObject];
    
    if (([touch view] == _mainView) && (showSwipeUpGesture == YES)) {
        if ((moveOnValidNumber > 2.0) && jailbreakSupported()) {
            
            [self tappedOnJailbreak:nil];
            [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
                self.jailbreakView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
                self.jailbreakView.alpha = 1;
            } completion:nil];
            
            // [swipeUpTimer invalidate];
            self.mainView.alpha = 0;
            
        } else if ((moveOnValidNumber < 2.0) || (!jailbreakSupported()))  {
            
            [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
                
                self.mainView.alpha = 1;
                self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
                self.jailbreakView.transform = CGAffineTransformScale(CGAffineTransformIdentity,3, 3);
                self.jailbreakView.alpha = 0;
                
            } completion:nil];
            
            
            
        }
        
    }  else if ([touch view] == _settingsButtonView) {
        [UIView animateWithDuration:0.3 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            self->_settingsButtonView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        } completion:nil];
        
        [self hapticTouchFeedback];
        
        [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            
            self.settingsTransitionView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
            
            self.settingsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, 0);
            self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.5, 0.5);
            
            self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, -[UIScreen mainScreen].bounds.size.height, 0);
        } completion:nil];
        
        
    } else if ([touch view] == _creditsButtonView) {
        [UIView animateWithDuration:0.3 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            self->_creditsButtonView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        } completion:nil];
        
        [self hapticTouchFeedback];
        
        [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            
            self.creditsTransitionView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
            self.creditsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, 0);
            
            self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.5, 0.5);
            self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, [UIScreen mainScreen].bounds.size.height, 0);
            
        } completion:nil];
        
        
    }
    
}

- (IBAction)doneSettings:(id)sender {
    
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        
        self.settingsTransitionView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.settingsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, [UIScreen mainScreen].bounds.size.height, 0);
        self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, 0);
        
    } completion:nil];
    
}

- (IBAction)doneCredits:(id)sender {
    
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        
        self.creditsTransitionView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.creditsTransitionView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, -[UIScreen mainScreen].bounds.size.height, 0);
        self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.mainView.transform = CGAffineTransformTranslate(CGAffineTransformIdentity, 0, 0);
        
    } completion:nil];
}

- (IBAction)dismissInitialError:(id)sender {
    
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        
        self.initalErrorView.alpha = 0;
        
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
