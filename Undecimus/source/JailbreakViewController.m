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
extern int maxStage;

- (IBAction)tappedOnJailbreak:(id)sender
{
    self.exploitMessageLabel.alpha = 1;
    self.exploitProgressLabel.alpha = 1;
    self.jailbreakProgressBar.alpha = 1;
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

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.jailbreakProgressBar.progress = 0;
    self.jailbreakProgressBar.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 2);
    prefs_t *prefs = copy_prefs();
    if (!jailbreakSupported()) {
        status(localize(@"Unsupported"), false, true);
        self.exploitMessageLabel.text = @"Unsupported";
    } else if (prefs->restore_rootfs) {
        status(localize(@"Restore RootFS"), true, true);
        self.exploitMessageLabel.text = @"Ready to restore RootFS";
    } else if (jailbreakEnabled()) {
        status(localize(@"Re-Jailbreak"), true, true);
        self.exploitMessageLabel.text = @"Ready to re-jailbreak";
    } else {
        status(localize(@"Jailbreak"), true, true);
        self.exploitMessageLabel.text = @"Ready to jailbreak";
    }
    
    self.settingsView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.7, 0.7);
    self.settingsView.alpha = 0;
    self.mainDevView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.7, 0.7);
    self.mainDevView.alpha = 0;
    self.creditsView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.7, 0.7);
    self.creditsView.alpha = 0;
    release_prefs(&prefs);
}


- (void)viewDidLoad {
    [super viewDidLoad];
    _canExit = YES;
    // Do any additional setup after loading the view, typically from a nib.
    prefs_t *prefs = copy_prefs();
    if (prefs->hide_log_window) {
        _outputView.hidden = YES;
        _outputView = nil;
    }
    
    if (prefs->dark_mode) {

        darkMode = YES;
        [self darkMode];
    }
    
    [self.settingsNavBar setBackgroundImage:[UIImage new] forBarMetrics:UIBarMetricsDefault];
    [self.settingsNavBar setShadowImage:[UIImage new]];
    
    [self.creditsNavBar setBackgroundImage:[UIImage new] forBarMetrics:UIBarMetricsDefault];
    [self.creditsNavBar setShadowImage:[UIImage new]];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(showSpeicalThanks:) name:@"showSpecialThanks" object:nil];
    
    self.exploitProgressLabel.text = [NSString stringWithFormat:@"%@/%@", [NSString stringWithFormat:@"%i", 0], [NSString stringWithFormat:@"%i", maxStage]];
    release_prefs(&prefs);
    sharedController = self;
    bundledResources = bundledResourcesVersion();
    LOG("unc0ver Version: %@", appVersion());
    self.uOVersionLabel.text = [NSString stringWithFormat:@"unc0ver Version: %@", appVersion()];
    printOSDetails();
    LOG("Bundled Resources Version: %@", bundledResources);
    if (bundledResources == nil) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
            showAlert(localize(@"Error"), localize(@"Bundled Resources version is missing. This build is invalid."), false, false);
        });
    }
}

bool darkMode = NO;

- (void)darkMode {
    
    

    [[NSNotificationCenter defaultCenter] postNotificationName:@"darkModeSettings" object:self];
    [[NSNotificationCenter defaultCenter] postNotificationName:@"darkModeCredits" object:self];
    darkMode = YES;
        [self.darkModeButton setImage:[UIImage imageNamed:@"DarkMode-Dark.png"] forState:UIControlStateNormal];
        [self.settingsButton setImage:[UIImage imageNamed:@"Settings-Dark.png"] forState:UIControlStateNormal];
    
        self.exploitProgressLabel.textColor = UIColor.whiteColor;
        self.exploitMessageLabel.textColor = UIColor.whiteColor;
        self.u0Label.textColor = UIColor.whiteColor;
        self.uOVersionLabel.textColor = UIColor.whiteColor;
        self.jailbreakLabel.textColor = UIColor.whiteColor;
        self.byLabel.textColor = UIColor.whiteColor;
        self.UIByLabel.textColor = UIColor.whiteColor;
        self.firstAndLabel.textColor = UIColor.whiteColor;
        self.secondAndLabel.textColor = UIColor.whiteColor;
        self.thirdAndLabel.textColor = UIColor.whiteColor;
        self.fourthAndLabel.textColor = UIColor.whiteColor;
    
        self.outputView.textColor = UIColor.whiteColor;
        self.backgroundView.backgroundColor = [UIColor colorWithRed:17.0f/255.0f green:20.0f/255.0f blue:24.0f/255.0f alpha:0.95f];
    
        [self.mainDevsButton setTitleColor:[UIColor whiteColor] forState: normal];
        [self.settingsNavBar setTintColor:[UIColor whiteColor]];
        [self.settingsNavBar setLargeTitleTextAttributes:@{NSForegroundColorAttributeName : [UIColor whiteColor]}];
        [self.creditsNavBar setTintColor:[UIColor whiteColor]];
        [self.creditsNavBar setLargeTitleTextAttributes:@{NSForegroundColorAttributeName : [UIColor whiteColor]}];
        [self setNeedsStatusBarAppearanceUpdate];
}

- (void)lightMode {

    darkMode = NO;
    [[NSNotificationCenter defaultCenter] postNotificationName:@"lightModeSettings" object:self];
    [[NSNotificationCenter defaultCenter] postNotificationName:@"lightModeCredits" object:self];
        [self.darkModeButton setImage:[UIImage imageNamed:@"DarkMode-Light.png"] forState:UIControlStateNormal];
        [self.settingsButton setImage:[UIImage imageNamed:@"Settings-Light.png"] forState:UIControlStateNormal];
        
        self.exploitProgressLabel.textColor = UIColor.blackColor;
        self.exploitMessageLabel.textColor = UIColor.blackColor;
        self.u0Label.textColor = UIColor.blackColor;
        self.jailbreakLabel.textColor = UIColor.blackColor;
        self.byLabel.textColor = UIColor.blackColor;
        self.UIByLabel.textColor = UIColor.blackColor;
        self.firstAndLabel.textColor = UIColor.blackColor;
        self.secondAndLabel.textColor = UIColor.blackColor;
        self.thirdAndLabel.textColor = UIColor.blackColor;
        self.fourthAndLabel.textColor = UIColor.blackColor;
        
        self.uOVersionLabel.textColor = UIColor.blackColor;
        self.outputView.textColor = UIColor.blackColor;
        
        self.backgroundView.backgroundColor = [UIColor.whiteColor colorWithAlphaComponent:0.84];
        
        [self.settingsNavBar setTintColor:[UIColor blackColor]];
        [self.settingsNavBar setLargeTitleTextAttributes:@{NSForegroundColorAttributeName : [UIColor blackColor]}];
        [self.creditsNavBar setTintColor:[UIColor blackColor]];
        [self.creditsNavBar setLargeTitleTextAttributes:@{NSForegroundColorAttributeName : [UIColor blackColor]}];
        [self setNeedsStatusBarAppearanceUpdate];
}

- (IBAction)enableDarkMode:(id)sender {
    
    [UIView animateWithDuration:2 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        if (!darkMode) {
            [self darkMode];
        } else {
            [self lightMode];
        }
        
    } completion:nil];
    
    prefs_t *prefs = copy_prefs();
    prefs->dark_mode = (bool)darkMode;
    set_prefs(prefs);
    release_prefs(&prefs);
    
}



- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    if (darkMode) {
    return UIStatusBarStyleLightContent;
    } else {
        return UIStatusBarStyleDefault;
    }
}

- (IBAction)openSettings:(id)sender {
    [UIView animateWithDuration:1 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.settingsView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.settingsView.alpha = 1;
        self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1.3, 1.3);
        self.mainView.alpha = 0;
    } completion:nil];
}

- (void) showSpeicalThanks:(NSNotification *) notification {
    [UIView animateWithDuration:1 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.creditsView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.creditsView.alpha = 1;
        self.settingsView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1.3, 1.3);
        self.settingsView.alpha = 0;
    } completion:nil];
}

- (IBAction)dismissSpeicalThanks:(id)sender{
    [UIView animateWithDuration:1 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.settingsView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.settingsView.alpha = 1;
        self.creditsView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.7, 0.7);
        self.creditsView.alpha = 0;
    } completion:nil];
}

- (IBAction)openMainDevView:(id)sender {
    [UIView animateWithDuration:1 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.mainDevView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.mainDevView.alpha = 1;
        self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1.3, 1.3);
        self.mainView.alpha = 0;
    } completion:nil];
}

- (IBAction)closeMainDevView:(id)sender{
    [UIView animateWithDuration:1 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.mainView.alpha = 1;
        self.mainDevView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.7, 0.7);
        self.mainDevView.alpha = 0;
    } completion:nil];
}


- (IBAction)closeSettings:(id)sender{
    [UIView animateWithDuration:1 delay:0 usingSpringWithDamping:1 initialSpringVelocity:1 options:UIViewAnimationOptionCurveEaseInOut animations:^{
        self.mainView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 1, 1);
        self.mainView.alpha = 1;
        self.settingsView.transform = CGAffineTransformScale(CGAffineTransformIdentity, 0.7, 0.7);
        self.settingsView.alpha = 0;
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

- (IBAction)tappendOnJoonwoo:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"iOS_App_Dev"] options:@{} completionHandler:nil];
}
- (IBAction)tappendOnUbik:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"HiMyNameIsUbik"] options:@{} completionHandler:nil];
}


- (IBAction)tappedOnSamG:(id)sender{
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://reddit.com/u/Samg_is_a_Ninja"] options:@{} completionHandler:nil];
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
