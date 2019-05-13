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
    release_prefs(&prefs);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    _canExit = YES;
    // Do any additional setup after loading the view, typically from a nib.
    auto prefs = copy_prefs();
    if (prefs->hide_log_window) {
        _outputView.hidden = YES;
        _outputView = nil;
        _goButtonSpacing.constant += 80;
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
