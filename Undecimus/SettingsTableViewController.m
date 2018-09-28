//
//  SettingsTableViewController.m
//  Undecimus
//
//  Created by Pwn20wnd on 9/14/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import "SettingsTableViewController.h"
#include "common.h"

@interface SettingsTableViewController ()

@end

@implementation SettingsTableViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    UIImageView *myImageView = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"Clouds"]];
    [myImageView setContentMode:UIViewContentModeBottomLeft];
    [myImageView setFrame:self.tableView.frame];
    UIView *myView = [[UIView alloc] initWithFrame:myImageView.frame];
    [myView setBackgroundColor:[UIColor whiteColor]];
    [myView setAlpha:0.84];
    [myView setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
    [myImageView addSubview:myView];
    [self.tableView setBackgroundView:myImageView];
    [self.navigationController.navigationBar setBackgroundImage:[UIImage new] forBarMetrics:UIBarMetricsDefault];
    [self.navigationController.navigationBar setShadowImage:[UIImage new]];
    [self.BootNonceTextField setDelegate:self];
    [self reloadData];
    _tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(userTappedAnyware:)];
    _tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:_tap];
}

- (void)userTappedAnyware:(UITapGestureRecognizer *) sender
{
    [self.view endEditing:YES];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

- (void)reloadData {
    [self.TweakInjectionSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_TWEAK_INJECTION]];
    [self.LoadDaemonsSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_LOAD_DAEMONS]];
    [self.DumpAPTicketSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_DUMP_APTICKET]];
    [self.BootNonceTextField setPlaceholder:[[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE]];
    [self.BootNonceTextField setText:nil];
    [self.RefreshIconCacheSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_REFRESH_ICON_CACHE]];
    [self.KernelExploitSegmentedControl setSelectedSegmentIndex:[[NSUserDefaults standardUserDefaults] integerForKey:@K_EXPLOIT]];
    [self.DisableAutoUpdatesSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_DISABLE_AUTO_UPDATES]];
    [self.DisableAppRevokesSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_DISABLE_APP_REVOKES]];
    [self.tableView reloadData];
}

- (IBAction)TweakInjectionSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.TweakInjectionSwitch isOn] forKey:@K_TWEAK_INJECTION];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}
- (IBAction)LoadDaemonsSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.LoadDaemonsSwitch isOn] forKey:@K_LOAD_DAEMONS];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}
- (IBAction)DumpAPTicketSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.DumpAPTicketSwitch isOn] forKey:@K_DUMP_APTICKET];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)BootNonceTextFieldTriggered:(id)sender {
    uint64_t val = 0;
    if ([[NSScanner scannerWithString:[self.BootNonceTextField text]] scanHexLongLong:&val] && val != HUGE_VAL && val != -HUGE_VAL) {
        [[NSUserDefaults standardUserDefaults] setObject:[NSString stringWithFormat:@ADDR, val] forKey:@K_BOOT_NONCE];
        [[NSUserDefaults standardUserDefaults] synchronize];
    } else {
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Invalid Entry"
                                                                       message:@"The boot nonce entered could not be parsed"
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault
                                                              handler:^(UIAlertAction * action) {}];
        
        [alert addAction:defaultAction];
        [self presentViewController:alert animated:YES completion:nil];
    }
    [self reloadData];
}

- (IBAction)RefreshIconCacheSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.RefreshIconCacheSwitch isOn] forKey:@K_REFRESH_ICON_CACHE];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}
- (IBAction)KernelExploitSegmentedControl:(id)sender {
    [[NSUserDefaults standardUserDefaults] setInteger:self.KernelExploitSegmentedControl.selectedSegmentIndex forKey:@K_EXPLOIT];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)DisableAppRevokesSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.RefreshIconCacheSwitch isOn] forKey:@K_DISABLE_APP_REVOKES];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

extern void iosurface_die(void);
extern int vfs_die(void);
extern int mptcp_die(void);

- (IBAction)tappedOnRestart:(id)sender {
    [self.restartButton setEnabled:NO];
    [self.restartButton setTitle:@"Restarting..." forState:UIControlStateDisabled];
    iosurface_die();
    vfs_die();
    mptcp_die();
}
- (IBAction)DisableAutoUpdatesSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.DisableAutoUpdatesSwitch isOn] forKey:@K_DISABLE_AUTO_UPDATES];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
