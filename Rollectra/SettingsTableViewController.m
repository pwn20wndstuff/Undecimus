//
//  SettingsTableViewController.m
//  Rollectra
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
    [[NSScanner scannerWithString:[self.BootNonceTextField text]] scanUnsignedLongLong:&val];
    [[NSUserDefaults standardUserDefaults] setObject:[NSString stringWithFormat:@ADDR, val] forKey:@K_BOOT_NONCE];
    [[NSUserDefaults standardUserDefaults] synchronize];
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

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
