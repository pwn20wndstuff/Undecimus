//
//  SettingsTableViewController.m
//  Undecimus
//
//  Created by Pwn20wnd on 9/14/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#include <sys/utsname.h>
#include <sys/sysctl.h>
#import "SettingsTableViewController.h"
#include <common.h>
#include "hideventsystem.h"
#include "remote_call.h"
#include "JailbreakViewController.h"
#include "utils.h"
#include "voucher_swap-poc.h"
#include "necp.h"
#include "kalloc_crash.h"
#include "prefs.h"
#include "diagnostics.h"

@interface SettingsTableViewController ()

@end

@implementation SettingsTableViewController

// https://github.com/Matchstic/ReProvision/blob/7b595c699335940f68702bb204c5aa55b8b1896f/Shared/Application%20Database/RPVApplication.m#L102

+ (NSDictionary *)provisioningProfileAtPath:(NSString *)path {
    auto stringContent = [NSString stringWithContentsOfFile:path encoding:NSASCIIStringEncoding error:nil];
    stringContent = [stringContent componentsSeparatedByString:@"<plist version=\"1.0\">"][1];
    stringContent = [NSString stringWithFormat:@"%@%@", @"<plist version=\"1.0\">", stringContent];
    stringContent = [stringContent componentsSeparatedByString:@"</plist>"][0];
    stringContent = [NSString stringWithFormat:@"%@%@", stringContent, @"</plist>"];
    auto const stringData = [stringContent dataUsingEncoding:NSASCIIStringEncoding];
    id const plist = [NSPropertyListSerialization propertyListWithData:stringData options:NSPropertyListImmutable format:nil error:nil];
    return plist;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadData];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    auto const myImageView = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"Clouds"]];
    [myImageView setContentMode:UIViewContentModeScaleAspectFill];
    [myImageView setFrame:self.tableView.frame];
    auto const myView = [[UIView alloc] initWithFrame:myImageView.frame];
    [myView setBackgroundColor:[UIColor whiteColor]];
    [myView setAlpha:0.84];
    [myView setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
    [myImageView addSubview:myView];
    [self.tableView setBackgroundView:myImageView];
    [self.BootNonceTextField setDelegate:self];
    self.tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(userTappedAnyware:)];
    self.tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:self.tap];
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
    auto prefs = copy_prefs();
    [self.TweakInjectionSwitch setOn:(BOOL)prefs->load_tweaks];
    [self.LoadDaemonsSwitch setOn:(BOOL)prefs->load_daemons];
    [self.DumpAPTicketSwitch setOn:(BOOL)prefs->dump_apticket];
    [self.BootNonceTextField setPlaceholder:@(prefs->boot_nonce)];
    [self.BootNonceTextField setText:nil];
    [self.RefreshIconCacheSwitch setOn:(BOOL)prefs->run_uicache];
    [self.KernelExploitSegmentedControl setSelectedSegmentIndex:(int)prefs->exploit];
    [self.DisableAutoUpdatesSwitch setOn:(BOOL)prefs->disable_auto_updates];
    [self.DisableAppRevokesSwitch setOn:(BOOL)prefs->disable_app_revokes];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(empty_list_exploit) forSegmentAtIndex:empty_list_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(multi_path_exploit) forSegmentAtIndex:multi_path_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(async_wake_exploit) forSegmentAtIndex:async_wake_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(voucher_swap_exploit) forSegmentAtIndex:voucher_swap_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(mach_swap_exploit) forSegmentAtIndex:mach_swap_exploit];
    [self.KernelExploitSegmentedControl setEnabled:supportsExploit(mach_swap_2_exploit) forSegmentAtIndex:mach_swap_2_exploit];
    [self.OpenCydiaButton setEnabled:[[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://"]]];
    [self.ExpiryLabel setPlaceholder:[NSString stringWithFormat:@"%d %@", (int)[[SettingsTableViewController provisioningProfileAtPath:[[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"]][@"ExpirationDate"] timeIntervalSinceDate:[NSDate date]] / 86400, localize(@"Days")]];
    [self.OverwriteBootNonceSwitch setOn:(BOOL)prefs->overwrite_boot_nonce];
    [self.ExportKernelTaskPortSwitch setOn:(BOOL)prefs->export_kernel_task_port];
    [self.RestoreRootFSSwitch setOn:(BOOL)prefs->restore_rootfs];
    [self.UptimeLabel setPlaceholder:[NSString stringWithFormat:@"%d %@", (int)getUptime() / 86400, localize(@"Days")]];
    [self.IncreaseMemoryLimitSwitch setOn:(BOOL)prefs->increase_memory_limit];
    [self.installSSHSwitch setOn:(BOOL)prefs->install_openssh];
    [self.installCydiaSwitch setOn:(BOOL)prefs->install_cydia];
    if (prefs->ecid) [self.ECIDLabel setPlaceholder:hexFromInt([@(prefs->ecid) integerValue])];
    [self.ReloadSystemDaemonsSwitch setOn:(BOOL)prefs->reload_system_daemons];
    [self.HideLogWindowSwitch setOn:(BOOL)prefs->hide_log_window];
    [self.ResetCydiaCacheSwitch setOn:(BOOL)prefs->reset_cydia_cache];
    [self.SSHOnlySwitch setOn:(BOOL)prefs->ssh_only];
    [self.EnableGetTaskAllowSwitch setOn:(BOOL)prefs->enable_get_task_allow];
    [self.SetCSDebuggedSwitch setOn:(BOOL)prefs->set_cs_debugged];
    [self.RestartSpringBoardButton setEnabled:respringSupported()];
    [self.restartButton setEnabled:restartSupported()];
    release_prefs(&prefs);
    [self.tableView reloadData];
}

- (IBAction)TweakInjectionSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->load_tweaks = (bool)self.TweakInjectionSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)LoadDaemonsSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->load_daemons = (bool)self.LoadDaemonsSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)DumpAPTicketSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->dump_apticket = (bool)self.DumpAPTicketSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)BootNonceTextFieldTriggered:(id)sender {
    auto val = (uint64_t)0;
    if ([[NSScanner scannerWithString:[self.BootNonceTextField text]] scanHexLongLong:&val] && val != HUGE_VAL && val != -HUGE_VAL) {
        auto prefs = copy_prefs();
        prefs->boot_nonce = [NSString stringWithFormat:@ADDR, val].UTF8String;
        set_prefs(prefs);
        release_prefs(&prefs);
    } else {
        auto const alertController = [UIAlertController alertControllerWithTitle:localize(@"Invalid Entry") message:localize(@"The boot nonce entered could not be parsed") preferredStyle:UIAlertControllerStyleAlert];
        auto const OK = [UIAlertAction actionWithTitle:localize(@"OK") style:UIAlertActionStyleDefault handler:nil];
        [alertController addAction:OK];
        [self presentViewController:alertController animated:YES completion:nil];
    }
    [self reloadData];
}

- (IBAction)RefreshIconCacheSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->run_uicache = (bool)self.RefreshIconCacheSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)KernelExploitSegmentedControl:(id)sender {
    auto prefs = copy_prefs();
    prefs->exploit = (int)self.KernelExploitSegmentedControl.selectedSegmentIndex;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)DisableAppRevokesSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->disable_app_revokes = (bool)self.DisableAppRevokesSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnRestart:(id)sender {
    auto const block = ^(void) {
        notice(localize(@"The device will be restarted."), true, false);
        auto const support = recommendedRestartSupport();
        switch (support) {
            case necp_exploit: {
                necp_die();
                break;
            }
            case voucher_swap_exploit: {
                voucher_swap_poc();
                break;
            }
            case kalloc_crash: {
                do_kalloc_crash();
                break;
            }
            default:
                break;
        }
        exit(EXIT_FAILURE);
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (IBAction)DisableAutoUpdatesSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->disable_auto_updates = (bool)self.DisableAutoUpdatesSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnShareDiagnosticsData:(id)sender {
    auto const URL = [NSURL fileURLWithPath:[NSString stringWithFormat:@"%@/Documents/diagnostics.plist", NSHomeDirectory()]];
    [getDiagnostics() writeToURL:URL error:nil];
    auto const activityViewController = [[UIActivityViewController alloc] initWithActivityItems:@[URL] applicationActivities:nil];
    if ([activityViewController respondsToSelector:@selector(popoverPresentationController)]) {
        [[activityViewController popoverPresentationController] setSourceView:self.ShareDiagnosticsDataButton];
    }
    [self presentViewController:activityViewController animated:YES completion:nil];
}

- (IBAction)tappedOnOpenCydia:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"cydia://"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnOpenGithub:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/pwn20wndstuff/Undecimus"] options:@{} completionHandler:nil];
}

- (IBAction)OverwriteBootNonceSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->overwrite_boot_nonce = (bool)self.OverwriteBootNonceSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnCopyNonce:(id)sender{
    auto const copyBootNonceAlert = [UIAlertController alertControllerWithTitle:localize(@"Copy boot nonce?") message:localize(@"Would you like to copy nonce generator to clipboard?") preferredStyle:UIAlertControllerStyleAlert];
    auto const copyAction = [UIAlertAction actionWithTitle:localize(@"Yes") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        auto prefs = copy_prefs();
        [[UIPasteboard generalPasteboard] setString:@(prefs->boot_nonce)];
        release_prefs(&prefs);
    }];
    auto const noAction = [UIAlertAction actionWithTitle:localize(@"No") style:UIAlertActionStyleCancel handler:nil];
    [copyBootNonceAlert addAction:copyAction];
    [copyBootNonceAlert addAction:noAction];
    [self presentViewController:copyBootNonceAlert animated:TRUE completion:nil];
}

- (IBAction)tappedOnCopyECID:(id)sender {
    auto const copyBootNonceAlert = [UIAlertController alertControllerWithTitle:localize(@"Copy ECID?") message:localize(@"Would you like to ECID to clipboard?") preferredStyle:UIAlertControllerStyleAlert];
    auto const copyAction = [UIAlertAction actionWithTitle:localize(@"Yes") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        auto prefs = copy_prefs();
        [[UIPasteboard generalPasteboard] setString:hexFromInt(@(prefs->ecid).integerValue)];
        release_prefs(&prefs);
    }];
    auto const noAction = [UIAlertAction actionWithTitle:localize(@"No") style:UIAlertActionStyleCancel handler:nil];
    [copyBootNonceAlert addAction:copyAction];
    [copyBootNonceAlert addAction:noAction];
    [self presentViewController:copyBootNonceAlert animated:TRUE completion:nil];
}

- (IBAction)tappedOnCheckForUpdate:(id)sender {
    auto const block = ^(void) {
        auto const update = [NSString stringWithContentsOfURL:[NSURL URLWithString:@"https://github.com/pwn20wndstuff/Undecimus/raw/master/Update.txt"] encoding:NSUTF8StringEncoding error:nil];
        if (update == nil) {
            notice(localize(@"Failed to check for update."), true, false);
        } else if ([update compare:appVersion() options:NSNumericSearch] == NSOrderedDescending) {
            notice(localize(@"An update is available."), true, false);
        } else {
            notice(localize(@"Already up to date."), true, false);
        }
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (IBAction)exportKernelTaskPortSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->export_kernel_task_port = (bool)self.ExportKernelTaskPortSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)RestoreRootFSSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->restore_rootfs = (bool)self.RestoreRootFSSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)installCydiaSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->install_cydia = (bool)self.installCydiaSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)installSSHSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->install_openssh = (bool)self.installSSHSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (void)tableView:(UITableView *)tableView willDisplayFooterView:(UITableViewHeaderFooterView *)footerView forSection:(NSInteger)section {
    footerView.textLabel.text = [@"unc0ver " stringByAppendingString:appVersion()];
    footerView.textLabel.textAlignment = NSTextAlignmentCenter;
}

- (IBAction)IncreaseMemoryLimitSwitch:(id)sender {
    auto prefs = copy_prefs();
    prefs->increase_memory_limit = (bool)self.IncreaseMemoryLimitSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnAutomaticallySelectExploit:(id)sender {
    auto prefs = copy_prefs();
    prefs->exploit = (int)recommendedJailbreakSupport();
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)reloadSystemDaemonsSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->reload_system_daemons = (bool)self.ReloadSystemDaemonsSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedRestartSpringBoard:(id)sender {
    auto const block = ^(void) {
        notice(localize(@"SpringBoard will be restarted."), true, false);
        auto const support = recommendedRespringSupport();
        switch (support) {
            case deja_xnu_exploit: {
                auto const bb_tp = hid_event_queue_exploit();
                _assert(MACH_PORT_VALID(bb_tp), localize(@"Unable to get task port for backboardd."), true);
                _assert(thread_call_remote(bb_tp, exit, 1, REMOTE_LITERAL(EXIT_SUCCESS)) == ERR_SUCCESS, localize(@"Unable to make backboardd exit."), true);
                break;
            }
            default:
                break;
        }
        exit(EXIT_FAILURE);
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (IBAction)tappedOnCleanDiagnosticsData:(id)sender {
    cleanLogs();
    notice(localize(@"Cleaned diagnostics data."), false, false);
}

- (IBAction)hideLogWindowSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->hide_log_window = (bool)self.HideLogWindowSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
    auto const block = ^(void) {
        notice(localize(@"Preference was changed. The app will now exit."), true, false);
        exit(EXIT_SUCCESS);
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (IBAction)resetCydiaCacheSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->reset_cydia_cache = (bool)self.ResetCydiaCacheSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)sshOnlySwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->ssh_only = (bool)self.SSHOnlySwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)enableGetTaskAllowSwitchTriggered:(id)sender {
    auto prefs = copy_prefs();
    prefs->enable_get_task_allow = (bool)self.EnableGetTaskAllowSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)setCSDebugged:(id)sender {
    auto prefs = copy_prefs();
    prefs->set_cs_debugged = (bool)self.SetCSDebuggedSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnResetAppPreferences:(id)sender {
    auto const block = ^(void) {
        reset_prefs();
        notice(localize(@"Preferences were reset. The app will now exit."), true, false);
        exit(EXIT_SUCCESS);
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
