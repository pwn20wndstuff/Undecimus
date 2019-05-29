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
    NSString *stringContent = [NSString stringWithContentsOfFile:path encoding:NSASCIIStringEncoding error:nil];
    stringContent = [stringContent componentsSeparatedByString:@"<plist version=\"1.0\">"][1];
    stringContent = [NSString stringWithFormat:@"%@%@", @"<plist version=\"1.0\">", stringContent];
    stringContent = [stringContent componentsSeparatedByString:@"</plist>"][0];
    stringContent = [NSString stringWithFormat:@"%@%@", stringContent, @"</plist>"];
    NSData *const stringData = [stringContent dataUsingEncoding:NSASCIIStringEncoding];
    id const plist = [NSPropertyListSerialization propertyListWithData:stringData options:NSPropertyListImmutable format:nil error:nil];
    return plist;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadData];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(darkModeSettings:) name:@"darkModeSettings" object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(lightModeSettings:) name:@"lightModeSettings" object:nil];
    [self.BootNonceTextField setDelegate:self];
    self.tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(userTappedAnyware:)];
    self.tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:self.tap];
}


-(void)darkModeSettings:(NSNotification *) notification  {
    [self.specialThanksLabel setTextColor:[UIColor whiteColor]];
    [self.TweakInjectionLabel setTextColor:[UIColor whiteColor]];
    [self.LoadDaemonsLabel setTextColor:[UIColor whiteColor]];
    [self.DumpAPTicketLabel setTextColor:[UIColor whiteColor]];
    [self.RefreshIconCacheLabel setTextColor:[UIColor whiteColor]];
    [self.DisableAutoUpdatesLabel setTextColor:[UIColor whiteColor]];
    [self.DisableAppRevokesLabel setTextColor:[UIColor whiteColor]];
    [self.OverwriteBootNonceLabel setTextColor:[UIColor whiteColor]];
    [self.ExportKernelTaskPortLabel setTextColor:[UIColor whiteColor]];
    [self.RestoreRootFSLabel setTextColor:[UIColor whiteColor]];
    [self.installCydiaLabel setTextColor:[UIColor whiteColor]];
    [self.installSSHLabel setTextColor:[UIColor whiteColor]];
    [self.IncreaseMemoryLimitLabel setTextColor:[UIColor whiteColor]];
    [self.ReloadSystemDaemonsLabel setTextColor:[UIColor whiteColor]];
    [self.HideLogWindowLabel setTextColor:[UIColor whiteColor]];
    [self.ResetCydiaCacheLabel setTextColor:[UIColor whiteColor]];
    [self.SSHOnlyLabel setTextColor:[UIColor whiteColor]];
    [self.EnableGetTaskAllowLabel setTextColor:[UIColor whiteColor]];
    [self.SetCSDebuggedLabel setTextColor:[UIColor whiteColor]];
    [self.AutoRespringLabel setTextColor:[UIColor whiteColor]];
    [self.kernelExploitLabel setTextColor:[UIColor whiteColor]];
    
    [self.bootNonceButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.BootNonceTextField setTintColor:[UIColor whiteColor]];
    
    [self.BootNonceTextField setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ECIDLabel setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidDarkModeButton setTitleColor:[UIColor whiteColor] forState:normal];
    
    [self.expiryDarkModeLabel setTextColor:[UIColor whiteColor]];
    [self.ExpiryLabel setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.UptimeLabel setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.upTimeLabel setTextColor:[UIColor whiteColor]];
}

-(void)lightModeSettings:(NSNotification *) notification  {
    [self.specialThanksLabel setTextColor:[UIColor blackColor]];
    [self.TweakInjectionLabel setTextColor:[UIColor blackColor]];
    [self.LoadDaemonsLabel setTextColor:[UIColor blackColor]];
    [self.DumpAPTicketLabel setTextColor:[UIColor blackColor]];
    [self.RefreshIconCacheLabel setTextColor:[UIColor blackColor]];
    [self.DisableAutoUpdatesLabel setTextColor:[UIColor blackColor]];
    [self.DisableAppRevokesLabel setTextColor:[UIColor blackColor]];
    [self.OverwriteBootNonceLabel setTextColor:[UIColor blackColor]];
    [self.ExportKernelTaskPortLabel setTextColor:[UIColor blackColor]];
    [self.RestoreRootFSLabel setTextColor:[UIColor blackColor]];
    [self.installCydiaLabel setTextColor:[UIColor blackColor]];
    [self.installSSHLabel setTextColor:[UIColor blackColor]];
    [self.IncreaseMemoryLimitLabel setTextColor:[UIColor blackColor]];
    [self.ReloadSystemDaemonsLabel setTextColor:[UIColor blackColor]];
    [self.HideLogWindowLabel setTextColor:[UIColor blackColor]];
    [self.ResetCydiaCacheLabel setTextColor:[UIColor blackColor]];
    [self.SSHOnlyLabel setTextColor:[UIColor blackColor]];
    [self.EnableGetTaskAllowLabel setTextColor:[UIColor blackColor]];
    [self.SetCSDebuggedLabel setTextColor:[UIColor blackColor]];
    [self.AutoRespringLabel setTextColor:[UIColor blackColor]];
    [self.kernelExploitLabel setTextColor:[UIColor blackColor]];
    
    [self.bootNonceButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.BootNonceTextField setTintColor:[UIColor blackColor]];
    
    [self.BootNonceTextField setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ECIDLabel setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidDarkModeButton setTitleColor:[UIColor blackColor] forState:normal];
    
    [self.expiryDarkModeLabel setTextColor:[UIColor blackColor]];
    [self.ExpiryLabel setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.UptimeLabel setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.upTimeLabel setTextColor:[UIColor blackColor]];
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
    prefs_t *prefs = copy_prefs();
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
    [self.OpenCydiaButton setEnabled:(BOOL)cydiaIsInstalled()];
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
    [self.AutoRespringSwitch setOn:(BOOL)prefs->auto_respring];
    [self.RestartSpringBoardButton setEnabled:respringSupported()];
    [self.restartButton setEnabled:restartSupported()];
    release_prefs(&prefs);
    [self.tableView reloadData];
}

- (IBAction)selectedSpecialThanks:(id)sender {
    
    [[NSNotificationCenter defaultCenter] postNotificationName:@"showSpecialThanks" object:self];
}

- (IBAction)TweakInjectionSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->load_tweaks = (bool)self.TweakInjectionSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)LoadDaemonsSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->load_daemons = (bool)self.LoadDaemonsSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)DumpAPTicketSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->dump_apticket = (bool)self.DumpAPTicketSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)BootNonceTextFieldTriggered:(id)sender {
    uint64_t val = 0;
    if ([[NSScanner scannerWithString:[self.BootNonceTextField text]] scanHexLongLong:&val] && val != HUGE_VAL && val != -HUGE_VAL) {
        prefs_t *prefs = copy_prefs();
        prefs->boot_nonce = [NSString stringWithFormat:@ADDR, val].UTF8String;
        set_prefs(prefs);
        release_prefs(&prefs);
    } else {
        UIAlertController *const alertController = [UIAlertController alertControllerWithTitle:localize(@"Invalid Entry") message:localize(@"The boot nonce entered could not be parsed") preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *const OK = [UIAlertAction actionWithTitle:localize(@"OK") style:UIAlertActionStyleDefault handler:nil];
        [alertController addAction:OK];
        [self presentViewController:alertController animated:YES completion:nil];
    }
    [self reloadData];
}

- (IBAction)RefreshIconCacheSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->run_uicache = (bool)self.RefreshIconCacheSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)KernelExploitSegmentedControl:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->exploit = (int)self.KernelExploitSegmentedControl.selectedSegmentIndex;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)DisableAppRevokesSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->disable_app_revokes = (bool)self.DisableAppRevokesSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnRestart:(id)sender {
    void (^const block)(void) = ^(void) {
        notice(localize(@"The device will be restarted."), true, false);
        NSInteger const support = recommendedRestartSupport();
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
    prefs_t *prefs = copy_prefs();
    prefs->disable_auto_updates = (bool)self.DisableAutoUpdatesSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnShareDiagnosticsData:(id)sender {
    NSURL *const URL = [NSURL fileURLWithPath:[NSString stringWithFormat:@"%@/Documents/diagnostics.plist", NSHomeDirectory()]];
    [getDiagnostics() writeToURL:URL error:nil];
    UIActivityViewController *const activityViewController = [[UIActivityViewController alloc] initWithActivityItems:@[URL] applicationActivities:nil];
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
    prefs_t *prefs = copy_prefs();
    prefs->overwrite_boot_nonce = (bool)self.OverwriteBootNonceSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnCopyNonce:(id)sender{
    UIAlertController *const copyBootNonceAlert = [UIAlertController alertControllerWithTitle:localize(@"Copy boot nonce?") message:localize(@"Would you like to copy nonce generator to clipboard?") preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *const copyAction = [UIAlertAction actionWithTitle:localize(@"Yes") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        prefs_t *prefs = copy_prefs();
        [[UIPasteboard generalPasteboard] setString:@(prefs->boot_nonce)];
        release_prefs(&prefs);
    }];
    UIAlertAction *const noAction = [UIAlertAction actionWithTitle:localize(@"No") style:UIAlertActionStyleCancel handler:nil];
    [copyBootNonceAlert addAction:copyAction];
    [copyBootNonceAlert addAction:noAction];
    [self presentViewController:copyBootNonceAlert animated:TRUE completion:nil];
}

- (IBAction)tappedOnCopyECID:(id)sender {
    UIAlertController *const copyBootNonceAlert = [UIAlertController alertControllerWithTitle:localize(@"Copy ECID?") message:localize(@"Would you like to ECID to clipboard?") preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *const copyAction = [UIAlertAction actionWithTitle:localize(@"Yes") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        prefs_t *prefs = copy_prefs();
        [[UIPasteboard generalPasteboard] setString:hexFromInt(@(prefs->ecid).integerValue)];
        release_prefs(&prefs);
    }];
    UIAlertAction *const noAction = [UIAlertAction actionWithTitle:localize(@"No") style:UIAlertActionStyleCancel handler:nil];
    [copyBootNonceAlert addAction:copyAction];
    [copyBootNonceAlert addAction:noAction];
    [self presentViewController:copyBootNonceAlert animated:TRUE completion:nil];
}

- (IBAction)tappedOnCheckForUpdate:(id)sender {
    void (^const block)(void) = ^(void) {
        NSString *const update = [NSString stringWithContentsOfURL:[NSURL URLWithString:@"https://github.com/pwn20wndstuff/Undecimus/raw/master/Update.txt"] encoding:NSUTF8StringEncoding error:nil];
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
    prefs_t *prefs = copy_prefs();
    prefs->export_kernel_task_port = (bool)self.ExportKernelTaskPortSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)RestoreRootFSSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->restore_rootfs = (bool)self.RestoreRootFSSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)installCydiaSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->install_cydia = (bool)self.installCydiaSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)installSSHSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
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
    prefs_t *prefs = copy_prefs();
    prefs->increase_memory_limit = (bool)self.IncreaseMemoryLimitSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnAutomaticallySelectExploit:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->exploit = (int)recommendedJailbreakSupport();
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)reloadSystemDaemonsSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->reload_system_daemons = (bool)self.ReloadSystemDaemonsSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedRestartSpringBoard:(id)sender {
    void (^const block)(void) = ^(void) {
        notice(localize(@"SpringBoard will be restarted."), true, false);
        NSInteger const support = recommendedRespringSupport();
        switch (support) {
            case deja_xnu_exploit: {
                mach_port_t const bb_tp = hid_event_queue_exploit();
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
    prefs_t *prefs = copy_prefs();
    prefs->hide_log_window = (bool)self.HideLogWindowSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
    void (^const block)(void) = ^(void) {
        notice(localize(@"Preference was changed. The app will now exit."), true, false);
        exit(EXIT_SUCCESS);
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (IBAction)resetCydiaCacheSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->reset_cydia_cache = (bool)self.ResetCydiaCacheSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)sshOnlySwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->ssh_only = (bool)self.SSHOnlySwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)enableGetTaskAllowSwitchTriggered:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->enable_get_task_allow = (bool)self.EnableGetTaskAllowSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)setCSDebugged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->set_cs_debugged = (bool)self.SetCSDebuggedSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)setAutoRespring:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->auto_respring = (bool)self.AutoRespringSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnResetAppPreferences:(id)sender {
    void (^const block)(void) = ^(void) {
        reset_prefs();
        notice(localize(@"Preferences were reset. The app will now exit."), true, false);
        exit(EXIT_SUCCESS);
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 44;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
