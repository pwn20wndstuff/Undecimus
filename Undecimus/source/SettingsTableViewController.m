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
    [self.bootNonceTextField setDelegate:self];
    self.tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(userTappedAnyware:)];
    self.tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:self.tap];
}


-(void)darkModeSettings:(NSNotification *) notification  {
    [self.specialThanksLabel setTextColor:[UIColor whiteColor]];
    [self.tweakInjectionLabel setTextColor:[UIColor whiteColor]];
    [self.loadDaemonsLabel setTextColor:[UIColor whiteColor]];
    [self.dumpAPTicketLabel setTextColor:[UIColor whiteColor]];
    [self.refreshIconCacheLabel setTextColor:[UIColor whiteColor]];
    [self.disableAutoUpdatesLabel setTextColor:[UIColor whiteColor]];
    [self.disableAppRevokesLabel setTextColor:[UIColor whiteColor]];
    [self.overwriteBootNonceLabel setTextColor:[UIColor whiteColor]];
    [self.exportKernelTaskPortLabel setTextColor:[UIColor whiteColor]];
    [self.restoreRootFSLabel setTextColor:[UIColor whiteColor]];
    [self.installCydiaLabel setTextColor:[UIColor whiteColor]];
    [self.installSSHLabel setTextColor:[UIColor whiteColor]];
    [self.increaseMemoryLimitLabel setTextColor:[UIColor whiteColor]];
    [self.reloadSystemDaemonsLabel setTextColor:[UIColor whiteColor]];
    [self.hideLogWindowLabel setTextColor:[UIColor whiteColor]];
    [self.resetCydiaCacheLabel setTextColor:[UIColor whiteColor]];
    [self.sshOnlyLabel setTextColor:[UIColor whiteColor]];
    [self.enableGetTaskAllowLabel setTextColor:[UIColor whiteColor]];
    [self.setCSDebuggedLabel setTextColor:[UIColor whiteColor]];
    [self.autoRespringLabel setTextColor:[UIColor whiteColor]];
    [self.kernelExploitLabel setTextColor:[UIColor whiteColor]];
    
    [self.bootNonceButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.bootNonceTextField setTintColor:[UIColor whiteColor]];
    
    [self.bootNonceTextField setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidLabel setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidDarkModeButton setTitleColor:[UIColor whiteColor] forState:normal];
    
    [self.expiryDarkModeLabel setTextColor:[UIColor whiteColor]];
    [self.expiryLabel setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.uptimeLabel setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.upTimeLabel setTextColor:[UIColor whiteColor]];
}

-(void)lightModeSettings:(NSNotification *) notification  {
    [self.specialThanksLabel setTextColor:[UIColor blackColor]];
    [self.tweakInjectionLabel setTextColor:[UIColor blackColor]];
    [self.loadDaemonsLabel setTextColor:[UIColor blackColor]];
    [self.dumpAPTicketLabel setTextColor:[UIColor blackColor]];
    [self.refreshIconCacheLabel setTextColor:[UIColor blackColor]];
    [self.disableAutoUpdatesLabel setTextColor:[UIColor blackColor]];
    [self.disableAppRevokesLabel setTextColor:[UIColor blackColor]];
    [self.overwriteBootNonceLabel setTextColor:[UIColor blackColor]];
    [self.exportKernelTaskPortLabel setTextColor:[UIColor blackColor]];
    [self.restoreRootFSLabel setTextColor:[UIColor blackColor]];
    [self.installCydiaLabel setTextColor:[UIColor blackColor]];
    [self.installSSHLabel setTextColor:[UIColor blackColor]];
    [self.increaseMemoryLimitLabel setTextColor:[UIColor blackColor]];
    [self.reloadSystemDaemonsLabel setTextColor:[UIColor blackColor]];
    [self.hideLogWindowLabel setTextColor:[UIColor blackColor]];
    [self.resetCydiaCacheLabel setTextColor:[UIColor blackColor]];
    [self.sshOnlyLabel setTextColor:[UIColor blackColor]];
    [self.enableGetTaskAllowLabel setTextColor:[UIColor blackColor]];
    [self.setCSDebuggedLabel setTextColor:[UIColor blackColor]];
    [self.autoRespringLabel setTextColor:[UIColor blackColor]];
    [self.kernelExploitLabel setTextColor:[UIColor blackColor]];
    
    [self.bootNonceButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.bootNonceTextField setTintColor:[UIColor blackColor]];
    
    [self.bootNonceTextField setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidLabel setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidDarkModeButton setTitleColor:[UIColor blackColor] forState:normal];
    
    [self.expiryDarkModeLabel setTextColor:[UIColor blackColor]];
    [self.expiryLabel setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.uptimeLabel setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
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
    [self.tweakInjectionSwitch setOn:(BOOL)prefs->load_tweaks];
    [self.loadDaemonsSwitch setOn:(BOOL)prefs->load_daemons];
    [self.dumpAPTicketSwitch setOn:(BOOL)prefs->dump_apticket];
    [self.bootNonceTextField setPlaceholder:@(prefs->boot_nonce)];
    [self.bootNonceTextField setText:nil];
    [self.refreshIconCacheSwitch setOn:(BOOL)prefs->run_uicache];
    [self.kernelExploitSegmentedControl setSelectedSegmentIndex:(int)prefs->exploit];
    [self.disableAutoUpdatesSwitch setOn:(BOOL)prefs->disable_auto_updates];
    [self.disableAppRevokesSwitch setOn:(BOOL)prefs->disable_app_revokes];
    [self.kernelExploitSegmentedControl setEnabled:supportsExploit(empty_list_exploit) forSegmentAtIndex:empty_list_exploit];
    [self.kernelExploitSegmentedControl setEnabled:supportsExploit(multi_path_exploit) forSegmentAtIndex:multi_path_exploit];
    [self.kernelExploitSegmentedControl setEnabled:supportsExploit(async_wake_exploit) forSegmentAtIndex:async_wake_exploit];
    [self.kernelExploitSegmentedControl setEnabled:supportsExploit(voucher_swap_exploit) forSegmentAtIndex:voucher_swap_exploit];
    [self.kernelExploitSegmentedControl setEnabled:supportsExploit(mach_swap_exploit) forSegmentAtIndex:mach_swap_exploit];
    [self.kernelExploitSegmentedControl setEnabled:supportsExploit(mach_swap_2_exploit) forSegmentAtIndex:mach_swap_2_exploit];
    [self.openCydiaButton setEnabled:(BOOL)cydiaIsInstalled()];
    [self.expiryLabel setPlaceholder:[NSString stringWithFormat:@"%d %@", (int)[[SettingsTableViewController provisioningProfileAtPath:[[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"]][@"ExpirationDate"] timeIntervalSinceDate:[NSDate date]] / 86400, localize(@"Days")]];
    [self.overwriteBootNonceSwitch setOn:(BOOL)prefs->overwrite_boot_nonce];
    [self.exportKernelTaskPortSwitch setOn:(BOOL)prefs->export_kernel_task_port];
    [self.restoreRootFSSwitch setOn:(BOOL)prefs->restore_rootfs];
    [self.uptimeLabel setPlaceholder:[NSString stringWithFormat:@"%d %@", (int)getUptime() / 86400, localize(@"Days")]];
    [self.increaseMemoryLimitSwitch setOn:(BOOL)prefs->increase_memory_limit];
    [self.installSSHSwitch setOn:(BOOL)prefs->install_openssh];
    [self.installCydiaSwitch setOn:(BOOL)prefs->install_cydia];
    if (prefs->ecid) [self.ecidLabel setPlaceholder:hexFromInt([@(prefs->ecid) integerValue])];
    [self.reloadSystemDaemonsSwitch setOn:(BOOL)prefs->reload_system_daemons];
    [self.hideLogWindowSwitch setOn:(BOOL)prefs->hide_log_window];
    [self.resetCydiaCacheSwitch setOn:(BOOL)prefs->reset_cydia_cache];
    [self.sshOnlySwitch setOn:(BOOL)prefs->ssh_only];
    [self.enableGetTaskAllowSwitch setOn:(BOOL)prefs->enable_get_task_allow];
    [self.setCSDebuggedSwitch setOn:(BOOL)prefs->set_cs_debugged];
    [self.autoRespringSwitch setOn:(BOOL)prefs->auto_respring];
    [self.restartSpringBoardButton setEnabled:respringSupported()];
    [self.restartButton setEnabled:restartSupported()];
    release_prefs(&prefs);
    [self.tableView reloadData];
}

- (IBAction)selectedSpecialThanks:(id)sender {
    
    [[NSNotificationCenter defaultCenter] postNotificationName:@"showSpecialThanks" object:self];
}

- (IBAction)tweakInjectionSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->load_tweaks = (bool)self.tweakInjectionSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)loadDaemonsSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->load_daemons = (bool)self.loadDaemonsSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)dumpAPTicketSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->dump_apticket = (bool)self.dumpAPTicketSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)bootNonceTextFieldEditingDidEnd:(id)sender {
    uint64_t val = 0;
    if ([[NSScanner scannerWithString:[self.bootNonceTextField text]] scanHexLongLong:&val] && val != HUGE_VAL && val != -HUGE_VAL) {
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

- (IBAction)refreshIconCacheSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->run_uicache = (bool)self.refreshIconCacheSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)kernelExploitSegmentedControlValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->exploit = (int)self.kernelExploitSegmentedControl.selectedSegmentIndex;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)disableAppRevokesSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->disable_app_revokes = (bool)self.disableAppRevokesSwitch.isOn;
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

- (IBAction)disableAutoUpdatesSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->disable_auto_updates = (bool)self.disableAutoUpdatesSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)tappedOnShareDiagnosticsData:(id)sender {
    NSURL *const URL = [NSURL fileURLWithPath:[NSString stringWithFormat:@"%@/Documents/diagnostics.plist", NSHomeDirectory()]];
    [getDiagnostics() writeToURL:URL error:nil];
    UIActivityViewController *const activityViewController = [[UIActivityViewController alloc] initWithActivityItems:@[URL] applicationActivities:nil];
    if ([activityViewController respondsToSelector:@selector(popoverPresentationController)]) {
        [[activityViewController popoverPresentationController] setSourceView:self.shareDiagnosticsDataButton];
    }
    [self presentViewController:activityViewController animated:YES completion:nil];
}

- (IBAction)tappedOnOpenCydia:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"cydia://"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnOpenGithub:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/pwn20wndstuff/Undecimus"] options:@{} completionHandler:nil];
}

- (IBAction)overwriteBootNonceSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->overwrite_boot_nonce = (bool)self.overwriteBootNonceSwitch.isOn;
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

- (IBAction)exportKernelTaskPortSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->export_kernel_task_port = (bool)self.exportKernelTaskPortSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)restoreRootFSSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->restore_rootfs = (bool)self.restoreRootFSSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)installCydiaSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->install_cydia = (bool)self.installCydiaSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)installSSHSwitchValueChanged:(id)sender {
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

- (IBAction)increaseMemoryLimitSwitch:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->increase_memory_limit = (bool)self.increaseMemoryLimitSwitch.isOn;
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

- (IBAction)reloadSystemDaemonsSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->reload_system_daemons = (bool)self.reloadSystemDaemonsSwitch.isOn;
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

- (IBAction)hideLogWindowSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->hide_log_window = (bool)self.hideLogWindowSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
    void (^const block)(void) = ^(void) {
        notice(localize(@"Preference was changed. The app will now exit."), true, false);
        exit(EXIT_SUCCESS);
    };
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), block);
}

- (IBAction)resetCydiaCacheSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->reset_cydia_cache = (bool)self.resetCydiaCacheSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)sshOnlySwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->ssh_only = (bool)self.sshOnlySwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)enableGetTaskAllowSwitchValueChanged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->enable_get_task_allow = (bool)self.enableGetTaskAllowSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)setCSDebugged:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->set_cs_debugged = (bool)self.setCSDebuggedSwitch.isOn;
    set_prefs(prefs);
    release_prefs(&prefs);
    [self reloadData];
}

- (IBAction)setAutoRespring:(id)sender {
    prefs_t *prefs = copy_prefs();
    prefs->auto_respring = (bool)self.autoRespringSwitch.isOn;
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
