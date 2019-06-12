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
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(dismissKeyboardFromDoneButton:) name:@"dismissKeyboard" object:nil];
    [self.bootNonceTextField setDelegate:self];
    [self.bootNonceTextField setAutocorrectionType:UITextAutocorrectionTypeNo];
    [self.kernelExploitTextField setDelegate:self];
    self.tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(userTappedAnyware:)];
    self.tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:self.tap];
    self.exploitPickerArray = [NSMutableArray new];
    self.availableExploits = [NSMutableDictionary new];
    for (size_t i = 0; exploit_infos[i]; i++) {
        if (exploit_infos[i]->exploit_capability != jailbreak_capability) {
            continue;
        }
        [_exploitPickerArray addObject:@(exploit_infos[i]->name)];
        if (!checkDeviceSupport(exploit_infos[i]->device_support_info)) {
            continue;
        }
        [_availableExploits addEntriesFromDictionary:@{@(exploit_infos[i]->name) : @(exploit_infos[i]->exploit)}];
    }
    self.substitutorPickerArray = [NSMutableArray new];
    self.availableSubstitutors = [NSMutableDictionary new];
    for (size_t i = 0; substitutor_infos[i]; i++) {
        [_substitutorPickerArray addObject:@(substitutor_infos[i]->name)];
        if (!checkDeviceSupport(substitutor_infos[i]->device_support_info)) {
            continue;
        }
        [_availableSubstitutors addEntriesFromDictionary:@{@(substitutor_infos[i]->name) : @(substitutor_infos[i]->substitutor)}];
    }
    self.kernelExploitPickerView = [[UIPickerView alloc] init];
    [self.kernelExploitPickerView setDataSource:self];
    [self.kernelExploitPickerView setDelegate:self];
    self.codeSubstitutorPickerView = [[UIPickerView alloc] init];
    [self.codeSubstitutorPickerView setDataSource:self];
    [self.codeSubstitutorPickerView setDelegate:self];
    [self.kernelExploitTextField setInputView:_kernelExploitPickerView];
    [self.codeSubstitutorTextField setInputView:_codeSubstitutorPickerView];
    self.exploitPickerToolbar = [[UIToolbar alloc] initWithFrame:CGRectMake(0, 0, 320, 56)];
    [self.exploitPickerToolbar setBarStyle:UIBarStyleDefault];
    [self.exploitPickerToolbar sizeToFit];
    self.substitutorPickerToolbar = [[UIToolbar alloc] initWithFrame:CGRectMake(0, 0, 320, 56)];
    [self.substitutorPickerToolbar setBarStyle:UIBarStyleDefault];
    [self.substitutorPickerToolbar sizeToFit];
    UIBarButtonItem *exploitPickerAlignRight = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:self action:nil];
    UIBarButtonItem *exploitPickerDoneButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(exploitPickerDoneAction)];
    [self.exploitPickerToolbar setItems:[NSArray arrayWithObjects:exploitPickerAlignRight, exploitPickerDoneButtonItem, nil] animated:NO];
    [self.kernelExploitTextField setInputAccessoryView:_exploitPickerToolbar];
    UIBarButtonItem *substitutorPickerAlignRight = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:self action:nil];
    UIBarButtonItem *substitutorPickerDoneButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(substitutorPickerDoneAction)];
    [self.substitutorPickerToolbar setItems:[NSArray arrayWithObjects:substitutorPickerAlignRight, substitutorPickerDoneButtonItem, nil] animated:NO];
    [self.codeSubstitutorTextField setInputAccessoryView:_substitutorPickerToolbar];
    self.isPicking = NO;
}

-(void)dismissKeyboardFromDoneButton:(NSNotification *) notification {
    [self.view endEditing:YES];
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
    [self.codeSubstitutorLabel setTextColor:[UIColor whiteColor]];
    [self.bootNonceButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.bootNonceTextField setTintColor:[UIColor whiteColor]];
    [self.bootNonceTextField setTextColor:[UIColor whiteColor]];
    [self.kernelExploitTextField setTintColor:[UIColor whiteColor]];
    [self.codeSubstitutorTextField setTintColor:[UIColor whiteColor]];
    [self.bootNonceTextField setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.kernelExploitTextField setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.codeSubstitutorTextField setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidLabel setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidDarkModeButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.expiryDarkModeLabel setTextColor:[UIColor whiteColor]];
    [self.expiryLabel setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.uptimeLabel setValue:[UIColor darkGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.upTimeLabel setTextColor:[UIColor whiteColor]];
    [self.exploitPickerToolbar setBarTintColor:[UIColor darkTextColor]];
    [self.substitutorPickerToolbar setBarTintColor:[UIColor darkTextColor]];
    [self.kernelExploitPickerView setBackgroundColor:[UIColor blackColor]];
    [self.codeSubstitutorPickerView setBackgroundColor:[UIColor blackColor]];
    [JailbreakViewController.sharedController.navigationController.navigationBar setLargeTitleTextAttributes:@{ NSForegroundColorAttributeName : [UIColor whiteColor] }];
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
    [self.codeSubstitutorLabel setTextColor:[UIColor blackColor]];
    [self.bootNonceButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.bootNonceTextField setTintColor:[UIColor blackColor]];
    [self.bootNonceTextField setTextColor:[UIColor blackColor]];
    [self.kernelExploitTextField setTintColor:[UIColor blackColor]];
    [self.codeSubstitutorTextField setTintColor:[UIColor blackColor]];
    [self.bootNonceTextField setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.kernelExploitTextField setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.codeSubstitutorTextField setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidLabel setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.ecidDarkModeButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.expiryDarkModeLabel setTextColor:[UIColor blackColor]];
    [self.expiryLabel setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.uptimeLabel setValue:[UIColor lightGrayColor] forKeyPath:@"_placeholderLabel.textColor"];
    [self.upTimeLabel setTextColor:[UIColor blackColor]];
    [self.exploitPickerToolbar setBarTintColor:[UIColor lightTextColor]];
    [self.substitutorPickerToolbar setBarTintColor:[UIColor lightTextColor]];
    [self.kernelExploitPickerView setBackgroundColor:[UIColor whiteColor]];
    [self.codeSubstitutorPickerView setBackgroundColor:[UIColor whiteColor]];
    [JailbreakViewController.sharedController.navigationController.navigationBar setLargeTitleTextAttributes:@{ NSForegroundColorAttributeName : [UIColor blackColor] }];
}

- (void)userTappedAnyware:(UITapGestureRecognizer *) sender
{
    if (!self.isPicking){
        [self.view endEditing:YES];
    }
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
    [self.disableAutoUpdatesSwitch setOn:(BOOL)prefs->disable_auto_updates];
    [self.disableAppRevokesSwitch setOn:(BOOL)prefs->disable_app_revokes];
    [self.kernelExploitTextField setText:nil];
    @try {
        [self.kernelExploitTextField setPlaceholder:[_exploitPickerArray objectAtIndex:(int)prefs->exploit]];
    } @catch (__unused NSException *exception) {
        [self.kernelExploitTextField setPlaceholder:localize(@"Unavailable")];
        [self.kernelExploitTextField setEnabled:NO];
    }
    [self.codeSubstitutorTextField setText:nil];
    @try {
        [self.codeSubstitutorTextField setPlaceholder:[_substitutorPickerArray objectAtIndex:(int)prefs->code_substitutor]];
    } @catch (__unused NSException *exception) {
        [self.codeSubstitutorTextField setPlaceholder:localize(@"Unavailable")];
        [self.codeSubstitutorTextField setEnabled:NO];
    }
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
    [JailbreakViewController.sharedController updateStatus];
    [self.tableView reloadData];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    
    if (indexPath.row == 0) {
        [[NSNotificationCenter defaultCenter] postNotificationName:@"showSpecialThanks" object:self];
    }
    
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
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

- (NSInteger)numberOfComponentsInPickerView:(UIPickerView *)pickerView {
    return 1;
}

- (NSInteger)pickerView:(UIPickerView *)pickerView numberOfRowsInComponent:(NSInteger)component {
    NSInteger count = 0;
    if (pickerView == _kernelExploitPickerView) {
        count = [self.availableExploits count];
    } else if (pickerView == _codeSubstitutorPickerView) {
        count = [self.availableSubstitutors count];
    }
    return count;
}

- (NSString *)pickerView:(UIPickerView *)pickerView titleForRow:(NSInteger)row forComponent:(NSInteger)component {
    NSString *title = nil;
    if (pickerView == _kernelExploitPickerView) {
        title = [[self.availableExploits allKeys] objectAtIndex:row];
    } else if (pickerView == _codeSubstitutorPickerView) {
        title = [[self.availableSubstitutors allKeys] objectAtIndex:row];
    }
    return title;
}

- (NSAttributedString *)pickerView:(UIPickerView *)pickerView attributedTitleForRow:(NSInteger)row forComponent:(NSInteger)component {
    NSString *title = nil;
    if (pickerView == _kernelExploitPickerView) {
        title = [self.availableExploits.allKeys objectAtIndex:row];
    } else if (pickerView == _codeSubstitutorPickerView) {
        title = [self.availableSubstitutors.allKeys objectAtIndex:row];
    }
    if (title == nil) {
        return nil;
    }
    prefs_t *prefs = copy_prefs();
    NSDictionary *attributes = @{NSForegroundColorAttributeName : prefs->dark_mode ? [UIColor whiteColor] : [UIColor blackColor] };
    release_prefs(&prefs);
    NSAttributedString *attributedString = [[NSAttributedString alloc] initWithString:title attributes:attributes];
    return attributedString;
}

- (void)pickerView:(UIPickerView *)pickerView didSelectRow:(NSInteger)row inComponent:(NSInteger)component {
    self.isPicking = YES;
}

- (void)exploitPickerDoneAction {
    self.isPicking = NO;
    prefs_t *prefs = copy_prefs();
    prefs->exploit = [[_availableExploits objectForKey:[[_availableExploits allKeys] objectAtIndex:[[self kernelExploitPickerView] selectedRowInComponent:0]]] intValue];
    set_prefs(prefs);
    release_prefs(&prefs);
    [[self kernelExploitTextField] resignFirstResponder];
    [self reloadData];
}

- (void)substitutorPickerDoneAction {
    self.isPicking = NO;
    prefs_t *prefs = copy_prefs();
    prefs->code_substitutor = [[_availableSubstitutors objectForKey:[[_availableSubstitutors allKeys] objectAtIndex:[[self codeSubstitutorPickerView] selectedRowInComponent:0]]] intValue];
    set_prefs(prefs);
    release_prefs(&prefs);
    [[self codeSubstitutorTextField] resignFirstResponder];
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
    UIAlertController *const copyBootNonceAlert = [UIAlertController alertControllerWithTitle:localize(@"Copy ECID?") message:localize(@"Would you like to copy ECID to clipboard?") preferredStyle:UIAlertControllerStyleAlert];
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

- (IBAction)tappedOnLoadTweaksInfoButton:(id)sender {
    showAlert(localize(@"Load Tweaks"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes Substrate load extensions that are commonly referred to as tweaks in newly started processes."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64 SoCs (A7-A11)."),
              false,
              false);
}

- (IBAction)tappedOnLoadDaemonsInfoButton:(id)sender {
    showAlert(localize(@"Load Daemons"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak load the launch daemons located at /Library/LaunchDaemons and execute files located at /etc/rc.d."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64/arm64e SoCs (A7-A12X)."),
              false,
              false);
}

- (IBAction)tappedOnDumpAPTicketInfoButton:(id)sender {
    showAlert(localize(@"Dump APTicket"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak create a copy of the system APTicket located at /System/Library/Caches/apticket.der at its Documents directory which is accessible via iTunes File Sharing."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64/arm64e SoCs (A7-A12X)."),
              false,
              false);
}

- (IBAction)tappedOnRefreshIconCacheInfoButton:(id)sender {
    showAlert(localize(@"Refresh Icon Cache"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak regenerate SpringBoard's system application installation cache to cause newly installed .app bundles to appear on the icon list."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64/arm64e SoCs (A7-A12X)."),
              false,
              false);
}

- (IBAction)tappedOnDisableAutoUpdatesInfoButton:(id)sender {
    showAlert(localize(@"Disable Updates"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak effectively disable the system's software update mechanism to prevent the system from automatically upgrading to the latest available firmware which may not be supported by the jailbreak at that time."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64/arm64e SoCs (A7-A12X)."),
              false,
              false);
}

- (IBAction)tappedOnDisableAppRevokesInfoButton:(id)sender {
    showAlert(localize(@"Disable Revokes"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak effectively disable the system's online certificate status protocol system to prevent enterprise certificates which the jailbreak may be signed with from getting revoked."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-11.4.1 on arm64 SoCs (A7-A11)."),
              false,
              false);
}

- (IBAction)tappedOnOverwriteBootNonceInfoButton:(id)sender {
    showAlert(localize(@"Set Boot Nonce"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak set the persistent com.apple.System.boot-nonce variable in non-volatile random-access memory (NVRAM) which may be required to downgrade to an unsigned iOS firmware by using SHSH files."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64/arm64e SoCs (A7-A12X)."),
              false,
              false);
}

- (IBAction)tappedOnExportKernelTaskPortInfoButton:(id)sender {
    showAlert(localize(@"Export TFP0"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak modify the host-port to grant any process access to the host-priv-port."
                       "\n"
                       "This option effectively grants any process access to the kernel task port (TFP0) and allows re-jailbreaking without exploiting again."
                       "\n"
                       "This option is considered unsafe as the privilege this option effectively grants to processes can be used for bad purposes by malicous apps."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64/arm64e SoCs (A7-A12X)."),
              false,
              false);
}

- (IBAction)tappedOnRestoreRootFSInfoButton:(id)sender {
    showAlert(localize(@"Restore RootFS"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak restore the root filesystem (RootFS) to the snapshot which is created by the system when the device is restored."
                       "\n"
                       "This option effectively allows uninstalling the jailbreak without losing any user data."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64/arm64e SoCs (A7-A12X)."),
              false,
              false);
}

- (IBAction)tappedOnIncreaseMemoryLimitInfoButton:(id)sender {
    showAlert(localize(@"Max Memory Limit"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak modify the Jetsam configuration file to increase the memory limit that is enforced upon processes by Jetsam to the maximum value to effectively bypass that mechanism."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64 SoCs (A7-A11)."),
              false,
              false);
}

- (IBAction)tappedOnInstallSSHInfoButton:(id)sender {
    showAlert(localize(@"(Re)Install OpenSSH"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak (re)install the openssh package."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64 SoCs (A7-A11)."),
              false,
              false);
}

- (IBAction)tappedOnInstallCydiaInfoButton:(id)sender {
    showAlert(localize(@"Reinstall Cydia"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes jailbreak reinstall the cydiainstaller package."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64 SoCs (A7-A11)."),
              false,
              false);
}

- (IBAction)tappedOnReloadSystemDaemonsInfoButton:(id)sender {
    showAlert(localize(@"Reload Daemons"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak reload all of the running system daemons to make the Substrate extensions (tweaks) load in them."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64 SoCs (A7-A11)."),
              false,
              false);
}

- (IBAction)tappedOnHideLogWindowInfoButton:(id)sender {
    showAlert(localize(@"Hide Log Window"),
              localize(@"Description:"
                       "\n\n"
                       "This option hides the log window or console in the jailbreak app for a more clean look."),
              false,
              false);
}

- (IBAction)tappedOnResetCydiaCacheInfoButton:(id)sender {
    showAlert(localize(@"Reset Cydia Cache"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak reset Cydia's cache."
                       "\n"
                       "This option will cause Cydia to regenerate the repo lists and its cache."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64 SoCs (A7-A11)."),
              false,
              false);
}

- (IBAction)tappedOnSSHOnlyInfoButton:(id)sender {
    showAlert(localize(@"SSH Only"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak skip installing Cydia and Substrate."
                       "\n"
                       "This option starts SSH on 127.0.0.1 (localhost) on port 22 via dropbear."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64/arm64e SoCs (A7-A12X)."),
              false,
              false);
}

- (IBAction)tappedOnEnableGetTaskAllowInfoButton:(id)sender {
    showAlert(localize(@"Set get-task-allow"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak dynamically enable the get-task-allow entitlement for every new process."
                       "\n"
                       "This option makes dyld treat the processes unrestricted."
                       "\n"
                       "This option enables dyld environment variables such as DYLD_INSERT_LIBRARIES."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64 SoCs (A7-A11)."),
              false,
              false);
}
- (IBAction)tappedOnCSDebuggedInfoButton:(id)sender {
    showAlert(localize(@"Set CS_DEBUGGED"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak dynamically set the CS_DEBUGGED codesign flag for every new process."
                       "\n"
                       "This option makes the kernel allow processes to run with invalid executable pages."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64 SoCs (A7-A11)."),
              false,
              false);
}
- (IBAction)tappedOnAutoRespringInfoButton:(id)sender {
    showAlert(localize(@"Auto Respring"),
              localize(@"Description:"
                       "\n\n"
                       "This option makes the jailbreak automatically restart the SpringBoard as soon as the jailbreak process is completed without the confirmation."
                       "\n\n"
                       "Compatibility:"
                       "\n\n"
                       "iOS 11.0-12.1.2 on arm64 SoCs (A7-A11)."),
              false,
              false);
}


- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 44;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
