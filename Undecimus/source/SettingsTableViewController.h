//
//  SettingsTableViewController.h
//  Undecimus
//
//  Created by Pwn20wnd on 9/14/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "common.h"
#import "utils.h"

#define K_TWEAK_INJECTION          @"TweakInjection"
#define K_LOAD_DAEMONS             @"LoadDaemons"
#define K_DUMP_APTICKET            @"DumpAPTicket"
#define K_REFRESH_ICON_CACHE       @"RefreshIconCache"
#define K_BOOT_NONCE               @"BootNonce"
#define K_EXPLOIT                  @"Exploit"
#define K_DISABLE_AUTO_UPDATES     @"DisableAutoUpdates"
#define K_DISABLE_APP_REVOKES      @"DisableAppRevokes"
#define K_OVERWRITE_BOOT_NONCE     @"OverwriteBootNonce"
#define K_EXPORT_KERNEL_TASK_PORT  @"ExportKernelTaskPort"
#define K_RESTORE_ROOTFS           @"RestoreRootFS"
#define K_INCREASE_MEMORY_LIMIT    @"IncreaseMemoryLimit"
#define K_ECID                     @"Ecid"
#define K_INSTALL_OPENSSH          @"InstallOpenSSH"
#define K_INSTALL_CYDIA            @"InstallCydia"
#define K_RELOAD_SYSTEM_DAEMONS    @"ReloadSystemDaemons"
#define K_HIDE_LOG_WINDOW          @"HideLogWindow"
#define K_RESET_CYDIA_CACHE        @"ResetCydiaCache"
#define K_SSH_ONLY                 @"SSHOnly"
#define K_ENABLE_GET_TASK_ALLOW    @"EnableGetTaskAllow"
#define K_SET_CS_DEBUGGED          @"SetCSDebugged"

@interface SettingsTableViewController : UITableViewController <UITextFieldDelegate>
@property (weak, nonatomic) IBOutlet UISwitch *TweakInjectionSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *LoadDaemonsSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *DumpAPTicketSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *RefreshIconCacheSwitch;
@property (weak, nonatomic) IBOutlet UITextField *BootNonceTextField;
@property (weak, nonatomic) IBOutlet UISegmentedControl *KernelExploitSegmentedControl;
@property (weak, nonatomic) IBOutlet UIButton *restartButton;
@property (weak, nonatomic) IBOutlet UISwitch *DisableAutoUpdatesSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *DisableAppRevokesSwitch;
@property (nonatomic) UITapGestureRecognizer *tap;
@property (weak, nonatomic) IBOutlet UIButton *ShareDiagnosticsDataButton;
@property (weak, nonatomic) IBOutlet UIButton *OpenCydiaButton;
@property (weak, nonatomic) IBOutlet UITextField *ExpiryLabel;
@property (weak, nonatomic) IBOutlet UISwitch *OverwriteBootNonceSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *ExportKernelTaskPortSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *RestoreRootFSSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *installCydiaSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *installSSHSwitch;
@property (weak, nonatomic) IBOutlet UITextField *UptimeLabel;
@property (weak, nonatomic) IBOutlet UISwitch *IncreaseMemoryLimitSwitch;
@property (weak, nonatomic) IBOutlet UITextField *ECIDLabel;
@property (weak, nonatomic) IBOutlet UISwitch *ReloadSystemDaemonsSwitch;
@property (weak, nonatomic) IBOutlet UIButton *RestartSpringBoardButton;
@property (weak, nonatomic) IBOutlet UISwitch *HideLogWindowSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *ResetCydiaCacheSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *SSHOnlySwitch;
@property (weak, nonatomic) IBOutlet UISwitch *EnableGetTaskAllowSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *SetCSDebuggedSwitch;

+ (NSDictionary *)_provisioningProfileAtPath:(NSString *)path;

@end

