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
@property (weak, nonatomic) IBOutlet UISwitch *AutoRespringSwitch;

@property (weak, nonatomic) IBOutlet UILabel *specialThanksLabel;
@property (weak, nonatomic) IBOutlet UILabel *TweakInjectionLabel;
@property (weak, nonatomic) IBOutlet UILabel *LoadDaemonsLabel;
@property (weak, nonatomic) IBOutlet UILabel *DumpAPTicketLabel;
@property (weak, nonatomic) IBOutlet UILabel *RefreshIconCacheLabel;
@property (weak, nonatomic) IBOutlet UILabel *DisableAutoUpdatesLabel;
@property (weak, nonatomic) IBOutlet UILabel *DisableAppRevokesLabel;
@property (weak, nonatomic) IBOutlet UILabel *OverwriteBootNonceLabel;
@property (weak, nonatomic) IBOutlet UILabel *ExportKernelTaskPortLabel;
@property (weak, nonatomic) IBOutlet UILabel *RestoreRootFSLabel;
@property (weak, nonatomic) IBOutlet UILabel *installCydiaLabel;
@property (weak, nonatomic) IBOutlet UILabel *installSSHLabel;
@property (weak, nonatomic) IBOutlet UILabel *IncreaseMemoryLimitLabel;
@property (weak, nonatomic) IBOutlet UILabel *ReloadSystemDaemonsLabel;
@property (weak, nonatomic) IBOutlet UILabel *HideLogWindowLabel;
@property (weak, nonatomic) IBOutlet UILabel *ResetCydiaCacheLabel;
@property (weak, nonatomic) IBOutlet UILabel *SSHOnlyLabel;
@property (weak, nonatomic) IBOutlet UILabel *EnableGetTaskAllowLabel;
@property (weak, nonatomic) IBOutlet UILabel *SetCSDebuggedLabel;
@property (weak, nonatomic) IBOutlet UILabel *AutoRespringLabel;
@property (weak, nonatomic) IBOutlet UILabel *kernelExploitLabel;
@property (weak, nonatomic) IBOutlet UIButton *bootNonceButton;
@property (weak, nonatomic) IBOutlet UIButton *ecidDarkModeButton;
@property (weak, nonatomic) IBOutlet UILabel *expiryDarkModeLabel;
@property (weak, nonatomic) IBOutlet UILabel *upTimeLabel;

+ (NSDictionary *)provisioningProfileAtPath:(NSString *)path;

@end

