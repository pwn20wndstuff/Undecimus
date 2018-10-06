//
//  SettingsTableViewController.h
//  Undecimus
//
//  Created by Pwn20wnd on 9/14/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>

#define K_TWEAK_INJECTION "TweakInjection"
#define K_LOAD_DAEMONS "LoadDaemons"
#define K_DUMP_APTICKET "DumpAPTicket"
#define K_REFRESH_ICON_CACHE "RefreshIconCache"
#define K_BOOT_NONCE "BootNonce"
#define K_EXPLOIT "Exploit"
#define K_DISABLE_AUTO_UPDATES "DisableAutoUpdates"
#define K_DISABLE_APP_REVOKES "DisableAppRevokes"

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

+ (NSArray *) supportedBuilds;

@end

