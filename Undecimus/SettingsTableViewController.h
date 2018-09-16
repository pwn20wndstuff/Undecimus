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

@interface SettingsTableViewController : UITableViewController <UITextFieldDelegate>
@property (weak, nonatomic) IBOutlet UISwitch *TweakInjectionSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *LoadDaemonsSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *DumpAPTicketSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *RefreshIconCacheSwitch;
@property (weak, nonatomic) IBOutlet UITextField *BootNonceTextField;
@property (weak, nonatomic) IBOutlet UISegmentedControl *KernelExploitSegmentedControl;

@end

