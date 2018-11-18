//
//  SettingsTableViewController.h
//  Undecimus
//
//  Created by Pwn20wnd on 9/14/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import <UIKit/UIKit.h>

#define K_TWEAK_INJECTION           "TweakInjection"
#define K_LOAD_DAEMONS              "LoadDaemons"
#define K_DUMP_APTICKET             "DumpAPTicket"
#define K_REFRESH_ICON_CACHE        "RefreshIconCache"
#define K_BOOT_NONCE                "BootNonce"
#define K_EXPLOIT                   "Exploit"
#define K_DISABLE_AUTO_UPDATES      "DisableAutoUpdates"
#define K_DISABLE_APP_REVOKES       "DisableAppRevokes"
#define K_OVERWRITE_BOOT_NONCE      "OverwriteBootNonce"
#define K_EXPORT_KERNEL_TASK_PORT   "ExportKernelTaskPort"
#define K_RESTORE_ROOTFS            "RestoreRootFS"
#define K_INCREASE_MEMORY_LIMIT     "IncreaseMemoryLimit"
#define K_ECID                      "Ecid"
#define K_INSTALL_OPENSSH           "InstallOpenSSH"
#define K_INSTALL_CYDIA             "InstallCydia"
#define K_RELOAD_SYSTEM_DAEMONS     "ReloadSystemDaemons"

#define LOG_FILE                    [[NSString stringWithFormat:@"%@/Documents/log_file.txt", NSHomeDirectory()] UTF8String]
#define PREFERENCES_FILE            [NSString stringWithFormat:@"%@/Library/Preferences/%@.plist", NSHomeDirectory(), [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleIdentifier"]]

#define ISDEBUGGERATTACHED()        (!(getppid() == 1))

#define START_LOGGING() do { \
    if (!ISDEBUGGERATTACHED()) { \
        freopen(LOG_FILE, "a+", stderr); \
        freopen(LOG_FILE, "a+", stdout); \
        setbuf(stdout, NULL); \
        setbuf(stderr, NULL);\
    } \
} while (false) \

#define RESET_LOGS() do { \
    if (!ISDEBUGGERATTACHED()) { \
        if (!access(LOG_FILE, F_OK)) { \
        unlink(LOG_FILE); \
        } \
    } \
} while(false) \

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

+ (NSDictionary *)_provisioningProfileAtPath:(NSString *)path;

@end

