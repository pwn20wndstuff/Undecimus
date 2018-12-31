//
//  SettingsTableViewController.m
//  Undecimus
//
//  Created by Pwn20wnd on 9/14/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#include <sys/utsname.h>
#include <sys/sysctl.h>
#import "SettingsTableViewController.h"
#include <common.h>
#include "hideventsystem.h"
#include "remote_call.h"
#include "ViewController.h"

@interface SettingsTableViewController ()

@end

@implementation SettingsTableViewController

// https://github.com/Matchstic/ReProvision/blob/7b595c699335940f68702bb204c5aa55b8b1896f/Shared/Application%20Database/RPVApplication.m#L102

+ (NSDictionary *)_provisioningProfileAtPath:(NSString *)path {
    NSError *err;
    NSString *stringContent = [NSString stringWithContentsOfFile:path encoding:NSASCIIStringEncoding error:&err];
    stringContent = [stringContent componentsSeparatedByString:@"<plist version=\"1.0\">"][1];
    stringContent = [NSString stringWithFormat:@"%@%@", @"<plist version=\"1.0\">", stringContent];
    stringContent = [stringContent componentsSeparatedByString:@"</plist>"][0];
    stringContent = [NSString stringWithFormat:@"%@%@", stringContent, @"</plist>"];
    
    NSData *stringData = [stringContent dataUsingEncoding:NSASCIIStringEncoding];
    
    NSError *error;
    NSPropertyListFormat format;
    
    id plist = [NSPropertyListSerialization propertyListWithData:stringData options:NSPropertyListImmutable format:&format error:&error];
    
    return plist;
}

#define STATUS_FILE          @"/var/lib/dpkg/status"
#define CYDIA_LIST @"/etc/apt/sources.list.d/cydia.list"

// https://github.com/lechium/nitoTV/blob/53cca06514e79279fa89639ad05b562f7d730079/Classes/packageManagement.m#L1138

+ (NSArray *)dependencyArrayFromString:(NSString *)depends
{
    NSMutableArray *cleanArray = [[NSMutableArray alloc] init];
    NSArray *dependsArray = [depends componentsSeparatedByString:@","];
    for (id depend in dependsArray)
    {
        NSArray *spaceDelimitedArray = [depend componentsSeparatedByString:@" "];
        NSString *isolatedDependency = [[spaceDelimitedArray objectAtIndex:0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if ([isolatedDependency length] == 0)
            isolatedDependency = [[spaceDelimitedArray objectAtIndex:1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        [cleanArray addObject:isolatedDependency];
    }
    
    return cleanArray;
}

// https://github.com/lechium/nitoTV/blob/53cca06514e79279fa89639ad05b562f7d730079/Classes/packageManagement.m#L1163

+ (NSArray *)parsedPackageArray
{
    NSString *packageString = [NSString stringWithContentsOfFile:STATUS_FILE encoding:NSUTF8StringEncoding error:nil];
    NSArray *lineArray = [packageString componentsSeparatedByString:@"\n\n"];
    //NSLog(@"lineArray: %@", lineArray);
    NSMutableArray *mutableList = [[NSMutableArray alloc] init];
    //NSMutableDictionary *mutableDict = [[NSMutableDictionary alloc] init];
    for (id currentItem in lineArray)
    {
        NSArray *packageArray = [currentItem componentsSeparatedByString:@"\n"];
        //    NSLog(@"packageArray: %@", packageArray);
        NSMutableDictionary *currentPackage = [[NSMutableDictionary alloc] init];
        for (id currentLine in packageArray)
        {
            NSArray *itemArray = [currentLine componentsSeparatedByString:@": "];
            if ([itemArray count] >= 2)
            {
                NSString *key = [itemArray objectAtIndex:0];
                NSString *object = [itemArray objectAtIndex:1];
                
                if ([key isEqualToString:@"Depends"]) //process the array
                {
                    NSArray *dependsObject = [SettingsTableViewController dependencyArrayFromString:object];
                    
                    [currentPackage setObject:dependsObject forKey:key];
                    
                } else { //every other key, even if it has an array is treated as a string
                    
                    [currentPackage setObject:object forKey:key];
                }
                
                
            }
        }
        
        //NSLog(@"currentPackage: %@\n\n", currentPackage);
        if ([[currentPackage allKeys] count] > 4)
        {
            //[mutableDict setObject:currentPackage forKey:[currentPackage objectForKey:@"Package"]];
            [mutableList addObject:currentPackage];
        }
        
        currentPackage = nil;
        
    }
    
    NSSortDescriptor *nameDescriptor = [[NSSortDescriptor alloc] initWithKey:@"Name" ascending:YES
                                                                    selector:@selector(localizedCaseInsensitiveCompare:)];
    NSSortDescriptor *packageDescriptor = [[NSSortDescriptor alloc] initWithKey:@"Package" ascending:YES
                                                                       selector:@selector(localizedCaseInsensitiveCompare:)];
    NSArray *descriptors = [NSArray arrayWithObjects:nameDescriptor, packageDescriptor, nil];
    NSArray *sortedArray = [mutableList sortedArrayUsingDescriptors:descriptors];
    
    mutableList = nil;
    
    return sortedArray;
}

// https://github.com/lechium/nitoTV/blob/53cca06514e79279fa89639ad05b562f7d730079/Classes/packageManagement.m#L854

+ (NSString *)domainFromRepoObject:(NSString *)repoObject
{
    //LogSelf;
    if ([repoObject length] == 0)return nil;
    NSArray *sourceObjectArray = [repoObject componentsSeparatedByString:@" "];
    NSString *url = [sourceObjectArray objectAtIndex:1];
    if ([url length] > 7)
    {
        NSString *urlClean = [url substringFromIndex:7];
        NSArray *secondArray = [urlClean componentsSeparatedByString:@"/"];
        return [secondArray objectAtIndex:0];
    }
    return nil;
}

// https://github.com/lechium/nitoTV/blob/53cca06514e79279fa89639ad05b562f7d730079/Classes/packageManagement.m#L869

+ (NSArray *)sourcesFromFile:(NSString *)theSourceFile
{
    NSMutableArray *finalArray = [[NSMutableArray alloc] init];
    NSString *sourceString = [[NSString stringWithContentsOfFile:theSourceFile encoding:NSASCIIStringEncoding error:nil] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSArray *sourceFullArray =  [sourceString componentsSeparatedByString:@"\n"];
    NSEnumerator *sourceEnum = [sourceFullArray objectEnumerator];
    id currentSource = nil;
    while (currentSource = [sourceEnum nextObject])
    {
        NSString *theObject = [SettingsTableViewController domainFromRepoObject:currentSource];
        if (theObject != nil)
        {
            if (![finalArray containsObject:theObject])
                [finalArray addObject:theObject];
        }
    }
    
    return finalArray;
}

+ (NSDictionary *)getDiagnostics {
    struct utsname u = { 0 };
    NSMutableDictionary *md = nil;
    uname(&u);
    md = [[NSMutableDictionary alloc] init];
    md[@"Sysname"] = [NSString stringWithUTF8String:u.sysname];
    md[@"Nodename"] = [NSString stringWithUTF8String:u.nodename];
    md[@"Release"] = [NSString stringWithUTF8String:u.release];
    md[@"Version"] = [NSString stringWithUTF8String:u.version];
    md[@"Machine"] = [NSString stringWithUTF8String:u.machine];
    md[@"ProductVersion"] = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"][@"ProductVersion"];
    md[@"ProductBuildVersion"] = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"][@"ProductBuildVersion"];
    md[@"Sources"] = [SettingsTableViewController sourcesFromFile:CYDIA_LIST];
    md[@"Packages"] = [SettingsTableViewController parsedPackageArray];
    md[@"Preferences"] = [[NSMutableDictionary alloc] init];
    md[@"Preferences"][@"TweakInjection"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_TWEAK_INJECTION];
    md[@"Preferences"][@"LoadDaemons"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_LOAD_DAEMONS];
    md[@"Preferences"][@"DumpAPTicket"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_DUMP_APTICKET];
    md[@"Preferences"][@"RefreshIconCache"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_REFRESH_ICON_CACHE];
    md[@"Preferences"][@"BootNonce"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE];
    md[@"Preferences"][@"Exploit"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_EXPLOIT];
    md[@"Preferences"][@"DisableAutoUpdates"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_DISABLE_AUTO_UPDATES];
    md[@"Preferences"][@"DisableAppRevokes"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_DISABLE_APP_REVOKES];
    md[@"Preferences"][@"OverwriteBootNonce"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_OVERWRITE_BOOT_NONCE];
    md[@"Preferences"][@"ExportKernelTaskPort"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_EXPORT_KERNEL_TASK_PORT];
    md[@"Preferences"][@"RestoreRootFS"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_RESTORE_ROOTFS];
    md[@"Preferences"][@"IncreaseMemoryLimit"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_INCREASE_MEMORY_LIMIT];
    md[@"Preferences"][@"InstallCydia"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_INSTALL_CYDIA];
    md[@"Preferences"][@"InstallOpenSSH"] = [[NSUserDefaults standardUserDefaults] objectForKey:@K_INSTALL_OPENSSH];
    md[@"AppVersion"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    md[@"LogFile"] = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:LOG_FILE] encoding:NSUTF8StringEncoding error:nil];
    return md;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    UIImageView *myImageView = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"Clouds"]];
    [myImageView setContentMode:UIViewContentModeScaleAspectFill];
    [myImageView setFrame:self.tableView.frame];
    UIView *myView = [[UIView alloc] initWithFrame:myImageView.frame];
    [myView setBackgroundColor:[UIColor whiteColor]];
    [myView setAlpha:0.84];
    [myView setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
    [myImageView addSubview:myView];
    [self.tableView setBackgroundView:myImageView];
    [self.BootNonceTextField setDelegate:self];
    self.tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(userTappedAnyware:)];
    self.tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:self.tap];
    [self reloadData];
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
    [self.TweakInjectionSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_TWEAK_INJECTION]];
    [self.LoadDaemonsSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_LOAD_DAEMONS]];
    [self.DumpAPTicketSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_DUMP_APTICKET]];
    [self.BootNonceTextField setPlaceholder:[[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE]];
    [self.BootNonceTextField setText:nil];
    [self.RefreshIconCacheSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_REFRESH_ICON_CACHE]];
    [self.KernelExploitSegmentedControl setSelectedSegmentIndex:[[NSUserDefaults standardUserDefaults] integerForKey:@K_EXPLOIT]];
    [self.DisableAutoUpdatesSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_DISABLE_AUTO_UPDATES]];
    [self.DisableAppRevokesSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_DISABLE_APP_REVOKES]];
    [self.KernelExploitSegmentedControl setEnabled:isSupportedByExploit(EMPTY_LIST) forSegmentAtIndex:0];
    [self.KernelExploitSegmentedControl setEnabled:isSupportedByExploit(MULTI_PATH) && hasMPTCP() forSegmentAtIndex:1];
    [self.KernelExploitSegmentedControl setEnabled:isSupportedByExploit(ASYNC_WAKE) forSegmentAtIndex:2];
    [self.OpenCydiaButton setEnabled:[[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://"]]];
    [self.ExpiryLabel setPlaceholder:[NSString stringWithFormat:@"%d %@", (int)[[SettingsTableViewController _provisioningProfileAtPath:[[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"]][@"ExpirationDate"] timeIntervalSinceDate:[NSDate date]] / 86400, NSLocalizedString(@"Days", nil)]];
    [self.OverwriteBootNonceSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_OVERWRITE_BOOT_NONCE]];
    [self.ExportKernelTaskPortSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_EXPORT_KERNEL_TASK_PORT]];
    [self.RestoreRootFSSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_RESTORE_ROOTFS]];
    [self.UptimeLabel setPlaceholder:[NSString stringWithFormat:@"%d %@", (int)uptime() / 86400, NSLocalizedString(@"Days", nil)]];
    [self.IncreaseMemoryLimitSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_INCREASE_MEMORY_LIMIT]];
    [self.installSSHSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_INSTALL_OPENSSH]];
    [self.installCydiaSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_INSTALL_CYDIA]];
    [self.ECIDLabel setPlaceholder:hexFromInt([[[NSUserDefaults standardUserDefaults] objectForKey:@K_ECID] integerValue])];
    [self.ReloadSystemDaemonsSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:@K_RELOAD_SYSTEM_DAEMONS]];
    [self.RestartSpringBoardButton setEnabled:isSupportedByRespring()];
    [self.restartButton setEnabled:isSupportedByRestart()];
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
    if ([[NSScanner scannerWithString:[self.BootNonceTextField text]] scanHexLongLong:&val] && val != HUGE_VAL && val != -HUGE_VAL) {
        [[NSUserDefaults standardUserDefaults] setObject:[NSString stringWithFormat:@ADDR, val] forKey:@K_BOOT_NONCE];
        [[NSUserDefaults standardUserDefaults] synchronize];
    } else {
        UIAlertController *alertController = [UIAlertController alertControllerWithTitle:NSLocalizedString(@"Invalid Entry", nil) message:NSLocalizedString(@"The boot nonce entered could not be parsed", nil) preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *OK = [UIAlertAction actionWithTitle:NSLocalizedString(@"OK", nil) style:UIAlertActionStyleDefault handler:nil];
        [alertController addAction:OK];
        [self presentViewController:alertController animated:YES completion:nil];
    }
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

- (IBAction)DisableAppRevokesSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.DisableAppRevokesSwitch isOn] forKey:@K_DISABLE_APP_REVOKES];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)tappedOnRestart:(id)sender {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        NOTICE(NSLocalizedString(@"The device will be restarted.", nil), true, false);
        crashKernel();
    });
}

- (IBAction)DisableAutoUpdatesSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.DisableAutoUpdatesSwitch isOn] forKey:@K_DISABLE_AUTO_UPDATES];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)tappedOnShareDiagnosticsData:(id)sender {
    NSURL *URL = [NSURL fileURLWithPath:[NSString stringWithFormat:@"%@/Documents/diagnostics.plist", NSHomeDirectory()]];
    [[SettingsTableViewController getDiagnostics] writeToURL:URL error:nil];
    UIActivityViewController *activityViewController = [[UIActivityViewController alloc] initWithActivityItems:@[URL] applicationActivities:nil];
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
    [[NSUserDefaults standardUserDefaults] setBool:[self.OverwriteBootNonceSwitch isOn] forKey:@K_OVERWRITE_BOOT_NONCE];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)tappedOnCopyNonce:(id)sender{
    UIAlertController *copyBootNonceAlert = [UIAlertController alertControllerWithTitle:NSLocalizedString(@"Copy boot nonce?", nil) message:NSLocalizedString(@"Would you like to copy nonce generator to clipboard?", nil) preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *copyAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"Yes", nil) style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [[UIPasteboard generalPasteboard] setString:[[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE]];
    }];
    UIAlertAction *noAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"No", nil) style:UIAlertActionStyleCancel handler:nil];
    [copyBootNonceAlert addAction:copyAction];
    [copyBootNonceAlert addAction:noAction];
    [self presentViewController:copyBootNonceAlert animated:TRUE completion:nil];
}

- (IBAction)tappedOnCopyECID:(id)sender {
    UIAlertController *copyBootNonceAlert = [UIAlertController alertControllerWithTitle:NSLocalizedString(@"Copy ECID?", nil) message:NSLocalizedString(@"Would you like to ECID to clipboard?", nil) preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *copyAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"Yes", nil) style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        [[UIPasteboard generalPasteboard] setString:hexFromInt([[[NSUserDefaults standardUserDefaults] objectForKey:@K_ECID] integerValue])];
    }];
    UIAlertAction *noAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"No", nil) style:UIAlertActionStyleCancel handler:nil];
    [copyBootNonceAlert addAction:copyAction];
    [copyBootNonceAlert addAction:noAction];
    [self presentViewController:copyBootNonceAlert animated:TRUE completion:nil];
}

- (IBAction)tappedOnGetTechnicalSupport:(id)sender {
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://discord.gg/jb"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnCheckForUpdate:(id)sender {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        NSString *Update = [NSString stringWithContentsOfURL:[NSURL URLWithString:@"https://github.com/pwn20wndstuff/Undecimus/raw/master/Update.txt"] encoding:NSUTF8StringEncoding error:nil];
        if (Update == nil) {
            NOTICE(NSLocalizedString(@"Failed to check for update.", nil), true, false);
        } else if ([Update compare:[[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] options:NSNumericSearch] == NSOrderedDescending) {
            NOTICE(NSLocalizedString(@"An update is available.", nil), true, false);
        } else {
            NOTICE(NSLocalizedString(@"Already up to date.", nil), true, false);
        }
    });
}

- (IBAction)exportKernelTaskPortSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.ExportKernelTaskPortSwitch isOn] forKey:@K_EXPORT_KERNEL_TASK_PORT];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}
- (IBAction)RestoreRootFSSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.RestoreRootFSSwitch isOn] forKey:@K_RESTORE_ROOTFS];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)installCydiaSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.installCydiaSwitch isOn] forKey:@K_INSTALL_CYDIA];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)installSSHSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.installSSHSwitch isOn] forKey:@K_INSTALL_OPENSSH];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (void)tableView:(UITableView *)tableView willDisplayFooterView:(UITableViewHeaderFooterView *)footerView forSection:(NSInteger)section {
    footerView.textLabel.textAlignment = NSTextAlignmentCenter;
}

- (IBAction)IncreaseMemoryLimitSwitch:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.IncreaseMemoryLimitSwitch isOn] forKey:@K_INCREASE_MEMORY_LIMIT];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)tappedOnAutomaticallySelectExploit:(id)sender {
    [[NSUserDefaults standardUserDefaults] setInteger:selectJailbreakExploit() forKey:@K_EXPLOIT];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)reloadSystemDaemonsSwitchTriggered:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[self.ReloadSystemDaemonsSwitch isOn] forKey:@K_RELOAD_SYSTEM_DAEMONS];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadData];
}

- (IBAction)tappedRestartSpringBoard:(id)sender {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        SETMESSAGE(NSLocalizedString(@"Failed to restart SpringBoard.", nil));
        NOTICE(NSLocalizedString(@"SpringBoard will be restarted.", nil), true, false);
        switch (selectRespringExploit()) {
            case DEJA_XNU: {
                mach_port_t bb_tp = hid_event_queue_exploit();
                _assert(MACH_PORT_VALID(bb_tp), message, true);
                _assert(thread_call_remote(bb_tp, exit, 1, REMOTE_LITERAL(0)) == 0, message, true);
                break;
            }
            default:
                break;
        }
    });
}

- (IBAction)tappedOnCleanDiagnosticsData:(id)sender {
    RESET_LOGS();
    START_LOGGING();
    NOTICE(@"Cleaned diagnostics data.", false, false);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
