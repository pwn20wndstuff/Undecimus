//
//  CreditsTableViewController.m
//  Undecimus
//
//  Created by Pwn20wnd on 9/14/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

#import "CreditsTableViewController.h"

@interface CreditsTableViewController ()

@end

@implementation CreditsTableViewController

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
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

+ (NSURL *)getURLForUserName:(NSString *)userName {
    if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"tweetbot://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"tweetbot:///user_profile/%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"twitterrific://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"twitterrific:///profile?screen_name=%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"tweetings://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"tweetings:///user?screen_name=%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"twitter://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"https://mobile.twitter.com/%@", userName]];
    } else {
        return [NSURL URLWithString:[NSString stringWithFormat:@"https://mobile.twitter.com/%@", userName]];
    }
}

-(IBAction)tappedOnIanBeer:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"i41nbeer"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnBazad:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"_bazad"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnMorpheus:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"Morpheus______"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnXerub:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"xerub"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnPsychoTea:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"ibsparkes"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnStek:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"stek29"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnNinjaPrawn:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"theninjaprawn"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnCryptic:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"Cryptiiiic"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnXerusDesign:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"xerusdesign"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnAppleDry:(id)sender{
   [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"AppleDry05"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnRob:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"AyyItzRob"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnMidnightChip:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"MidnightChip"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnGeoSn0w:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"FCE365"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnSwaggo:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"Swag_iOS"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnJailbreakbuster:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"jailbreakbuster"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnJakeashacks:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"Jakeashacks"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnJonathanSeals:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"JonathanSeals"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnSaurik:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"saurik"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnUndecimusResources:(id)sender{
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/pwn20wndstuff/Undecimus-Resources"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnTihmstar:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"tihmstar"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnSiguza:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"s1guza"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnS0rryMyBad:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"S0rryMyBad"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnExternalist:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"Externalist"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnRealBrightiup:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"realBrightiup"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnNitoTV:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"nitoTV"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnMatchstic:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"_Matchstic"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnUmanghere:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"umanghere"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnMiscMisty:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"MiscMisty"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnSemaphore:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"notcom"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnLibimobiledevice:(id)sender{
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/libimobiledevice"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnCoolStar:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"coolstarorg"] options:@{} completionHandler:nil];
}


@end
