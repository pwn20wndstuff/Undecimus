//
//  CreditsTableViewController.m
//  Undecimus
//
//  Created by Pwn20wnd on 9/14/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
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

+ (NSURL *)openTwitterProfileForUsername:(NSString *)userName {
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

+ (NSURL *)openRedditProfileForUsername:(NSString *)userName {
    if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"apollo://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"apollo://www.reddit.com/u/%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"reddit://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"reddit:///u/%@", userName]];
    } else {
        return [NSURL URLWithString:[NSString stringWithFormat:@"https://reddit.com/u/%@", userName]];
    }
}

-(IBAction)tappedPwn:(id)sender {
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"pwn20wnd"] options:@{} completionHandler:nil];
}

-(IBAction)tappedBing:(id)sender {
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"sbingner"] options:@{} completionHandler:nil];
}

-(IBAction)tappedDennis:(id)sender {
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"DennisBednarz"] options:@{} completionHandler:nil];
}

-(IBAction)tappedSamg:(id)sender {
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openRedditProfileForUsername:@"Samg_is_a_ninja"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnIanBeer:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"i41nbeer"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnMorpheus:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"morpheus______"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnXerub:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"xerub"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnPsychoTea:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"ibsparkes"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnStek:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"stek29"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnNinjaPrawn:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"theninjaprawn"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnCryptic:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"Cryptiiiic"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnXerusDesign:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"xerusdesign"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnAppleDry:(id)sender{
   [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"AppleDry05"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnRob:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"Rob_Coleman123"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnMidnightChip:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"MidnightChip"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnGeoSn0w:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"FCE365"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnSwaggo:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"Swag_iOS"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnJailbreakbuster:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"jailbreakbuster"] options:@{} completionHandler:nil];
}

-(IBAction)tappedOnJakeashacks:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController openTwitterProfileForUsername:@"Jakeashacks"] options:@{} completionHandler:nil];
}
@end
