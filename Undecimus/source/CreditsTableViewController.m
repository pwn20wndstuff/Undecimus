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
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(darkModeCreditsView:) name:@"darkModeCredits" object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(lightModeCreditsView:) name:@"lightModeCredits" object:nil];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

-(void) darkModeCreditsView:(NSNotification *) notification  {
    
    [self.IanBeerButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.BazadButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.MorpheusButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.XerubButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.PsychoTeaButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.StekButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.NinjaPrawnButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.CrypticButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.XerusDesignButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.AppleDryButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.RobButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.MidnightChipButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.GeoSn0wButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.SwaggoButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.JailbreakbusterButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.JakeashacksButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.JonathanSealsButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.SaurikButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.SiguzaButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.S0rryMyBadButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.ExternalistButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.RealBrightiupButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.NitoTVButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.MatchsticButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.UmanghereButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.MiscMistyButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.BenButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.SamGButton setTitleColor:[UIColor whiteColor] forState:normal];
    [self.DennisButton setTitleColor:[UIColor whiteColor] forState:normal];
}

-(void) lightModeCreditsView:(NSNotification *) notification  {
    
    [self.IanBeerButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.BazadButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.MorpheusButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.XerubButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.PsychoTeaButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.StekButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.NinjaPrawnButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.CrypticButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.XerusDesignButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.AppleDryButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.RobButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.MidnightChipButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.GeoSn0wButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.SwaggoButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.JailbreakbusterButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.JakeashacksButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.JonathanSealsButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.SaurikButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.SiguzaButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.S0rryMyBadButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.ExternalistButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.RealBrightiupButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.NitoTVButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.MatchsticButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.UmanghereButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.MiscMistyButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.BenButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.SamGButton setTitleColor:[UIColor blackColor] forState:normal];
    [self.DennisButton setTitleColor:[UIColor blackColor] forState:normal];
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

-(IBAction)tappedOnSaurik:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"saurik"] options:@{} completionHandler:nil];
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

-(IBAction)tappedOnBen:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"benjweaverdev"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnSamG:(id)sender{
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://reddit.com/u/Samg_is_a_Ninja"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnDennis:(id)sender{
    [[UIApplication sharedApplication] openURL:[CreditsTableViewController getURLForUserName:@"DennisBednarz"] options:@{} completionHandler:nil];
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 44;
}

@end
