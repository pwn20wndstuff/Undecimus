# unc0ver
### The most advanced jailbreak tool
![unc0ver logo](https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Undecimus/Assets.xcassets/AppIcon.appiconset/Icon-App-60x60%403x.png?token=AlyO4xDujoguob2DCFfUbNI8jO82OyCgks5bx5ZPwA%3D%3D)

unc0ver jailbreak for iOS 11.0 - 11.4b3<br/>
by [@pwn20wnd](https://twitter.com/Pwn20wnd) & [@sbingner](https://twitter.com/sbingner)<br/>
UI by [@DennisBednarz](https://twitter.com/DennisBednarz) & [Samg_is_a_Ninja](https://reddit.com/u/Samg_is_a_Ninja)<br/>

## The most outstanding changes over the other jailbreaks
* All exploits in same app
* Detailed error messages
* Faster patches
* More stable patches
* No extra battery drain
* No random freezes
* No random slow downs
* No data is logged or shared
* No malware
* Proper jailbreak state detection
* Proper bootstrap extraction to fix issues such as Cydia not appearing after jailbreak
* Native build of Cydia for iOS 11
* Telesphoreo port for ARM64
* Much faster Cydia
* Much more stable Cydia
* Much more modern looking and acting Cydia
* Cydia skips uicache when not needed
* Cydia supports iPhone X screen size
* Cydia Substrate for tweak injection
* Much faster ldrestart 
* Much more stable ldrestart
* Changes to Cydia were made with permission from Saurik 
* Option to skip loading daemons
* Option to dump APTicket
* Option to refresh icon cache
* Option to disable auto updates
* Option to block app revokes
* Option to restore RootFS
* Button to restart device
* Button to open Cydia in case it doesn't appear on the Home Screen
* Label to show the days left till the application expires
* Working debugserver
* An awesome UI

## Switching from the other jailbreaks
* The RootFS will automatically be restored

## Getting support
* Use the built-in diagnostics tool
* Tweet [@pwn20wnd](https://twitter.com/Pwn20wnd)

## Best practices
* Perform a full restore with Rollectra before switching from the other jailbreaks
* Turn on the AirPlane Mode before starting the jailbreak
* Turn off Siri before starting the jailbreak

## Source code
* This project is completely open source and it will be kept like it in the future
* Any kind of contribution is welcome
* The source code can be found on [pwn20wndstuff](https://github.com/pwn20wndstuff)'s GitHub account

## Video tutorial
* <a href="https://youtu.be/TqHYjLHO0zs">https://youtu.be/TqHYjLHO0zs</a>

## To Do List
* Contact [@saurik](https://twitter.com/saurik) to enable the Cydia Store purchases on iOS 11 and remove the empty front page ads in Cydia: Partially done
* Completely switch to Cydia Substrate and ditch Substitute: Done
* Make switching from other jailbreaks without wiping the device possible: Done
* Fix a kernel panic that's triggered by a kernel data abort which is caused by a UaF bug in jailbreakd: Done
* Chain [@_bazad](https://twitter.com/_bazad)'s [blanket](https://github.com/bazad/blanket) to bypass the developer certificate requirement for multi_path: Almost done
* Enable the on-fly entitlement patching on iOS 11: Work in progress
* WebKit Port with [@_niklasb](https://twitter.com/_niklasb)'s [WebKit Exploit](https://github.com/phoenhex/files/tree/master/exploits/ios-11.3.1): Work in progress

## Screenshots
<img src="https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Resources/Screenshot-1.PNG?token=AlyO4wXUInR6oHEgx0Tg31ri0t1q91frks5bx5ZbwA%3D%3D" width="281.25" height="609" /> <img src="https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Resources/Screenshot-2.PNG?token=AlyO48vs-YYcaKUgxXh8nIEUQQz_QEoqks5bx5ZqwA%3D%3D" width="281.25" height="609" /> <img src="https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Resources/Screenshot-3.PNG?token=AlyO44tYr5-jl7Pg0jup0tCqm3rSjUhiks5bx5Z4wA%3D%3D" width="281.25" height="609" />

## Changelog
* ~~rc1: Initial release~~
* ~~rc2: Add the dynastic repo by default and fix a bug in firmware checker~~
* ~~rc3: Add a switch to manually enable restoring RootFS, stop erasing user preferences when restoring RootFS and fix bugs~~
* ~~rc4: Add a label to display the uptime, a label to display the app's version number, spawn to the PATH and stop bundling system fonts~~
* ~~rc5: Run videosubscriptionsd in the jailed state, fix a bug in firmware and update checker~~
* ~~rc6: Start logging again, improve update checker and fix multi_path~~
* ~~rc7: Fix a bug in RootFS Restore and multi_path~~
* ~~rc8: Fix a bug in RootFS Remount and add a work in progress warning for some firmwares~~
* ~~rc9: Fix a bug in RootFS Remount, add even more detailed error messages and add a switch to increase the memory limit to improve the stability and improve the compatibility layer to work correctly with some tweaks that were specifically made for the other jailbreaks~~
* ~~v1.0.0: Fix a bug in RootFS Restore and Remount, make the settings tab match with the rest of the UI and fix bugs~~
* ~~v1.0.1: Disable the RootFS Restore for the unstable versions~~
* ~~v1.0.2: Enable and fix the RootFS Restore for all versions~~
* ~~v1.0.3: Fix the beta firmwares~~
* ~~v1.1.0: Automatically select the best exploit, rewrite the versions checker, improve assertion, show the code which has failed in the error messages, improve memory management, optimize and clean up the code, fix the Storage settings, switch to a new technique to disable auto updates, remove so much useless logging, only set the boot-nonce if the switch is on without checking if it exists or not, log offsets, remove static sleeps to improve the speed, fix series of bugs and leave no known bug~~
* ~~v1.1.1: Add a label to show the ECID and a button to open the source code, improve auto layout and fix various bugs in RootFS remount, RootFS restore, RootFS resource copier, Icon cache refresher, Version checker, Exploit selector, jailbreak state detector and others~~
* ~~v1.1.2: Improve auto layout and code and Significantly improve Empty_List (VFS) exploit and slightly improve Multi_Path (MPTCP)~~
* ~~v1.1.3: Fix a bug in starting jailbreakd~~
* ~~v1.1.4: Fix a bug in finding offsets:  [Download (IPA)](https://github.com/pwn20wndstuff/Undecimus/raw/master/Resources/Undecimus.ipa)~~
* Releases are now available at https://github.com/pwn20wndstuff/Undecimus/releases

## Special Thanks
* [@i41nbeer](https://twitter.com/i41nbeer) for mach_portal, triple_fetch, async_wake, empty_list, multi_path and deja_xnu
* [@Morpheus______](https://twitter.com/Morpheus______) for the QiLin Toolkit
* [@xerub](https://twitter.com/xerub) for libjb and the original patchfinder64
* [@iBSparkes](https://twitter.com/iBSparkes) for the original amfid_payload, jailbreakd and pspawn_hook
* [@stek29](https://twitter.com/stek29) for the patchfinder64 additions, unlocknvram, host_get_special_port(4) patch and shenanigans bypass
* [@theninjaprawn](https://twitter.com/theninjaprawn) for the patchfinder64 additions
* [@saurik](https://twitter.com/saurik) for Cydia and Substrate
* [@FCE365](https://twitter.com/FCE365) for the empty_list reliability improvements
* [@tihmstar](https://twitter.com/tihmstar) for libgrabkernel, liboffsetfinder64 and v1ntex
* Credits for [Undecimus-Resources](https://github.com/pwn20wndstuff/Undecimus-Resources)
* [@coolstarorg](https://twitter.com/coolstarorg) for originally testing the snapshot rename idea on corellium
* [@Cryptiiiic](https://twitter.com/Cryptiiiic) for testing
* [@xanDesign_](https://twitter.com/xanDesign_) for testing
* [@AppleDry05](https://twitter.com/AppleDry05) for testing
* [@AyyItzRob](https://twitter.com/AyyItzRob) for testing
* [@MidnightChip](https://twitter.com/MidnightChip) for testing
* [@Swag_iOS](https://twitter.com/Swag_iOS) for testing
* [@jailbreakbuster](https://twitter.com/jailbreakbuster) for testing
* [@Jakeashacks](https://twitter.com/Jakeashacks) for testing
