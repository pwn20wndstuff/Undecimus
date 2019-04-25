# unc0ver
### The most advanced jailbreak tool
![unc0ver logo](https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Undecimus/Assets.xcassets/AppIcon.appiconset/Icon-App-60x60%403x.png?token=AlyO4xDujoguob2DCFfUbNI8jO82OyCgks5bx5ZPwA%3D%3D)

unc0ver jailbreak for iOS 11.0 - 12.1.2<br/>
by [@pwn20wnd](https://twitter.com/Pwn20wnd) & [@sbingner](https://twitter.com/sbingner)<br/>
UI by [@DennisBednarz](https://twitter.com/DennisBednarz) & [Samg_is_a_Ninja](https://reddit.com/u/Samg_is_a_Ninja)<br/>

## Changes over other jailbreaks
* All exploits in same app
* Detailed error messages
* Faster and more stable patches
* No extra battery drain
* No random freezes and\or slow downs
* No malware
* Proper jailbreak state detection
* Proper bootstrap extraction to fix issues such as Cydia not appearing after jailbreak
* Native build of Cydia for iOS 11, with support for the iPhone X screen size and a modern look (changes made with permission from [@saurik](https://twitter.com/saurik) )
* Telesphoreo port for ARM64
* Cydia Substrate for tweak injection
* Much faster and stable ldrestart
* Working debugserver
* An awesome UI

### In-app Options
* Option to skip loading daemons
* Option to dump APTicket
* Option to refresh icon cache
* Option to disable auto updates
* Option to block app revokes
* Option to restore RootFS
* Button to restart device
* Button to open Cydia in case it doesn't appear on the Home Screen
* Label to show the days left till the application expires

<img src="https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Resources/Screenshot-2.PNG?token=AlyO4wXUInR6oHEgx0Tg31ri0t1q91frks5bx5ZbwA%3D%3D" width="281.25" height="609" /> <img src="https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Resources/Screenshot-1.PNG?token=AlyO48vs-YYcaKUgxXh8nIEUQQz_QEoqks5bx5ZqwA%3D%3D" width="281.25" height="609" /> <img src="https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Resources/Screenshot-3.PNG?token=AlyO48vs-YYcaKUgxXh8nIEUQQz_QEoqks5bx5ZqwA%3D%3D" width="281.25" height="609" />

### Tips
*  Perform a full restore with [Succession](https://www.reddit.com/r/jailbreak/comments/bg2sfp/release_succession_fully_restore_your_ios_device/) before switching from other jailbreaks
* Use the built-in diagnostics tool to troubleshoot encountered issues during the jailbreak proccess
* Tweet [@pwn20wnd](https://twitter.com/Pwn20wnd) for further development on any issues or questions

Refer to this [tutorial](https://youtu.be/TqHYjLHO0zs) to see the jailbreak proccess in action.

### Changelog
* Changelogs and releases are available at https://github.com/pwn20wndstuff/Undecimus/releases

### To Do List
* Chain [@_bazad](https://twitter.com/_bazad)'s [blanket](https://github.com/bazad/blanket) to bypass the developer certificate requirement for multi_path: Almost done
* Enable the on-fly entitlement patching on iOS 11: Work in progress
* WebKit Port with [@_niklasb](https://twitter.com/_niklasb)'s [WebKit Exploit](https://github.com/phoenhex/files/tree/master/exploits/ios-11.3.1): Work in progress

## Special Thanks
* [@i41nbeer](https://twitter.com/i41nbeer) for mach_portal, triple_fetch, async_wake, empty_list, multi_path and deja_xnu
* [@Morpheus______](https://twitter.com/Morpheus______) for the QiLin Toolkit
* [@xerub](https://twitter.com/xerub) for libjb and the original patchfinder64
* [@iBSparkes](https://twitter.com/iBSparkes) for the original amfid_payload, jailbreakd, pspawn_hook and machswap
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

*This project is completely open source and it will be kept like it in the future. You can find it on [pwn20wndstuff](https://github.com/pwn20wndstuff)'s GitHub account and any kind of contribution is welcome.*
