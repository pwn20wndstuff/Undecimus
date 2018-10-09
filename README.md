# unc0ver

![unc0ver logo](https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Undecimus/Assets.xcassets/AppIcon.appiconset/Icon-App-60x60%403x.png?token=AlyO4-VMCHAG0liqJnnmDwTLr2xoigPVks5bww-vwA%3D%3D)

unc0ver jailbreak for iOS 11.0 - 11.4b3<br/>
by [@pwn20wnd](https://twitter.com/Pwn20wnd) & [@sbingner](https://twitter.com/sbingner)<br/>
UI by [@DennisBednarz](https://twitter.com/DennisBednarz) & [Samg_is_a_Ninja](https://reddit.com/u/Samg_is_a_Ninja)<br/>

## What are the most outstanding changes over what we currently have?
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
* Working debugserver
* An awesome UI

## What is done on the technical side?
* Exploit kernel_task
* Get kernel base
* Find offsets
* Get root
* Escape sandbox
* Get entitlements
* Dump APTicket
* Unlock nvram
* Set boot-nonce
* Lock nvram
* Allow double mount
* Remount RootFS
* Prepare resources
* Inject to trust cache
* Log slide
* Set HSP4
* Patch amfid
* Spawn jailbreakd
* Patch launchd
* Update version string
* Extract bootstrap
* Disable stashing
* Disable app revokes
* Allow SpringBoard to show non-default system apps
* Disable Auto Updates
* Load Daemons
* Run uicache
* Load Tweaks

## Having an issue?
* Use the built-in diagnostics tool

## TODO:
* Contact [@saurik](https://twitter.com/saurik) to enable Cydia Store purchases on iOS 11
* Chain [@_bazad](https://twitter.com/_bazad)'s [blanket](https://github.com/bazad/blanket) to bypass developer certificate requirement for multi_path
* Enable on-fly entitlement patching on iOS 11
* WebKit Port with [@_niklasb](https://twitter.com/_niklasb)'s [WebKit Exploit](https://github.com/phoenhex/files/tree/master/exploits/ios-11.3.1)

## Changelog:
* RC1: Initial release

## Special Thanks:
* [@i41nbeer](https://twitter.com/i41nbeer) for triple_fetch, async_wake, empty_list & multi_path
* [@Morpheus______](https://twitter.com/Morpheus______) for the QiLin Toolkit
* [@xerub](https://twitter.com/xerub) for libjb and the original patchfinder64
* [@iBSparkes](https://twitter.com/iBSparkes) for the original amfid_payload, jailbreakd and pspawn_hook
* [@stek29](https://twitter.com/stek29) for the patchfinder64 additions, unlocknvram and hsp4
* [@theninjaprawn](https://twitter.com/theninjaprawn) for the patchfinder64 additions
* [@Cryptiiiic](https://twitter.com/Cryptiiiic) for testing
* [@xanDesign_](https://twitter.com/xanDesign_) for testing
* [@AppleDry05](https://twitter.com/AppleDry05) for testing
* [@Rob_Coleman123](https://twitter.com/Rob_Coleman123) for testing
* [@MidnightChip](https://twitter.com/MidnightChip) for testing
* [@FCE365](https://twitter.com/FCE365) for testing
* [@Swag_iOS](https://twitter.com/Swag_iOS) for testing
