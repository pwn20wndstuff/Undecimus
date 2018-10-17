# unc0ver

### The most advanced jailbreak tool

![unc0ver logo](https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Undecimus/Assets.xcassets/AppIcon.appiconset/Icon-App-60x60%403x.png)

unc0ver jailbreak for iOS 11.0 - 11.4b3

by [@pwn20wnd](https://twitter.com/Pwn20wnd) & [@sbingner](https://twitter.com/sbingner)

UI by [@DennisBednarz](https://twitter.com/DennisBednarz) & [Samg_is_a_Ninja](https://reddit.com/u/Samg_is_a_Ninja)

## The most outstanding changes over the other jailbreaks

- All exploits in same app
- Detailed error messages
- Faster patches
- More stable patches
- No extra battery drain
- No random freezes
- No random slow downs
- No data is logged or shared
- No malware
- Proper jailbreak state detection
- Proper bootstrap extraction to fix issues such as Cydia not appearing after jailbreak
- Native build of Cydia for iOS 11
- Telesphoreo port for ARM64
- Much faster Cydia
- Much more stable Cydia
- Much more modern looking and acting Cydia
- Cydia skips uicache when not needed
- Cydia supports iPhone X screen size
- Cydia Substrate for tweak injection
- Much faster ldrestart
- Much more stable ldrestart
- Changes to Cydia were made with permission from Saurik
- Option to skip loading daemons
- Option to dump APTicket
- Option to refresh icon cache
- Option to disable auto updates
- Option to block app revokes
- Option to restore RootFS
- Button to restart device
- Button to open Cydia in case it doesn't appear on the Home Screen
- Label to show the days left till the application expires
- Working debugserver
- An awesome UI

## The technical side

- Exploit kernel_task
- Get kernel base
- Find offsets
- Get root
- Escape sandbox
- Get entitlements
- Dump APTicket
- Unlock nvram
- Set boot-nonce
- Lock nvram
- Allow double mount
- Remount RootFS
- Prepare resources
- Inject to trust cache
- Log slide
- Set HSP4
- Patch amfid
- Spawn jailbreakd
- Patch launchd
- Update version string
- Extract bootstrap
- Disable stashing
- Disable app revokes
- Allow SpringBoard to show non-default system apps
- Disable Auto Updates
- Load Daemons
- Run uicache
- Load Tweaks

## Switching from the other jailbreaks

- The RootFS will automatically be restored

## Getting support

- Use the built-in diagnostics tool
- Get technical support on the [r/Jailbreak Discord Server](https://discord.gg/jb)
- Tweet [@pwn20wnd](https://twitter.com/Pwn20wnd)

## Best practices

- Turn on the AirPlane Mode before starting the jailbreak
- Turn off Siri before starting the jailbreak

## Source code

- This project is completely open source and it will be kept like it in the future
- Any kind of contribution is welcome
- The source code can be found on [pwn20wndstuff](https://github.com/pwn20wndstuff)'s GitHub account

## Video tutorial

[![YouTube](https://img.youtube.com/vi/TqHYjLHO0zs/0.jpg)](http://www.youtube.com/watch?v=TqHYjLHO0zs "YouTube")

## To Do List

- Completely switch to Cydia Substrate and ditch Substitute
- Fix a kernel panic that's triggered by a kernel data abort which is caused by a UaF bug in jailbreakd
- Chain [@\_bazad](https://twitter.com/_bazad)'s [blanket](https://github.com/bazad/blanket) to bypass the developer certificate requirement for multi_path
- Enable the on-fly entitlement patching on iOS 11
- WebKit Port with [@\_niklasb](https://twitter.com/_niklasb)'s [WebKit Exploit](https://github.com/phoenhex/files/tree/master/exploits/ios-11.3.1)

## Screenshots

<img src="https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Resources/Screenshot-1.PNG" width="187.5" height="333.5" /> <img src="https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Resources/Screenshot-2.PNG" width="187.5" height="333.5" /> <img src="https://raw.githubusercontent.com/pwn20wndstuff/Undecimus/master/Resources/Screenshot-3.PNG" width="187.5" height="333.5" />

## Changelog

- RC1: Initial release: [Download (IPA)](https://github.com/pwn20wndstuff/Undecimus/raw/master/Resources/Undecimus-RC1.ipa)
- RC2: Add the dynastic repo by default and fix the unsupported error on some devices running the iOS 11.4 Beta: [Download (IPA)](https://github.com/pwn20wndstuff/Undecimus/raw/master/Resources/Undecimus-RC2.ipa)
- RC3: Add an option to restore the RootFS, don't reset the preferences when switching from other jailbreaks and fix several errors: [Download (IPA)](https://github.com/pwn20wndstuff/Undecimus/raw/master/Resources/Undecimus-RC3.ipa)
- RC4: Add a label to display the uptime, remove the custom fonts as they are the same with the system fonts, enable logging again and include spawn in the PATH: [Download (IPA)](https://github.com/pwn20wndstuff/Undecimus/raw/master/Resources/Undecimus-RC4.ipa)
- RC5: Attempt to fix the videosubscriptionsd crashes, fix the Unsupported error and fix the Update Checker: [Download (IPA)](https://github.com/pwn20wndstuff/Undecimus/raw/master/Resources/Undecimus-RC5.ipa)
- RC6: Enable logging, improve the version checks, improve the memory management and fix the MP exploit: [Download (IPA)](https://github.com/pwn20wndstuff/Undecimus/raw/master/Resources/Undecimus-RC6.ipa)
- RC7: Fix the RootFS Restore on iOS 11.2 - 11.2.6 and improve the reliability of the MP Exploit's clean up: [Download (IPA)](https://github.com/pwn20wndstuff/Undecimus/raw/master/Resources/Undecimus.ipa)

## Special Thanks

- [@i41nbeer](https://twitter.com/i41nbeer) for triple_fetch, async_wake, empty_list & multi_path
- [@Morpheus**\_\_**](https://twitter.com/Morpheus______) for the QiLin Toolkit
- [@xerub](https://twitter.com/xerub) for libjb and the original patchfinder64
- [@iBSparkes](https://twitter.com/iBSparkes) for the original amfid_payload, jailbreakd and pspawn_hook
- [@stek29](https://twitter.com/stek29) for the patchfinder64 additions, unlocknvram and hsp4
- [@theninjaprawn](https://twitter.com/theninjaprawn) for the patchfinder64 additions
- [@Cryptiiiic](https://twitter.com/Cryptiiiic) for testing
- [@xanDesign\_](https://twitter.com/xanDesign_) for testing
- [@AppleDry05](https://twitter.com/AppleDry05) for testing
- [@Rob_Coleman123](https://twitter.com/Rob_Coleman123) for testing
- [@MidnightChip](https://twitter.com/MidnightChip) for testing
- [@FCE365](https://twitter.com/FCE365) for testing
- [@Swag_iOS](https://twitter.com/Swag_iOS) for testing
- [@jailbreakbuster](https://twitter.com/jailbreakbuster) for testing
- [@Jakeashacks](https://twitter.com/Jakeashacks) for testing
