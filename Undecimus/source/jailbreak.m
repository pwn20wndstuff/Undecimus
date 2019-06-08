//
//  jailbreak.c
//  Undecimus
//
//  Created by Pwn20wnd on 5/11/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#include "jailbreak.h"
#include <sys/snapshot.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <copyfile.h>
#include <spawn.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dirent.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <common.h>
#include <iokit.h>
#include <NSTask.h>
#include <MobileGestalt.h>
#include <netdb.h>
#include <reboot.h>
#import <snappy.h>
#import <inject.h>
#include <sched.h>
#import <patchfinder64.h>
#import <offsetcache.h>
#import <kerneldec.h>
#include <pwd.h>
#import "JailbreakViewController.h"
#include "KernelOffsets.h"
#include "empty_list_sploit.h"
#include "KernelMemory.h"
#include "KernelExecution.h"
#include "KernelUtilities.h"
#include "remote_memory.h"
#include "remote_call.h"
#include "unlocknvram.h"
#include "multi_path_sploit.h"
#include "async_wake.h"
#include "utils.h"
#include "ArchiveFile.h"
#include "FakeApt.h"
#include "voucher_swap.h"
#include "kernel_memory.h"
#include "kernel_slide.h"
#include "find_port.h"
#include "machswap_offsets.h"
#include "machswap_pwn.h"
#include "machswap2_pwn.h"
#include "prefs.h"

int stage = __COUNTER__;
extern int maxStage;

#define update_stage() do { \
    dispatch_async(dispatch_get_main_queue(), ^{ \
        [UIView performWithoutAnimation:^{ \
            [[[JailbreakViewController sharedController] jailbreakProgressBar] setProgress:(float)((float) stage/ (float) maxStage) animated:YES]; \
            [[[JailbreakViewController sharedController] jailbreakProgressBar] setProgress:(float)((float) stage/ (float) maxStage) animated:YES]; \
            [[JailbreakViewController sharedController] exploitProgressLabel].text = [NSString stringWithFormat:@"%d/%d", stage, maxStage]; \
        }]; \
    }); \
} while (false)

#define upstage() do { \
    __COUNTER__; \
    stage++; \
    update_stage(); \
} while (false)

#define find_offset(x, symbol, critical) do { \
    if (!KERN_POINTER_VALID(getoffset(x))) { \
        setoffset(x, find_symbol(symbol != NULL ? symbol : "_" #x)); \
    } \
    if (!KERN_POINTER_VALID(getoffset(x))) { \
        kptr_t (*_find_ ##x)(void) = dlsym(RTLD_DEFAULT, "find_" #x); \
        if (_find_ ##x != NULL) { \
            setoffset(x, _find_ ##x()); \
        } \
    } \
    if (KERN_POINTER_VALID(getoffset(x))) { \
        LOG(#x " = " ADDR " + " ADDR, getoffset(x), kernel_slide); \
        setoffset(x, getoffset(x) + kernel_slide); \
    } else { \
        setoffset(x, 0); \
        if (critical) { \
            _assert(false, localize(@"Unable to find kernel offset for " #x), true); \
        } \
    } \
} while (false)

void jailbreak()
{
    status(localize(@"Jailbreaking"), false, false);
    
    int rv = 0;
    bool usedPersistedKernelTaskPort = NO;
    pid_t const my_pid = getpid();
    uid_t const my_uid = getuid();
    host_t myHost = HOST_NULL;
    host_t myOriginalHost = HOST_NULL;
    kptr_t myProcAddr = KPTR_NULL;
    kptr_t myOriginalCredAddr = KPTR_NULL;
    kptr_t myCredAddr = KPTR_NULL;
    kptr_t kernelCredAddr = KPTR_NULL;
    kptr_t Shenanigans = KPTR_NULL;
    prefs_t *prefs = copy_prefs();
    bool needStrap = NO;
    bool needSubstitutor = NO;
    bool skipSubstitutor = NO;
    NSString *const homeDirectory = NSHomeDirectory();
    NSString *const temporaryDirectory = NSTemporaryDirectory();
    NSMutableArray *debsToInstall = [NSMutableArray new];
    NSMutableString *status = [NSMutableString new];
    bool const betaFirmware = isBetaFirmware();
    time_t const start_time = time(NULL);
    JailbreakViewController *sharedController = [JailbreakViewController sharedController];
    NSMutableArray *resources = [NSMutableArray new];
    NSFileManager *const fileManager = [NSFileManager defaultManager];
    bool const doInject = (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0);
    const char *success_file = [temporaryDirectory stringByAppendingPathComponent:@"jailbreak.completed"].UTF8String;
    NSString *const NSJailbreakDirectory = @"/jb";
    const char *jailbreakDirectory = NSJailbreakDirectory.UTF8String;
    struct passwd *const root_pw = getpwnam("root");
    struct passwd *const mobile_pw = getpwnam("mobile");
    substitutor_info_t *substitutor = NULL;
    _assert(my_uid == mobile_pw->pw_uid, localize(@"Unable to verify my user id."), true);
#define NSJailbreakFile(x) ([NSJailbreakDirectory stringByAppendingPathComponent:x])
#define jailbreak_file(x) (NSJailbreakFile(@(x)).UTF8String)
    _assert(clean_file(success_file), localize(@"Unable to clean success file."), true);
#define insertstatus(x) do { [status appendString:x]; } while (false)
#define sync_prefs() do { _assert(set_prefs(prefs), localize(@"Unable to synchronize app preferences. Please restart the app and try again."), true); } while (false)
#define write_test_file(file) do { \
    _assert(create_file(file, root_pw->pw_uid, 0644), localize(@"Unable to create test file."), true); \
    _assert(clean_file(file), localize(@"Unable to clean test file."), true); \
} while (false)
#define inject_trust_cache() do { \
    if (toInjectToTrustCache.count <= 0) break; \
    LOG("Injecting %lu files to trust cache", toInjectToTrustCache.count); \
    _assert(injectTrustCache(toInjectToTrustCache, getoffset(trustcache), pmap_load_trust_cache) == 0, localize(@"Unable to inject trust cache"), true); \
    LOG("Injected %lu files to trust cache", toInjectToTrustCache.count); \
    [toInjectToTrustCache removeAllObjects]; \
    injectedToTrustCache = true; \
} while(false)
    
    upstage();
    
    {
        // Exploit kernel.
        
        progress(localize(@"Exploiting kernel..."));
        bool exploit_success = NO;
        myHost = mach_host_self();
        _assert(MACH_PORT_VALID(myHost), localize(@"Unable to get host port."), true);
        myOriginalHost = myHost;
        if (restore_kernel_task_port(&tfp0) &&
            restore_kernel_base(&kernel_base, &kernel_slide) &&
            restore_kernel_offset_cache()) {
            usedPersistedKernelTaskPort = YES;
            exploit_success = YES;
        } else {
            switch (prefs->exploit) {
                case empty_list_exploit: {
                    if (vfs_sploit() &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base = find_kernel_base())) {
                        exploit_success = YES;
                    }
                    break;
                }
                case multi_path_exploit: {
                    if (mptcp_go() &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base = find_kernel_base())) {
                        exploit_success = YES;
                    }
                    break;
                }
                case async_wake_exploit: {
                    if (async_wake_go() &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base = find_kernel_base())) {
                        exploit_success = YES;
                    }
                    break;
                }
                case voucher_swap_exploit: {
                    voucher_swap();
                    if (MACH_PORT_VALID(tfp0) &&
                        kernel_slide_init() &&
                        kernel_slide != -1 &&
                        KERN_POINTER_VALID(kernel_base = (kernel_slide + STATIC_KERNEL_BASE_ADDRESS))) {
                        exploit_success = YES;
                    }
                    break;
                }
                case mach_swap_exploit: {
                    machswap_offsets_t *const machswap_offsets = get_machswap_offsets();
                    if (machswap_offsets != NULL &&
                        machswap_exploit(machswap_offsets) == ERR_SUCCESS &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base)) {
                        exploit_success = YES;
                    }
                    break;
                }
                case mach_swap_2_exploit: {
                    machswap_offsets_t *const machswap_offsets = get_machswap_offsets();
                    if (machswap_offsets != NULL &&
                        machswap2_exploit(machswap_offsets) == ERR_SUCCESS &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base)) {
                        exploit_success = YES;
                    }
                    break;
                }
                default: {
                    notice(localize(@"No exploit selected."), false, false);
                    status(localize(@"Jailbreak"), true, true);
                    return;
                    break;
                }
            }
        }
        if (kernel_slide == -1 && kernel_base != -1) kernel_slide = (kernel_base - STATIC_KERNEL_BASE_ADDRESS);
        LOG("tfp0: 0x%x", tfp0);
        LOG("kernel_base: " ADDR, kernel_base);
        LOG("kernel_slide: " ADDR, kernel_slide);
        if (exploit_success && !verify_tfp0()) {
            LOG("Unable to verify TFP0.");
            exploit_success = NO;
        }
        if (exploit_success && ReadKernel32(kernel_base) != MACH_HEADER_MAGIC) {
            LOG("Unable to verify kernel_base.");
            exploit_success = NO;
        }
        if (!exploit_success) {
            notice(localize(@"Unable to exploit kernel. This is not an error. Reboot and try again."), true, false);
            exit(EXIT_FAILURE);
            _assert(false, localize(@"Unable to exit."), true);
        }
        insertstatus(localize(@"Exploited kernel.\n"));
        LOG("Successfully exploited kernel.");
    }
    
    upstage();
    
    {
        if (!found_offsets) {
            // Initialize patchfinder.
            
            progress(localize(@"Initializing patchfinder..."));
            char *const original_kernel_cache_path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
            const char *decompressed_kernel_cache_path = [homeDirectory stringByAppendingPathComponent:@"Documents/kernelcache.dec"].UTF8String;
            if (!canRead(decompressed_kernel_cache_path)) {
                kptr_t sandbox = KPTR_NULL;
                if (!canRead(original_kernel_cache_path)) {
                    sandbox = swap_sandbox_for_proc(proc_struct_addr(), KPTR_NULL);
                }
                FILE *const original_kernel_cache = fopen(original_kernel_cache_path, "rb");
                _assert(original_kernel_cache != NULL, localize(@"Unable to open original kernelcache for reading."), true);
                FILE *const decompressed_kernel_cache = fopen(decompressed_kernel_cache_path, "w+b");
                _assert(decompressed_kernel_cache != NULL, localize(@"Unable to open decompressed kernelcache for writing."), true);
                _assert(decompress_kernel(original_kernel_cache, decompressed_kernel_cache, NULL, true) == ERR_SUCCESS, localize(@"Unable to decompress kernelcache."), true);
                fclose(decompressed_kernel_cache);
                fclose(original_kernel_cache);
                if (KERN_POINTER_VALID(sandbox)) {
                    swap_sandbox_for_proc(proc_struct_addr(), sandbox);
                }
            }
            char *kernelVersion = getKernelVersion();
            _assert(kernelVersion != NULL, localize(@"Unable to get kernel version."), true);
            if (init_kernel(NULL, KPTR_NULL, decompressed_kernel_cache_path) != ERR_SUCCESS ||
                find_strref(kernelVersion, 1, string_base_const, true, false) == KPTR_NULL) {
                _assert(clean_file(decompressed_kernel_cache_path), localize(@"Unable to clean corrupted kernelcache."), true);
                _assert(false, localize(@"Unable to initialize patchfinder."), true);
            }
            SafeFreeNULL(kernelVersion);
            LOG("Successfully initialized patchfinder.");
        } else {
            auth_ptrs = getoffset(auth_ptrs);
            monolithic_kernel = getoffset(monolithic_kernel);
        }
        if (auth_ptrs) {
            setoffset(auth_ptrs, true);
            LOG("Detected authentication pointers.");
            pmap_load_trust_cache = _pmap_load_trust_cache;
            sync_prefs();
        }
        if (monolithic_kernel) {
            setoffset(monolithic_kernel, true);
            LOG("Detected monolithic kernel.");
        }
        offset_options = getoffset(unrestrict-options);
        if (!offset_options) {
            offset_options = kmem_alloc(sizeof(kptr_t));
            wk64(offset_options, KPTR_NULL);
            setoffset(unrestrict-options, offset_options);
        }
        if (prefs->enable_get_task_allow) {
            SETOPT(GET_TASK_ALLOW);
        } else {
            UNSETOPT(GET_TASK_ALLOW);
        }
        if (prefs->set_cs_debugged) {
            SETOPT(CS_DEBUGGED);
        } else {
            UNSETOPT(CS_DEBUGGED);
        }
    }
    
    upstage();
    
    if (!found_offsets) {
        // Find offsets.
        
        progress(localize(@"Finding offsets..."));
        setoffset(kernel_base, kernel_base);
        setoffset(kernel_slide, kernel_slide);
        find_offset(trustcache, NULL, true);
        find_offset(OSBoolean_True, NULL, true);
        find_offset(osunserializexml, NULL, true);
        find_offset(smalloc, NULL, true);
        if (!auth_ptrs) {
            find_offset(add_x0_x0_0x40_ret, NULL, true);
        }
        find_offset(zone_map_ref, NULL, true);
        find_offset(vfs_context_current, NULL, true);
        find_offset(vnode_lookup, NULL, true);
        find_offset(vnode_put, NULL, true);
        find_offset(kernel_task, NULL, true);
        find_offset(shenanigans, NULL, true);
        if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
            find_offset(vnode_get_snapshot, NULL, true);
            find_offset(fs_lookup_snapshot_metadata_by_name_and_return_name, NULL, true);
            find_offset(apfs_jhash_getvnode, NULL, true);
        }
        if (auth_ptrs) {
            find_offset(pmap_load_trust_cache, NULL, true);
            find_offset(paciza_pointer__l2tp_domain_module_start, NULL, true);
            find_offset(paciza_pointer__l2tp_domain_module_stop, NULL, true);
            find_offset(l2tp_domain_inited, NULL, true);
            find_offset(sysctl__net_ppp_l2tp, NULL, true);
            find_offset(sysctl_unregister_oid, NULL, true);
            find_offset(mov_x0_x4__br_x5, NULL, true);
            find_offset(mov_x9_x0__br_x1, NULL, true);
            find_offset(mov_x10_x3__br_x6, NULL, true);
            find_offset(kernel_forge_pacia_gadget, NULL, true);
            find_offset(kernel_forge_pacda_gadget, NULL, true);
            find_offset(IOUserClient__vtable, NULL, true);
            find_offset(IORegistryEntry__getRegistryEntryID, NULL, true);
        }
        find_offset(lck_mtx_lock, NULL, true);
        find_offset(lck_mtx_unlock, NULL, true);
        find_offset(proc_find, NULL, true);
        find_offset(proc_rele, NULL, true);
        find_offset(extension_create_file, NULL, true);
        find_offset(extension_add, NULL, true);
        find_offset(extension_release, NULL, true);
        find_offset(sfree, NULL, true);
        find_offset(sstrdup, NULL, true);
        find_offset(strlen, NULL, true);
        find_offset(issue_extension_for_mach_service, NULL, true);
        find_offset(issue_extension_for_absolute_path, NULL, true);
        find_offset(IOMalloc, NULL, true);
        find_offset(IOFree, NULL, true);
        found_offsets = true;
        LOG("Successfully found offsets.");
        
        // Deinitialize patchfinder.
        term_kernel();
    }
    
    upstage();
    
    {
        // Initialize jailbreak.
        kptr_t const ShenanigansPatch = 0xca13feba37be;
        
        progress(localize(@"Initializing jailbreak..."));
        LOG("Escaping sandbox...");
        myProcAddr = proc_struct_addr();
        LOG("myProcAddr = " ADDR, myProcAddr);
        _assert(KERN_POINTER_VALID(myProcAddr), localize(@"Unable to find my process in kernel memory."), true);
        kernelCredAddr = get_kernel_cred_addr();
        LOG("kernelCredAddr = " ADDR, kernelCredAddr);
        _assert(KERN_POINTER_VALID(kernelCredAddr), localize(@"Unable to find kernel's credentials in kernel memory."), true);
        Shenanigans = ReadKernel64(getoffset(shenanigans));
        LOG("Shenanigans = " ADDR, Shenanigans);
        _assert(KERN_POINTER_VALID(Shenanigans) || Shenanigans == ShenanigansPatch, localize(@"Unable to verify shenanigans in kernel memory."), true);
        if (Shenanigans != kernelCredAddr) {
            LOG("Detected corrupted shenanigans pointer.");
            Shenanigans = kernelCredAddr;
        }
        _assert(WriteKernel64(getoffset(shenanigans), ShenanigansPatch), localize(@"Unable to overwrite shenanigans in kernel memory."), true);
        myCredAddr = kernelCredAddr;
        myOriginalCredAddr = give_creds_to_process_at_addr(myProcAddr, myCredAddr);
        LOG("myOriginalCredAddr = " ADDR, myOriginalCredAddr);
        _assert(KERN_POINTER_VALID(myOriginalCredAddr), localize(@"Unable to steal kernel's credentials."), true);
        _assert(setuid(root_pw->pw_uid) == ERR_SUCCESS, localize(@"Unable to set user id."), true);
        _assert(getuid() == root_pw->pw_uid, localize(@"Unable to verify user id."), true);
        myHost = mach_host_self();
        _assert(MACH_PORT_VALID(myHost), localize(@"Unable to upgrade host port."), true);
        LOG("Successfully escaped sandbox.");
        LOG("Initializing kernel code execution...");
        _assert(init_kexec(), localize(@"Unable to initialize kernel code execution."), true);
        LOG("Successfully initialized kernel code execution.");
        LOG("Setting HSP4 as TFP0...");
        _assert(set_hsp4(tfp0), localize(@"Unable to set HSP4."), true);
        LOG("Successfully set HSP4 as TFP0.");
        insertstatus(localize(@"Set HSP4 as TFP0.\n"));
        LOG("Setting kernel task info...");
        _assert(set_kernel_task_info(), localize(@"Unable to set kernel task info."), true);
        LOG("Successfully set kernel task info.");
        insertstatus(localize(@"Set kernel task info.\n"));
        LOG("Platformizing...");
        _assert(set_platform_binary(myProcAddr, true), localize(@"Unable to make my task a platform task."), true);
        _assert(set_cs_platform_binary(myProcAddr, true), localize(@"Unable to make my codesign blob a platform blob."), true);
        LOG("Successfully initialized jailbreak.");
    }
    
    upstage();
    
    {
        if (prefs->export_kernel_task_port) {
            // Export kernel task port.
            progress(localize(@"Exporting kernel task port..."));
            _assert(export_tfp0(myOriginalHost), localize(@"Unable to export TFP0."), true);
            LOG("Successfully exported kernel task port.");
            insertstatus(localize(@"Exported kernel task port.\n"));
        } else {
            // Unexport kernel task port.
            progress(localize(@"Unexporting kernel task port..."));
            _assert(unexport_tfp0(myOriginalHost), localize(@"Unable to unexport TFP0."), true);
            LOG("Successfully unexported kernel task port.");
            insertstatus(localize(@"Unexported kernel task port.\n"));
        }
    }
    
    upstage();
    
    {
        // Write a test file to UserFS.
        
        progress(localize(@"Writing a test file to UserFS..."));
        const char *testFile = [NSString stringWithFormat:@"/var/mobile/test-%lu.txt", time(NULL)].UTF8String;
        write_test_file(testFile);
        LOG("Successfully wrote a test file to UserFS.");
    }
    
    upstage();
    
    {
        if (prefs->dump_apticket) {
            NSString *const originalFile = @"/System/Library/Caches/apticket.der";
            NSString *const dumpFile = [homeDirectory stringByAppendingPathComponent:@"Documents/apticket.der"];
            if (![sha1sum(originalFile) isEqualToString:sha1sum(dumpFile)]) {
                // Dump APTicket.
                
                progress(localize(@"Dumping APTicket..."));
                NSData *const fileData = [NSData dataWithContentsOfFile:originalFile];
                _assert(([fileData writeToFile:dumpFile atomically:YES]), localize(@"Unable to dump APTicket."), true);
                LOG("Successfully dumped APTicket.");
            }
            insertstatus(localize(@"Dumped APTicket.\n"));
        }
    }
    
    upstage();
    
    {
        if (prefs->overwrite_boot_nonce) {
            // Unlock nvram.
            
            progress(localize(@"Unlocking nvram..."));
            _assert(unlocknvram() == ERR_SUCCESS, localize(@"Unable to unlock nvram."), true);
            LOG("Successfully unlocked nvram.");
            
            _assert(runCommand("/usr/sbin/nvram", "-p", NULL) == ERR_SUCCESS, localize(@"Unable to print nvram variables."), true);
            char *const bootNonceKey = "com.apple.System.boot-nonce";
            if (runCommand("/usr/sbin/nvram", bootNonceKey, NULL) != ERR_SUCCESS ||
                strstr(lastSystemOutput.bytes, prefs->boot_nonce) == NULL) {
                // Set boot-nonce.
                
                progress(localize(@"Setting boot-nonce..."));
                _assert(runCommand("/usr/sbin/nvram", [NSString stringWithFormat:@"%s=%s", bootNonceKey, prefs->boot_nonce].UTF8String, NULL) == ERR_SUCCESS, localize(@"Unable to set boot nonce."), true);
                _assert(runCommand("/usr/sbin/nvram", [NSString stringWithFormat:@"%s=%s", kIONVRAMForceSyncNowPropertyKey, bootNonceKey].UTF8String, NULL) == ERR_SUCCESS, localize(@"Unable to synchronize boot nonce."), true);
                LOG("Successfully set boot-nonce.");
            }
            _assert(runCommand("/usr/sbin/nvram", "-p", NULL) == ERR_SUCCESS, localize(@"Unable to print new nvram variables."), true);
            
            // Lock nvram.
            
            progress(localize(@"Locking nvram..."));
            _assert(locknvram() == ERR_SUCCESS, localize(@"Unable to lock nvram."), true);
            LOG("Successfully locked nvram.");
            
            insertstatus(localize(@"Overwrote boot nonce.\n"));
        }
    }
    
    upstage();
    
    {
        // Log slide.
        
        progress(localize(@"Logging slide..."));
        NSString *const file = @(SLIDE_FILE);
        NSData *const fileData = [[NSString stringWithFormat:@(ADDR "\n"), kernel_slide] dataUsingEncoding:NSUTF8StringEncoding];
        if (![[NSData dataWithContentsOfFile:file] isEqual:fileData]) {
            _assert(clean_file(file.UTF8String), localize(@"Unable to clean old kernel slide log."), true);
            _assert(create_file_data(file.UTF8String, root_pw->pw_uid, 0644, fileData), localize(@"Unable to log kernel slide."), true);
        }
        LOG("Successfully logged slide.");
        insertstatus(localize(@"Logged slide.\n"));
    }
    
    upstage();
    
    {
        // Log ECID.
        
        progress(localize(@"Logging ECID..."));
        NSString *const ECID = getECID();
        if (ECID != nil) {
            prefs->ecid = ECID.UTF8String;
            sync_prefs();
        } else {
            LOG("I couldn't get the ECID... Am I running on a real device?");
        }
        LOG("Successfully logged ECID.");
        insertstatus(localize(@"Logged ECID.\n"));
    }
    
    upstage();
    
    {
        NSArray *const array = @[@"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate",
                                 @"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation",
                                 @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate",
                                 @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation"];
        if (prefs->disable_auto_updates) {
            // Disable Auto Updates.
            
            progress(localize(@"Disabling Auto Updates..."));
            for (id path in array) {
                ensure_symlink("/dev/null", [path UTF8String]);
            }
            _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.Preferences.plist", ^(id plist) {
                plist[@"kBadgedForSoftwareUpdateKey"] = @NO;
                plist[@"kBadgedForSoftwareUpdateJumpOnceKey"] = @NO;
            }), localize(@"Unable to disable software update badge."), true);
            LOG("Successfully disabled Auto Updates.");
            insertstatus(localize(@"Disabled Auto Updates.\n"));
        } else {
            // Enable Auto Updates.
            
            progress(localize(@"Enabling Auto Updates..."));
            for (id path in array) {
                ensure_directory([path UTF8String], root_pw->pw_uid, 0755);
            }
            _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.Preferences.plist", ^(id plist) {
                plist[@"kBadgedForSoftwareUpdateKey"] = @YES;
                plist[@"kBadgedForSoftwareUpdateJumpOnceKey"] = @YES;;
            }), localize(@"Unable to enable software update badge."), true);
            insertstatus(localize(@"Enabled Auto Updates.\n"));
        }
    }
    
    upstage();
    
    {
        // Remount RootFS.
        
        progress(localize(@"Remounting RootFS..."));
        int rootfd = open("/", O_RDONLY);
        _assert(rootfd > 0, localize(@"Unable to open RootFS."), true);
        const char **snapshots = snapshot_list(rootfd);
        char *systemSnapshot = copySystemSnapshot();
        _assert(systemSnapshot != NULL, localize(@"Unable to copy system snapshot."), true);
        char *const original_snapshot = "orig-fs";
        bool has_original_snapshot = NO;
        char *const thedisk = "/dev/disk0s1s1";
        char *oldest_snapshot = NULL;
        _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, localize(@"Unable to print mount list."), false);
        if (snapshots == NULL) {
            close(rootfd);
            
            // Clear dev vnode's si_flags.
            
            LOG("Clearing dev vnode's si_flags...");
            kptr_t devVnode = get_vnode_for_path(thedisk);
            LOG("devVnode = " ADDR, devVnode);
            _assert(KERN_POINTER_VALID(devVnode), localize(@"Unable to get vnode for root device."), true);
            kptr_t v_specinfo = ReadKernel64(devVnode + koffset(KSTRUCT_OFFSET_VNODE_VU_SPECINFO));
            LOG("v_specinfo = " ADDR, v_specinfo);
            _assert(KERN_POINTER_VALID(v_specinfo), localize(@"Unable to get specinfo for root device."), true);
            WriteKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS), 0);
            _assert(vnode_put(devVnode) == ERR_SUCCESS, localize(@"Unable to close vnode for root device."), true);
            LOG("Successfully cleared dev vnode's si_flags.");
            
            // Mount RootFS.
            
            LOG("Mounting RootFS...");
            NSString *const invalidRootMessage = localize(@"RootFS already mounted, delete OTA file from Settings - Storage if present and reboot.");
            _assert(!is_mountpoint("/var/MobileSoftwareUpdate/mnt1"), invalidRootMessage, true);
            char *const rootFsMountPoint = "/private/var/tmp/jb/mnt1";
            if (is_mountpoint(rootFsMountPoint)) {
                _assert(unmount(rootFsMountPoint, MNT_FORCE) == ERR_SUCCESS, localize(@"Unable to unmount old RootFS mount point."), true);
            }
            _assert(clean_file(rootFsMountPoint), localize(@"Unable to clean old RootFS mount point."), true);
            char *const hardwareMountPoint = "/private/var/hardware";
            if (is_mountpoint(hardwareMountPoint)) {
                _assert(unmount(hardwareMountPoint, MNT_FORCE) == ERR_SUCCESS, localize(@"Unable to unmount hardware mount point."), true);
            }
            _assert(ensure_directory(rootFsMountPoint, root_pw->pw_uid, 0755), localize(@"Unable to create RootFS mount point."), true);
            const char *argv[] = {"/sbin/mount_apfs", thedisk, rootFsMountPoint, NULL};
            _assert(runCommandv(argv[0], 3, argv, ^(pid_t pid) {
                kptr_t const procStructAddr = get_proc_struct_for_pid(pid);
                LOG("procStructAddr = " ADDR, procStructAddr);
                _assert(KERN_POINTER_VALID(procStructAddr), localize(@"Unable to find mount_apfs's process in kernel memory."), true);
                give_creds_to_process_at_addr(procStructAddr, kernelCredAddr);
            }) == ERR_SUCCESS, localize(@"Unable to mount RootFS."), true);
            _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, localize(@"Unable to print new mount list."), true);
            const char *systemSnapshotLaunchdPath = [@(rootFsMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
            _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, localize(@"Unable to verify newly mounted RootFS."), true);
            LOG("Successfully mounted RootFS.");
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot...");
            rootfd = open(rootFsMountPoint, O_RDONLY);
            _assert(rootfd > 0, localize(@"Unable to open newly mounted RootFS."), true);
            snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, localize(@"Unable to get snapshots for newly mounted RootFS."), true);
            LOG("Snapshots on newly mounted RootFS:");
            for (const char **snapshot = snapshots; *snapshot; snapshot++) {
                LOG("\t%s", *snapshot);
                if (strcmp(*snapshot, original_snapshot) == 0) {
                    LOG("Clearing old original system snapshot...");
                    _assert(fs_snapshot_delete(rootfd, original_snapshot, 0) == ERR_SUCCESS, localize(@"Unable to clear old original system snapshot."), true);
                }
            }
            SafeFreeNULL(snapshots);
            NSString *const systemVersionPlist = @"/System/Library/CoreServices/SystemVersion.plist";
            NSString *const rootSystemVersionPlist = [@(rootFsMountPoint) stringByAppendingPathComponent:systemVersionPlist];
            NSDictionary *const snapshotSystemVersion = [NSDictionary dictionaryWithContentsOfFile:systemVersionPlist];
            _assert(snapshotSystemVersion != nil, localize(@"Unable to get SystemVersion.plist for RootFS."), true);
            NSDictionary *const rootfsSystemVersion = [NSDictionary dictionaryWithContentsOfFile:rootSystemVersionPlist];
            _assert(rootfsSystemVersion != nil, localize(@"Unable to get SystemVersion.plist for newly mounted RootFS."), true);
            if (![rootfsSystemVersion[@"ProductBuildVersion"] isEqualToString:snapshotSystemVersion[@"ProductBuildVersion"]]) {
                LOG("snapshot VersionPlist: %@", snapshotSystemVersion);
                LOG("rootfs VersionPlist: %@", rootfsSystemVersion);
                _assert("BuildVersions match"==NULL, invalidRootMessage, true);
            }
            char *const test_snapshot = "test-snapshot";
            _assert(fs_snapshot_create(rootfd, test_snapshot, 0) == ERR_SUCCESS, localize(@"Unable to create test snapshot."), true);
            _assert(fs_snapshot_delete(rootfd, test_snapshot, 0) == ERR_SUCCESS, localize(@"Unable to delete test snapshot."), true);
            kptr_t system_snapshot_vnode = KPTR_NULL;
            kptr_t system_snapshot_vnode_v_data = KPTR_NULL;
            uint32_t system_snapshot_vnode_v_data_flag = 0;
            if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
                system_snapshot_vnode = get_vnode_for_snapshot(rootfd, systemSnapshot);
                LOG("system_snapshot_vnode = " ADDR, system_snapshot_vnode);
                _assert(KERN_POINTER_VALID(system_snapshot_vnode), localize(@"Unable to get vnode for system snapshot."), true);
                system_snapshot_vnode_v_data = ReadKernel64(system_snapshot_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_DATA));
                LOG("system_snapshot_vnode_v_data = " ADDR, system_snapshot_vnode_v_data);
                _assert(KERN_POINTER_VALID(system_snapshot_vnode_v_data), localize(@"Unable to get vnode data for system snapshot."), true);
                system_snapshot_vnode_v_data_flag = ReadKernel32(system_snapshot_vnode_v_data + 49);
                LOG("system_snapshot_vnode_v_data_flag = 0x%x", system_snapshot_vnode_v_data_flag);
                WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag & ~0x40);
            }
            _assert(fs_snapshot_rename(rootfd, systemSnapshot, original_snapshot, 0) == ERR_SUCCESS, localize(@"Unable to rename system snapshot."), true);
            if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
                WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag);
                _assert(vnode_put(system_snapshot_vnode) == ERR_SUCCESS, localize(@"Unable to close system snapshot vnode."), true);
            }
            LOG("Successfully renamed system snapshot.");
            
            // Reboot.
            close(rootfd);
            
            LOG("Rebooting...");
            notice(localize(@"The system snapshot has been successfully renamed. The device will now be restarted."), true, false);
            _assert(reboot(RB_QUICK) == ERR_SUCCESS, localize(@"Unable to call reboot."), true);
            _assert(false, localize(@"Unable to reboot device."), true);
            LOG("Successfully rebooted.");
        } else {
            LOG("APFS Snapshots:");
            for (const char **snapshot = snapshots; *snapshot; snapshot++) {
                if (oldest_snapshot == NULL) {
                    oldest_snapshot = strdup(*snapshot);
                }
                if (strcmp(original_snapshot, *snapshot) == 0) {
                    has_original_snapshot = YES;
                }
                LOG("%s", *snapshot);
            }
        }
        
        kptr_t rootfs_vnode = get_vnode_for_path("/");
        LOG("rootfs_vnode = " ADDR, rootfs_vnode);
        _assert(KERN_POINTER_VALID(rootfs_vnode), localize(@"Unable to get vnode for RootFS."), true);
        kptr_t v_mount = ReadKernel64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
        LOG("v_mount = " ADDR, v_mount);
        _assert(KERN_POINTER_VALID(v_mount), localize(@"Unable to get mount info for RootFS."), true);
        uint32_t v_flag = ReadKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG));
        if ((v_flag & MNT_RDONLY) || (v_flag & MNT_NOSUID)) {
            v_flag &= ~(MNT_RDONLY | MNT_NOSUID);
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag & ~MNT_ROOTFS);
            char *opts = strdup(thedisk);
            _assert(opts != NULL, localize(@"Unable to allocate memory for ops."), true);
            _assert(mount("apfs", "/", MNT_UPDATE, (void *)&opts) == ERR_SUCCESS, localize(@"Unable to remount RootFS."), true);
            SafeFreeNULL(opts);
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag);
        }
        _assert(vnode_put(rootfs_vnode) == ERR_SUCCESS, localize(@"Unable to close RootFS vnode."), true);
        _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, localize(@"Unable to print new mount list."), false);
        NSString *const file = [NSString stringWithContentsOfFile:@"/.installed_unc0ver" encoding:NSUTF8StringEncoding error:nil];
        needStrap = file == nil;
        needStrap |= ![file isEqualToString:@""] && ![file isEqualToString:[NSString stringWithFormat:@"%f\n", kCFCoreFoundationVersionNumber]];
        needStrap &= access("/electra", F_OK) != ERR_SUCCESS;
        needStrap &= access("/chimera", F_OK) != ERR_SUCCESS;
        if (needStrap)
            LOG("We need strap.");
        if (!has_original_snapshot) {
            if (oldest_snapshot != NULL) {
                _assert(fs_snapshot_rename(rootfd, oldest_snapshot, original_snapshot, 0) == ERR_SUCCESS, localize(@"Unable to rename oldest snapshot."), true);
            } else if (needStrap) {
                _assert(fs_snapshot_create(rootfd, original_snapshot, 0) == ERR_SUCCESS, localize(@"Unable to create stock snapshot."), true);
            }
        }
        close(rootfd);
        SafeFreeNULL(snapshots);
        SafeFreeNULL(systemSnapshot);
        SafeFreeNULL(oldest_snapshot);
        LOG("Successfully remounted RootFS.");
        insertstatus(localize(@"Remounted RootFS.\n"));
    }
    
    upstage();
    
    {
        // Write a test file to RootFS.
        
        progress(localize(@"Writing a test file to RootFS..."));
        const char *testFile = [NSString stringWithFormat:@"/test-%lu.txt", time(NULL)].UTF8String;
        write_test_file(testFile);
        LOG("Successfully wrote a test file to RootFS.");
    }
    
    upstage();
    
    {
        NSArray *const array = @[@"/var/Keychains/ocspcache.sqlite3",
                                 @"/var/Keychains/ocspcache.sqlite3-shm",
                                 @"/var/Keychains/ocspcache.sqlite3-wal"];
        if (prefs->disable_app_revokes && kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber_iOS_12_0) {
            // Disable app revokes.
            progress(localize(@"Disabling app revokes..."));
            blockDomainWithName("ocsp.apple.com");
            for (id path in array) {
                ensure_symlink("/dev/null", [path UTF8String]);
            }
            LOG("Successfully disabled app revokes.");
            insertstatus(localize(@"Disabled App Revokes.\n"));
        } else {
            // Enable app revokes.
            progress(localize(@"Enabling app revokes..."));
            unblockDomainWithName("ocsp.apple.com");
            for (id path in array) {
                if (is_symlink([path UTF8String])) {
                    clean_file([path UTF8String]);
                }
            }
            LOG("Successfully enabled app revokes.");
            insertstatus(localize(@"Enabled App Revokes.\n"));
        }
    }
    
    upstage();
    
    {
        // Create jailbreak directory.
        
        progress(localize(@"Creating jailbreak directory..."));
        _assert(ensure_directory(jailbreakDirectory, root_pw->pw_uid, 0755), localize(@"Unable to create jailbreak directory."), true);
        _assert(chdir(jailbreakDirectory) == ERR_SUCCESS, localize(@"Unable to change working directory to jailbreak directory."), true);
        LOG("Successfully created jailbreak directory.");
        insertstatus(localize(@"Created jailbreak directory.\n"));
    }
    
    upstage();
    
    {
        NSString *const offsetsFile = NSJailbreakFile(@"offsets.plist");
        NSMutableDictionary *dictionary = [NSMutableDictionary new];
#define cache_address(value, name) do { \
    dictionary[@(name)] = ADDRSTRING(value); \
} while (false)
#define cache_offset(offset, name) cache_address(getoffset(offset), name)
        cache_address(kernel_base, "KernelBase");
        cache_address(kernel_slide, "KernelSlide");
        cache_offset(trustcache, "TrustChain");
        cache_address(ReadKernel64(getoffset(OSBoolean_True)), "OSBooleanTrue");
        cache_address(ReadKernel64(getoffset(OSBoolean_True)) + sizeof(kptr_t), "OSBooleanFalse");
        cache_offset(osunserializexml, "OSUnserializeXML");
        cache_offset(smalloc, "Smalloc");
        cache_offset(add_x0_x0_0x40_ret, "AddRetGadget");
        cache_offset(zone_map_ref, "ZoneMapOffset");
        cache_offset(vfs_context_current, "VfsContextCurrent");
        cache_offset(vnode_lookup, "VnodeLookup");
        cache_offset(vnode_put, "VnodePut");
        cache_offset(kernel_task, "KernelTask");
        cache_offset(shenanigans, "Shenanigans");
        cache_offset(lck_mtx_lock, "LckMtxLock");
        cache_offset(lck_mtx_unlock, "LckMtxUnlock");
        cache_offset(vnode_get_snapshot, "VnodeGetSnapshot");
        cache_offset(fs_lookup_snapshot_metadata_by_name_and_return_name, "FsLookupSnapshotMetadataByNameAndReturnName");
        cache_offset(pmap_load_trust_cache, "PmapLoadTrustCache");
        cache_offset(apfs_jhash_getvnode, "APFSJhashGetVnode");
        cache_offset(paciza_pointer__l2tp_domain_module_start, "PacizaPointerL2TPDomainModuleStart");
        cache_offset(paciza_pointer__l2tp_domain_module_stop, "PacizaPointerL2TPDomainModuleStop");
        cache_offset(l2tp_domain_inited, "L2TPDomainInited");
        cache_offset(sysctl__net_ppp_l2tp, "SysctlNetPPPL2TP");
        cache_offset(sysctl_unregister_oid, "SysctlUnregisterOid");
        cache_offset(mov_x0_x4__br_x5, "MovX0X4BrX5");
        cache_offset(mov_x9_x0__br_x1, "MovX9X0BrX1");
        cache_offset(mov_x10_x3__br_x6, "MovX10X3BrX6");
        cache_offset(kernel_forge_pacia_gadget, "KernelForgePaciaGadget");
        cache_offset(kernel_forge_pacda_gadget, "KernelForgePacdaGadget");
        cache_offset(IOUserClient__vtable, "IOUserClientVtable");
        cache_offset(IORegistryEntry__getRegistryEntryID, "IORegistryEntryGetRegistryEntryID");
        cache_offset(proc_find, "ProcFind");
        cache_offset(proc_rele, "ProcRele");
        cache_offset(extension_create_file, "ExtensionCreateFile");
        cache_offset(extension_add, "ExtensionAdd");
        cache_offset(extension_release, "ExtensionRelease");
        cache_offset(sfree, "Sfree");
        cache_offset(sstrdup, "Sstrdup");
        cache_offset(strlen, "Strlen");
#undef cache_offset
#undef cache_address
        if (![[NSMutableDictionary dictionaryWithContentsOfFile:offsetsFile] isEqual:dictionary]) {
            // Cache offsets.
            
            progress(localize(@"Caching offsets..."));
            _assert(([dictionary writeToFile:offsetsFile atomically:YES]), localize(@"Unable to cache offsets to file."), true);
            _assert(init_file(offsetsFile.UTF8String, root_pw->pw_uid, 0644), localize(@"Unable to set permissions for offset cache file."), true);
            LOG("Successfully cached offsets.");
            insertstatus(localize(@"Cached Offsets.\n"));
        }
    }
    
    upstage();
    
    {
        if (prefs->restore_rootfs) {
            progress(localize(@"Restoring RootFS..."));
            notice(localize(@"Will restore RootFS. This may take a while. Don't exit the app and don't let the device lock."), 1, 1);
            
            LOG("Reverting back RootFS remount...");
            int const rootfd = open("/", O_RDONLY);
            _assert(rootfd > 0, localize(@"Unable to open RootFS."), true);
            const char **snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, localize(@"Unable to get snapshots for RootFS."), true);
            _assert(*snapshots != NULL, localize(@"Found no snapshot for RootFS."), true);
            char *snapshot = strdup(*snapshots);
            LOG("%s", snapshot);
            _assert(snapshot != NULL, localize(@"Unable to find original snapshot for RootFS."), true);
            if (!(kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber_iOS_11_3)) {
                char *systemSnapshot = copySystemSnapshot();
                _assert(systemSnapshot != NULL, localize(@"Unable to copy system snapshot."), true);
                _assert(fs_snapshot_rename(rootfd, snapshot, systemSnapshot, 0) == ERR_SUCCESS, localize(@"Unable to rename original snapshot."), true);
                SafeFreeNULL(snapshot);
                snapshot = strdup(systemSnapshot);
                _assert(snapshot != NULL, localize(@"Unable to duplicate string."), true);
                SafeFreeNULL(systemSnapshot);
            }
            char *const systemSnapshotMountPoint = "/private/var/tmp/jb/mnt2";
            if (is_mountpoint(systemSnapshotMountPoint)) {
                _assert(unmount(systemSnapshotMountPoint, MNT_FORCE) == ERR_SUCCESS, localize(@"Unable to unmount old snapshot mount point."), true);
            }
            _assert(clean_file(systemSnapshotMountPoint), localize(@"Unable to clean old snapshot mount point."), true);
            _assert(ensure_directory(systemSnapshotMountPoint, root_pw->pw_uid, 0755), localize(@"Unable to create snapshot mount point."), true);
            _assert(fs_snapshot_mount(rootfd, systemSnapshotMountPoint, snapshot, 0) == ERR_SUCCESS, localize(@"Unable to mount original snapshot."), true);
            const char *systemSnapshotLaunchdPath = [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
            _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, localize(@"Unable to verify mounted snapshot."), true);
            _assert(extractDebsForPkg(@"rsync", nil, false, true), localize(@"Unable to extract rsync."), true);
            _assert(extractDebsForPkg(@"uikittools", nil, false, true), localize(@"Unable to extract uikittools."), true);
            inject_trust_cache();
            if (kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber_iOS_11_3) {
                _assert(runCommand("/usr/bin/rsync", "-vaxcH", "--progress", "--delete-after", "--exclude=/Developer", "--exclude=/usr/bin/uicache", "--exclude=/usr/bin/find", [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"."].UTF8String, "/", NULL) == 0, localize(@"Unable to sync /."), true);
            } else {
                _assert(runCommand("/usr/bin/rsync", "-vaxcH", "--progress", "--delete", [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"Applications/."].UTF8String, "/Applications", NULL) == 0, localize(@"Unable to sync /Applications."), true);
            }
            _assert(unmount(systemSnapshotMountPoint, MNT_FORCE) == ERR_SUCCESS, localize(@"Unable to unmount original snapshot mount point."), true);
            close(rootfd);
            SafeFreeNULL(snapshot);
            SafeFreeNULL(snapshots);
            _assert(runCommand("/usr/bin/uicache", NULL) >= 0, localize(@"Unable to refresh icon cache."), true);
            _assert(clean_file("/usr/bin/uicache"), localize(@"Unable to clean uicache binary."), true);
            _assert(clean_file("/usr/bin/find"), localize(@"Unable to clean find binary."), true);
            LOG("Successfully reverted back RootFS remount.");
            
            // Clean up.
            
            LOG("Cleaning up...");
            NSArray *const cleanUpFileList = @[@"/var/cache",
                                               @"/var/lib",
                                               @"/var/stash",
                                               @"/var/db/stash",
                                               @"/var/mobile/Library/Cydia",
                                               @"/var/mobile/Library/Caches/com.saurik.Cydia"];
            for (id file in cleanUpFileList) {
                clean_file([file UTF8String]);
            }
            LOG("Successfully cleaned up.");
            
            // Disallow SpringBoard to show non-default system apps.
            
            LOG("Disallowing SpringBoard to show non-default system apps...");
            _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.springboard.plist", ^(id plist) {
                plist[@"SBShowNonDefaultSystemApps"] = @NO;
            }), localize(@"Unable to update SpringBoard preferences."), true);
            LOG("Successfully disallowed SpringBoard to show non-default system apps.");
            
            // Disable RootFS Restore.
            
            LOG("Disabling RootFS Restore...");
            prefs->restore_rootfs = false;
            sync_prefs();
            LOG("Successfully disabled RootFS Restore.");
            
            insertstatus(localize(@"Restored RootFS.\n"));
            
            // Reboot.
            
            LOG("Rebooting...");
            notice(localize(@"RootFS has been successfully restored. The device will now be restarted."), true, false);
            _assert(reboot(RB_QUICK) == ERR_SUCCESS, localize(@"Unable to call reboot."), true);
            _assert(false, localize(@"Unable to reboot device."), true);
            LOG("Successfully rebooted.");
        }
    }
    
    upstage();
    
    {
        // Allow SpringBoard to show non-default system apps.
        
        progress(localize(@"Allowing SpringBoard to show non-default system apps..."));
        _assert(modifyPlist(@"/var/mobile/Library/Preferences/com.apple.springboard.plist", ^(id plist) {
            plist[@"SBShowNonDefaultSystemApps"] = @YES;
        }), localize(@"Unable to update SpringBoard preferences."), true);
        LOG("Successfully allowed SpringBoard to show non-default system apps.");
        insertstatus(localize(@"Allowed SpringBoard to show non-default system apps.\n"));
    }
    
    upstage();
    
    if (prefs->ssh_only && needStrap) {
        progress(localize(@"Enabling SSH..."));
        NSMutableArray *toInject = [NSMutableArray new];
        if (!verifySums(pathForResource(@"binpack64-256.md5sums"), HASHTYPE_MD5)) {
            ArchiveFile *const binpack64 = [ArchiveFile archiveWithFile:pathForResource(@"binpack64-256.tar.lzma")];
            _assert(binpack64 != nil, localize(@"Unable to open binpack."), true);
            _assert([binpack64 extractToPath:NSJailbreakDirectory], localize(@"Unable to extract binpack."), true);
            for (id file in binpack64.files.allKeys) {
                NSString *const path = [NSJailbreakDirectory stringByAppendingPathComponent:file];
                if (cdhashFor(path) != nil) {
                    if (![toInjectToTrustCache containsObject:path]) {
                        [toInjectToTrustCache addObject:path];
                    }
                }
            }
        }
        NSDirectoryEnumerator *directoryEnumerator = [fileManager enumeratorAtURL:[NSURL URLWithString:NSJailbreakDirectory] includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:nil];
        _assert(directoryEnumerator != nil, localize(@"Unable to create directory enumerator."), true);
        for (id URL in directoryEnumerator) {
            NSString *const path = [URL path];
            if (cdhashFor(path) != nil) {
                if (![toInjectToTrustCache containsObject:path]) {
                    [toInjectToTrustCache addObject:path];
                }
            }
        }
        for (id file in [fileManager contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
            NSString *const path = [@"/Applications" stringByAppendingPathComponent:file];
            NSMutableDictionary *const info_plist = [NSMutableDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
            if (info_plist == nil) continue;
            if ([info_plist[@"CFBundleIdentifier"] hasPrefix:@"com.apple."]) continue;
            directoryEnumerator = [fileManager enumeratorAtURL:[NSURL URLWithString:path] includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:nil];
            if (directoryEnumerator == nil) continue;
            for (id URL in directoryEnumerator) {
                NSString *const path = [URL path];
                if (cdhashFor(path) != nil) {
                    if (![toInjectToTrustCache containsObject:path]) {
                        [toInjectToTrustCache addObject:path];
                    }
                }
            }
        }
        inject_trust_cache();
        NSString *const binpackMessage = localize(@"Unable to setup binpack.");
        _assert(ensure_symlink(jailbreak_file("usr/bin/scp"), "/usr/bin/scp"), binpackMessage, true);
        _assert(ensure_directory("/usr/local/lib", root_pw->pw_uid, 0755), binpackMessage, true);
        _assert(ensure_directory("/usr/local/lib/zsh", root_pw->pw_uid, 0755), binpackMessage, true);
        _assert(ensure_directory("/usr/local/lib/zsh/5.0.8", root_pw->pw_uid, 0755), binpackMessage, true);
        _assert(ensure_symlink(jailbreak_file("/usr/local/lib/zsh/5.0.8/zsh"), "/usr/local/lib/zsh/5.0.8/zsh"), binpackMessage, true);
        _assert(ensure_symlink(jailbreak_file("bin/zsh"), "/bin/zsh"), binpackMessage, true);
        _assert(ensure_symlink(jailbreak_file("etc/zshrc"), "/etc/zshrc"), binpackMessage, true);
        _assert(ensure_symlink(jailbreak_file("usr/share/terminfo"), "/usr/share/terminfo"), binpackMessage, true);
        _assert(ensure_symlink(jailbreak_file("usr/local/bin"), "/usr/local/bin"), binpackMessage, true);
        _assert(ensure_symlink(jailbreak_file("etc/profile"), "/etc/profile"), binpackMessage, true);
        _assert(ensure_directory("/etc/dropbear", root_pw->pw_uid, 0755), binpackMessage, true);
        _assert(ensure_directory(jailbreak_file("Library"), root_pw->pw_uid, 0755), binpackMessage, true);
        _assert(ensure_directory(jailbreak_file("Library/LaunchDaemons"), root_pw->pw_uid, 0755), binpackMessage, true);
        _assert(ensure_directory(jailbreak_file("etc/rc.d"), root_pw->pw_uid, 0755), binpackMessage, true);
        if (access(jailbreak_file("Library/LaunchDaemons/dropbear.plist"), F_OK) != ERR_SUCCESS) {
            NSMutableDictionary *dropbear_plist = [NSMutableDictionary new];
            _assert(dropbear_plist, localize(@"Unable to allocate memory for dropbear plist."), true);
            dropbear_plist[@"Program"] = NSJailbreakFile(@"usr/local/bin/dropbear");
            dropbear_plist[@"RunAtLoad"] = @YES;
            dropbear_plist[@"Label"] = @"ShaiHulud";
            dropbear_plist[@"KeepAlive"] = @YES;
            dropbear_plist[@"ProgramArguments"] = [NSMutableArray new];
            dropbear_plist[@"ProgramArguments"][0] = @"/usr/local/bin/dropbear";
            dropbear_plist[@"ProgramArguments"][1] = @"-F";
            dropbear_plist[@"ProgramArguments"][2] = @"-R";
            dropbear_plist[@"ProgramArguments"][3] = @"--shell";
            dropbear_plist[@"ProgramArguments"][4] = NSJailbreakFile(@"bin/bash");
            dropbear_plist[@"ProgramArguments"][5] = @"-p";
            dropbear_plist[@"ProgramArguments"][6] = @"22";
            _assert([dropbear_plist writeToFile:NSJailbreakFile(@"Library/LaunchDaemons/dropbear.plist") atomically:YES], localize(@"Unable to create dropbear launch daemon."), true);
            _assert(init_file(jailbreak_file("Library/LaunchDaemons/dropbear.plist"), root_pw->pw_uid, 0644), localize(@"Unable to initialize dropbear launch daemon."), true);
        }
        if (prefs->load_daemons) {
            for (id file in [fileManager contentsOfDirectoryAtPath:NSJailbreakFile(@"Library/LaunchDaemons") error:nil]) {
                NSString *const path = [NSJailbreakFile(@"Library/LaunchDaemons") stringByAppendingPathComponent:file];
                runCommand(jailbreak_file("bin/launchctl"), "load", path.UTF8String, NULL);
            }
            for (id file in [fileManager contentsOfDirectoryAtPath:NSJailbreakFile(@"etc/rc.d") error:nil]) {
                NSString *const path = [NSJailbreakFile(@"etc/rc.d") stringByAppendingPathComponent:file];
                if ([fileManager isExecutableFileAtPath:path]) {
                    runCommand(jailbreak_file("bin/bash"), "-c", path.UTF8String, NULL);
                }
            }
        }
        if (prefs->run_uicache) {
            _assert(runCommand(jailbreak_file("usr/bin/uicache"), NULL) == ERR_SUCCESS, localize(@"Unable to refresh icon cache."), true);
        }
        _assert(runCommand(jailbreak_file("bin/launchctl"), "stop", "com.apple.cfprefsd.xpc.daemon", NULL) == ERR_SUCCESS, localize(@"Unable to flush preference cache."), true);
        LOG("Successfully enabled SSH.");
        insertstatus(localize(@"Enabled SSH.\n"));
    }
    
    if (prefs->code_substitutor != -1) {
        substitutor = get_substitutor_info(prefs->code_substitutor);
        _assert(substitutor != NULL, localize(@"Unable to get substitutor info."), true);
    } else {
        goto out;
    }
    
    upstage();
    
    {
        // Copy over resources to RootFS.
        
        progress(localize(@"Copying over resources to RootFS..."));
        
        _assert(chdir("/") == ERR_SUCCESS, localize(@"Unable to change working directory to RootFS."), true);
        
        // Uninstall RootLessJB if it is found to prevent conflicts with dpkg.
        _assert(uninstallRootLessJB(), localize(@"Unable to uninstall RootLessJB."), true);
        
        // Make sure we have an apt packages cache
        _assert(ensureAptPkgLists(), localize(@"Unable to extract apt package lists."), true);
        
        needSubstitutor = ( needStrap ||
                         (access(substitutor->startup_executable, F_OK) != ERR_SUCCESS) ||
                         !verifySums([NSString stringWithFormat:@"/var/lib/dpkg/info/%s.md5sums", substitutor->package_id], HASHTYPE_MD5)
                         );
        if (needSubstitutor) {
            LOG(@"We need %s.", substitutor->name);
            NSString *const substitutorDeb = debForPkg(@(substitutor->package_id));
            _assert(substitutor != nil, localize(@"Unable to get deb for %s.", substitutor->name), true);
            if (pidOfProcess(substitutor->server_executable) == 0) {
                _assert(extractDeb(substitutorDeb, doInject), localize(@"Unable to extract %s.", substitutor->name), true);
            } else {
                skipSubstitutor = YES;
                LOG("%s is running, not extracting again for now.", substitutor->name);
            }
            [debsToInstall addObject:substitutorDeb];
        }
        
        NSArray *resourcesPkgs = resolveDepsForPkg(@"jailbreak-resources", true);
        _assert(resourcesPkgs != nil, localize(@"Unable to get resource packages."), true);
        resourcesPkgs = [@[@"system-memory-reset-fix"] arrayByAddingObjectsFromArray:resourcesPkgs];
        if (betaFirmware) {
            resourcesPkgs = [@[@"com.parrotgeek.nobetaalert"] arrayByAddingObjectsFromArray:resourcesPkgs];
        }
        if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
            resourcesPkgs = [@[@"com.ps.letmeblock"] arrayByAddingObjectsFromArray:resourcesPkgs];
        }
        
        NSMutableArray *pkgsToRepair = [NSMutableArray new];
        LOG("Resource Pkgs: \"%@\".", resourcesPkgs);
        for (id pkg in resourcesPkgs) {
            // Ignore substitutor because we just handled that separately.
            if ([pkg isEqualToString:@(substitutor->package_id)] || [pkg isEqualToString:@"firmware"])
                continue;
            if (verifySums([NSString stringWithFormat:@"/var/lib/dpkg/info/%@.md5sums", pkg], HASHTYPE_MD5)) {
                LOG("Pkg \"%@\" verified.", pkg);
            } else {
                LOG(@"Need to repair \"%@\".", pkg);
                if ([pkg isEqualToString:@"signing-certificate"]) {
                    // Hack to make sure it catches the Depends: version if it's already installed
                    [debsToInstall addObject:debForPkg(@"jailbreak-resources")];
                }
                [pkgsToRepair addObject:pkg];
            }
        }
        if (pkgsToRepair.count > 0) {
            LOG(@"(Re-)Extracting \"%@\".", pkgsToRepair);
            NSArray <NSString *> *const debsToRepair = debsForPkgs(pkgsToRepair);
            _assert(debsToRepair.count == pkgsToRepair.count, localize(@"Unable to get debs for packages to repair."), true);
            _assert(extractDebs(debsToRepair, doInject), localize(@"Unable to repair packages."), true);
            [debsToInstall addObjectsFromArray:debsToRepair];
        }
        
        // Ensure ldid's symlink isn't missing
        // (it's created by update-alternatives which may not have been called yet)
        if (access("/usr/bin/ldid", F_OK) != ERR_SUCCESS) {
            _assert(access("/usr/libexec/ldid", F_OK) == ERR_SUCCESS, localize(@"Unable to access ldid."), true);
            _assert(ensure_symlink("../libexec/ldid", "/usr/bin/ldid"), localize(@"Unable to create symlink for ldid."), true);
        }
        
        // These don't need to lay around
        clean_file("/Library/LaunchDaemons/jailbreakd.plist");
        clean_file(jailbreak_file("jailbreakd.plist"));
        clean_file(jailbreak_file("amfid_payload.dylib"));
        clean_file(jailbreak_file("libjailbreak.dylib"));
        
        LOG("Successfully copied over resources to RootFS.");
        insertstatus(localize(@"Copied over resources to RootFS.\n"));
    }
    
    upstage();
    
    {
        // Inject trust cache
        
        progress(localize(@"Injecting trust cache..."));
        [resources addObjectsFromArray:[NSArray arrayWithContentsOfFile:@"/usr/share/jailbreak/injectme.plist"]];
        // If substitutor is already running but was broken, skip injecting again
        if (!skipSubstitutor) {
            [resources addObject:@(substitutor->startup_executable)];
        }
        for (char **resource = substitutor->resources; *resource; resource++) {
            [resources addObject:@(*resource)];
        }
        for (id file in resources) {
            if (![toInjectToTrustCache containsObject:file]) {
                [toInjectToTrustCache addObject:file];
            }
        }
        inject_trust_cache();
        LOG("Successfully injected trust cache.");
        insertstatus(localize(@"Injected trust cache.\n"));
    }
    
    upstage();
    
    {
        // Repair filesystem.
        
        progress(localize(@"Repairing filesystem..."));
        
        _assert(ensure_directory("/var/lib", root_pw->pw_uid, 0755), localize(@"Unable to repair state information directory"), true);
        
        // Make sure dpkg is not corrupted
        if (is_directory("/var/lib/dpkg")) {
            if (is_directory("/Library/dpkg")) {
                LOG(@"Removing /var/lib/dpkg...");
                _assert(clean_file("/var/lib/dpkg"), localize(@"Unable to clean old dpkg database."), true);
            } else {
                LOG(@"Moving /var/lib/dpkg to /Library/dpkg...");
                _assert([fileManager moveItemAtPath:@"/var/lib/dpkg" toPath:@"/Library/dpkg" error:nil], localize(@"Unable to restore dpkg database."), true);
            }
        }
        
        _assert(ensure_symlink("/Library/dpkg", "/var/lib/dpkg"), localize(@"Unable to symlink dpkg database."), true);
        _assert(ensure_directory("/Library/dpkg", root_pw->pw_uid, 0755), localize(@"Unable to repair dpkg database."), true);
        _assert(ensure_file("/var/lib/dpkg/status", root_pw->pw_uid, 0644), localize(@"Unable to repair dpkg status file."), true);
        _assert(ensure_file("/var/lib/dpkg/available", root_pw->pw_uid, 0644), localize(@"Unable to repair dpkg available file."), true);
        
        // Make sure firmware-sbin package is not corrupted.
        NSString *file = [NSString stringWithContentsOfFile:@"/var/lib/dpkg/info/firmware-sbin.list" encoding:NSUTF8StringEncoding error:nil];
        if ([file containsString:@"/sbin/fstyp"] || [file containsString:@"\n\n"]) {
            // This is not a stock file for iOS11+
            file = [file stringByReplacingOccurrencesOfString:@"/sbin/fstyp\n" withString:@""];
            file = [file stringByReplacingOccurrencesOfString:@"\n\n" withString:@"\n"];
            [file writeToFile:@"/var/lib/dpkg/info/firmware-sbin.list" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        
        // Make sure this is a symlink - usually handled by ncurses pre-inst
        _assert(ensure_symlink("/usr/lib", "/usr/lib/_ncurses"), localize(@"Unable to repair ncurses."), true);
        
        // This needs to be there for substitutor to work properly
        _assert(ensure_directory("/Library/Caches", root_pw->pw_uid, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO), localize(@"Unable to repair caches directory for %s.", substitutor->name), true);
        LOG("Successfully repaired filesystem.");
        
        insertstatus(localize(@"Repaired Filesystem.\n"));
    }
    
    upstage();
    
    {
        // Load substitutor
        
        // Configure substitutor.
        progress(localize(@"Configuring %s...", substitutor->name));
        if (prefs->load_tweaks) {
            clean_file(substitutor->loader_killswitch);
        } else {
            _assert(create_file(substitutor->loader_killswitch, root_pw->pw_uid, 644), localize(@"Unable to disable %s's loader.", substitutor->name), true);
        }
        LOG("Successfully configured %s.", substitutor->name);
        
        // Run substitutor
        progress(localize(@"Starting %s...", substitutor->name));
        if (access("/Library/substrate", F_OK) == ERR_SUCCESS &&
            is_directory("/Library/substrate") &&
            access(substitutor->bootstrap_tools, F_OK) == ERR_SUCCESS &&
            is_symlink(substitutor->bootstrap_tools)) {
            _assert(clean_file(substitutor->bootstrap_tools), localize(@"Unable to clean old %s bootstrap tools directory.", substitutor->name), true);
            _assert([fileManager moveItemAtPath:@"/Library/substrate" toPath:@(substitutor->bootstrap_tools) error:nil], localize(@"Unable to move %s bootstrap tools directory.", substitutor->name), true);
        }
        _assert(runCommand(substitutor->startup_executable, NULL) == ERR_SUCCESS, localize(@"Unable to %@ %s.", skipSubstitutor ? @"restart" : @"start", substitutor->name), skipSubstitutor?false:true);
        LOG("Successfully started %s.", substitutor->name);
        
        insertstatus(localize(@"Loaded %s.\n", substitutor->name));
    }
    
    upstage();
    
    {
        // Extract bootstrap.
        progress(localize(@"Extracting bootstrap..."));
        
        if (!pkgIsConfigured("xz")) {
            removePkg("lzma", true);
            extractDebsForPkg(@"lzma", debsToInstall, false, doInject);
            inject_trust_cache();
        }
        
        if (pkgIsInstalled("openssl") && compareInstalledVersion("openssl", "lt", "1.0.2q")) {
            removePkg("openssl", true);
        }
        
        // Test dpkg
        if (!pkgIsConfigured("dpkg")) {
            LOG("Extracting dpkg...");
            _assert(extractDebsForPkg(@"dpkg", debsToInstall, false, doInject), localize(@"Unable to extract dpkg."), true);
            inject_trust_cache();
            NSString *const dpkg_deb = debForPkg(@"dpkg");
            _assert(installDeb(dpkg_deb.UTF8String, true), localize(@"Unable to install deb for dpkg."), true);
            [debsToInstall removeObject:dpkg_deb];
        }
        
        if (needStrap || !pkgIsConfigured("firmware")) {
            if (access("/usr/libexec/cydia/firmware.sh", F_OK) != ERR_SUCCESS || !pkgIsConfigured("cydia")) {
                LOG("Extracting Cydia...");
                NSArray <NSString *> *const fwDebs = debsForPkgs(@[@"cydia", @"cydia-lproj", @"darwintools", @"uikittools", @"system-cmds"]);
                _assert(fwDebs != nil, localize(@"Unable to get firmware debs."), true);
                _assert(installDebs(fwDebs, true, false), localize(@"Unable to install firmware debs."), true);
            }
            rv = _system("/usr/libexec/cydia/firmware.sh");
            _assert(WEXITSTATUS(rv) == 0, localize(@"Unable to create virtual dependencies."), true);
        }
        
        // Dpkg better work now
        
        if (pkgIsInstalled("science.xnu.undecimus.resources")) {
            LOG("Removing old resources...");
            _assert(removePkg("science.xnu.undecimus.resources", true), localize(@"Unable to remove old resources."), true);
        }
        
        if (pkgIsInstalled("jailbreak-resources-with-cert")) {
            LOG("Removing resources-with-cert...");
            _assert(removePkg("jailbreak-resources-with-cert", true), localize(@"Unable to remove old-development resources."), true);
        }
        
        if ((pkgIsInstalled("apt7") && compareInstalledVersion("apt7", "lt", "1:0")) ||
            (pkgIsInstalled("apt7-lib") && compareInstalledVersion("apt7-lib", "lt", "1:0")) ||
            (pkgIsInstalled("apt7-key") && compareInstalledVersion("apt7-key", "lt", "1:0"))
            ) {
            LOG("Installing newer version of apt7");
            NSArray <NSString *> *const apt7debs = debsForPkgs(@[@"apt7", @"apt7-key", @"apt7-lib"]);
            _assert(apt7debs != nil && apt7debs.count == 3, localize(@"Unable to get debs for apt7."), true);
            for (id deb in apt7debs) {
                if (![debsToInstall containsObject:deb]) {
                    [debsToInstall addObject:deb];
                }
            }
        }
        
        if (debsToInstall.count > 0) {
            LOG("Installing manually exctracted debs...");
            _assert(installDebs(debsToInstall, true, true), localize(@"Unable to install manually extracted debs."), true);
        }
        
        _assert(ensure_directory("/etc/apt/undecimus", root_pw->pw_uid, 0755), localize(@"Unable to create local repo."), true);
        clean_file("/etc/apt/sources.list.d/undecimus.list");
        char const *listPath = "/etc/apt/undecimus/undecimus.list";
        NSString *const listContents = @"deb file:///var/lib/undecimus/apt ./\n";
        NSString *const existingList = [NSString stringWithContentsOfFile:@(listPath) encoding:NSUTF8StringEncoding error:nil];
        if (![listContents isEqualToString:existingList]) {
            clean_file(listPath);
            [listContents writeToFile:@(listPath) atomically:NO encoding:NSUTF8StringEncoding error:nil];
        }
        init_file(listPath, root_pw->pw_uid, 0644);
        const char *prefsPath = "/etc/apt/undecimus/preferences";
        NSString *prefsContents = @"Package: *\nPin: release o=Undecimus\nPin-Priority: 1001\n";
        NSString *existingPrefs = [NSString stringWithContentsOfFile:@(prefsPath) encoding:NSUTF8StringEncoding error:nil];
        if (![prefsContents isEqualToString:existingPrefs]) {
            clean_file(prefsPath);
            [prefsContents writeToFile:@(prefsPath) atomically:NO encoding:NSUTF8StringEncoding error:nil];
        }
        init_file(prefsPath, root_pw->pw_uid, 0644);
        NSString *const repoPath = pathForResource(@"apt");
        _assert(repoPath != nil, localize(@"Unable to get repo path."), true);
        ensure_directory("/var/lib/undecimus", root_pw->pw_uid, 0755);
        ensure_symlink([repoPath UTF8String], "/var/lib/undecimus/apt");
        if (!pkgIsConfigured("apt1.4") || !aptUpdate()) {
            NSArray *const aptNeeded = resolveDepsForPkg(@"apt1.4", false);
            _assert(aptNeeded != nil && aptNeeded.count > 0, localize(@"Unable to resolve dependencies for apt."), true);
            NSArray <NSString *> *const aptDebs = debsForPkgs(aptNeeded);
            _assert(installDebs(aptDebs, true, true), localize(@"Unable to install debs for apt."), true);
            _assert(aptUpdate(), localize(@"Unable to update apt package index."), true);
            _assert(aptRepair(), localize(@"Unable to repair system."), true);
        }
        
        // Workaround for what appears to be an apt bug
        ensure_symlink("/var/lib/undecimus/apt/./Packages", "/var/lib/apt/lists/_var_lib_undecimus_apt_._Packages");
        
        if (!aptInstall(@[@"-f"])) {
            _assert(aptRepair(), localize(@"Unable to repair system."), true);
        }
        
        // Dpkg and apt both work now
        
        if (needStrap) {
            prefs->run_uicache = true;
            sync_prefs();
        }
        // Now that things are running, let's install the deb for the files we just extracted
        if (needSubstitutor) {
            if (pkgIsInstalled("com.ex.substitute")) {
                _assert(removePkg("com.ex.substitute", true), localize(@"Unable to remove Substitute."), true);
            }
            _assert(aptInstall(@[@(substitutor->package_id)]), localize(@"Unable to install %s.", substitutor->name), true);
        }
        if (!betaFirmware) {
            if (pkgIsInstalled("com.parrotgeek.nobetaalert")) {
                _assert(removePkg("com.parrotgeek.nobetaalert", true), localize(@"Unable to remove NoBetaAlert."), true);
            }
        }
        if (!(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0)) {
            if (pkgIsInstalled("com.ps.letmeblock")) {
                _assert(removePkg("com.ps.letmeblock", true), localize(@"Unable to remove LetMeBlock."), true);
            }
        }
        
        NSData *const file_data = [[NSString stringWithFormat:@"%f\n", kCFCoreFoundationVersionNumber] dataUsingEncoding:NSUTF8StringEncoding];
        if (![[NSData dataWithContentsOfFile:@"/.installed_unc0ver"] isEqual:file_data]) {
            _assert(clean_file("/.installed_unc0ver"), localize(@"Unable to clean old bootstrap marker file."), true);
            _assert(create_file_data("/.installed_unc0ver", root_pw->pw_uid, 0644, file_data), localize(@"Unable to create bootstrap marker file."), true);
        }
        
        _assert(ensure_file("/.cydia_no_stash", root_pw->pw_uid, 0644), localize(@"Unable to disable stashing."), true);
        
        // Make sure everything's at least as new as what we bundled
        rv = system("dpkg --configure -a");
        _assert(WEXITSTATUS(rv) == ERR_SUCCESS, localize(@"Unable to configure installed packages."), false);
        _assert(aptUpgrade(), localize(@"Unable to upgrade apt packages."), false);
        
        // Make sure resources are injected to trust cache
        [toInjectToTrustCache addObjectsFromArray:resources];
        inject_trust_cache();
        
        clean_file(jailbreak_file("tar"));
        clean_file(jailbreak_file("lzma"));
        clean_file(jailbreak_file("substrate.tar.lzma"));
        clean_file("/electra");
        clean_file("/chimera");
        clean_file("/.bootstrapped_electra");
        clean_file([NSString stringWithFormat:@"/etc/.installed-chimera-%@", getECID()].UTF8String);
        clean_file("/usr/lib/libjailbreak.dylib");
        
        LOG("Successfully extracted bootstrap.");
        
        insertstatus(localize(@"Extracted Bootstrap.\n"));
    }
    
    upstage();
    
    {
        // Fix storage preferences.
        
        progress(localize(@"Fixing storage preferences..."));
        if (access("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", "/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/Support/softwareupdated") == ERR_SUCCESS, localize(@"Unable to to fix path for softwareupdated."), false);
        }
        if (access("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", "/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/Support/softwareupdateservicesd") == ERR_SUCCESS, localize(@"Unable to fix path for softwareupdateservicesd."), false);
        }
        if (access("/System/Library/com.apple.mobile.softwareupdated.plist", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/com.apple.mobile.softwareupdated.plist", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist") == ERR_SUCCESS, localize(@"Unable to fix path for softwareupdated launch daemon."), false);
            _assert(runCommand("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist", NULL) == ERR_SUCCESS, localize(@"Unable to load softwareupdated launch daemon."), false);
        }
        if (access("/System/Library/com.apple.softwareupdateservicesd.plist", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/com.apple.softwareupdateservicesd.plist", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist") == ERR_SUCCESS, localize(@"Unable to fix path for softwareupdateservicesd launch daemon."), false);
            _assert(runCommand("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist", NULL) == ERR_SUCCESS, localize(@"Unable to load softwareupdateservicesd launch daemon."), false);
        }
        LOG("Successfully fixed storage preferences.");
        insertstatus(localize(@"Fixed Storage Preferences.\n"));
    }
    
    upstage();
    
    {
        char *targettype = sysctlWithName("hw.targettype");
        _assert(targettype != NULL, localize(@"Unable to get hardware targettype."), true);
        NSString *const jetsamFile = [NSString stringWithFormat:@"/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", targettype];
        SafeFreeNULL(targettype);
        
        if (prefs->increase_memory_limit) {
            // Increase memory limit.
            
            progress(localize(@"Increasing memory limit..."));
            _assert(modifyPlist(jetsamFile, ^(id plist) {
                plist[@"Version4"][@"System"][@"Override"][@"Global"][@"UserHighWaterMark"] = [NSNumber numberWithInteger:[plist[@"Version4"][@"PListDevice"][@"MemoryCapacity"] integerValue]];
            }), localize(@"Unable to update Jetsam plist to increase memory limit."), true);
            LOG("Successfully increased memory limit.");
            insertstatus(localize(@"Increased Memory Limit.\n"));
        } else {
            // Restore memory limit.
            
            progress(localize(@"Restoring memory limit..."));
            _assert(modifyPlist(jetsamFile, ^(id plist) {
                plist[@"Version4"][@"System"][@"Override"][@"Global"][@"UserHighWaterMark"] = nil;
            }), localize(@"Unable to update Jetsam plist to restore memory limit."), true);
            LOG("Successfully restored memory limit.");
            insertstatus(localize(@"Restored Memory Limit.\n"));
        }
    }
    
    upstage();
    
    {
        if (prefs->install_openssh) {
            // Install OpenSSH.
            progress(localize(@"Installing OpenSSH..."));
            _assert(aptInstall(@[@"openssh"]), localize(@"Unable to install OpenSSH."), true);
            prefs->install_openssh = false;
            sync_prefs();
            LOG("Successfully installed OpenSSH.");
            
            insertstatus(localize(@"Installed OpenSSH.\n"));
        }
    }
    
    upstage();
    
    {
        if (pkgIsInstalled("cydia-gui")) {
            // Remove Electra's Cydia.
            progress(localize(@"Removing Cydia Dummy Package..."));
            _assert(removePkg("cydia-gui", true), localize(@"Unable to remove Cydia Dummy Package."), true);
            prefs->install_cydia = true;
            prefs->run_uicache = true;
            sync_prefs();
            LOG("Successfully removed Cydia Dummy Package.");
            
            insertstatus(localize(@"Removed Cydia Dummy Package.\n"));
        }
        deduplicateSillySources();
        if (pkgIsInstalled("cydia-upgrade-helper")) {
            // Remove Electra's Cydia Upgrade Helper.
            progress(localize(@"Removing Electra's Cydia Upgrade Helper..."));
            _assert(removePkg("cydia-upgrade-helper", true), localize(@"Unable to remove Electra's Cydia Upgrade Helper."), true);
            prefs->install_cydia = true;
            prefs->run_uicache = true;
            sync_prefs();
            LOG("Successfully removed Electra's Cydia Upgrade Helper.");
        }
        if (access("/etc/apt/sources.list.d/electra.list", F_OK) == ERR_SUCCESS ||
            access("/etc/apt/sources.list.d/chimera.sources", F_OK) == ERR_SUCCESS) {
            prefs->install_cydia = true;
            prefs->run_uicache = true;
            sync_prefs();
        }
        // Unblock Saurik's repo if it is blocked.
        unblockDomainWithName("apt.saurik.com");
        if (prefs->install_cydia) {
            // Install Cydia.
            
            progress(localize(@"Installing Cydia..."));
            NSString *const cydiaVer = versionOfPkg(@"cydia");
            _assert(cydiaVer != nil, localize(@"Unable to get Cydia version."), true);
            _assert(aptInstall(@[@"--reinstall", [@"cydia" stringByAppendingFormat:@"=%@", cydiaVer]]), localize(@"Unable to reinstall Cydia."), true);
            prefs->install_cydia = false;
            prefs->run_uicache = true;
            sync_prefs();
            LOG("Successfully installed Cydia.");
            
            insertstatus(localize(@"Installed Cydia.\n"));
        }
    }
    
    upstage();
    
    {
        if (prefs->load_daemons) {
            // Load Daemons.
            
            progress(localize(@"Loading Daemons..."));
            system("echo 'really jailbroken';"
                   "shopt -s nullglob;"
                   "for a in /Library/LaunchDaemons/*.plist;"
                   "do echo loading $a;"
                   "launchctl load \"$a\" ;"
                   "done; ");
            // Substitutor is already running, no need to run it again
            systemf("for file in /etc/rc.d/*; do "
                    "if [[ -x \"$file\" && \"$file\" != \"%s\" ]]; then "
                    "\"$file\";"
                    "fi;"
                    "done", substitutor->run_command);
            LOG("Successfully loaded Daemons.");
            
            insertstatus(localize(@"Loaded Daemons.\n"));
        }
    }
    
    upstage();
    
    {
        if (prefs->reset_cydia_cache) {
            // Reset Cydia cache.
            
            progress(localize(@"Resetting Cydia cache..."));
            _assert(clean_file("/var/mobile/Library/Cydia"), localize(@"Unable to clean Cydia's directory."), true);
            _assert(clean_file("/var/mobile/Library/Caches/com.saurik.Cydia"), localize(@"Unable to clean Cydia's cache directory."), true);
            prefs->reset_cydia_cache = false;
            sync_prefs();
            LOG("Successfully reset Cydia cache.");
            
            insertstatus(localize(@"Reset Cydia Cache.\n"));
        }
    }
    
    upstage();
    
    {
        if (prefs->run_uicache || !cydiaIsInstalled()) {
            // Run uicache.
            
            progress(localize(@"Refreshing icon cache..."));
            _assert(runCommand("/usr/bin/uicache", NULL) >= 0, localize(@"Unable to refresh icon cache."), true);
            prefs->run_uicache = false;
            sync_prefs();
            LOG("Successfully ran uicache.");
            insertstatus(localize(@"Ran uicache.\n"));
        }
    }
    
    upstage();
    
    {
        if (!(prefs->load_tweaks && prefs->reload_system_daemons)) {
            // Flush preference cache.
            
            progress(localize(@"Flushing preference cache..."));
            _assert(runCommand("/bin/launchctl", "stop", "com.apple.cfprefsd.xpc.daemon", NULL) == ERR_SUCCESS, localize(@"Unable to flush preference cache."), true);
            LOG("Successfully flushed preference cache.");
            insertstatus(localize(@"Flushed preference cache.\n"));
        }
    }
    
    upstage();
    
    {
        if (prefs->load_tweaks) {
            // Load Tweaks.
            
            progress(localize(@"Loading Tweaks..."));
            NSMutableString *waitCommand = [NSMutableString new];
            [waitCommand appendFormat:@"while [[ ! -f %s ]]; do :; done;", success_file];
            if (!prefs->auto_respring) {
                [waitCommand appendFormat:@"while ps -p %d; do :; done;", my_pid];
            }
            if (prefs->reload_system_daemons && !needStrap) {
                rv = systemf("nohup bash -c \""
                             "%s"
                             "launchctl unload /System/Library/LaunchDaemons/com.apple.backboardd.plist && "
                             "ldrestart ;"
                             "launchctl load /System/Library/LaunchDaemons/com.apple.backboardd.plist"
                             "\" >/dev/null 2>&1 &", waitCommand.UTF8String);
            } else {
                rv = systemf("nohup bash -c \""
                             "%s"
                             "launchctl stop com.apple.mDNSResponder ;"
                             "sbreload"
                             "\" >/dev/null 2>&1 &", waitCommand.UTF8String);
            }
            _assert(WEXITSTATUS(rv) == ERR_SUCCESS, localize(@"Unable to load tweaks."), true);
            LOG("Successfully loaded Tweaks.");
            
            insertstatus(localize(@"Loaded Tweaks.\n"));
        }
    }
    
out:;
#undef sync_prefs
#undef write_test_file
#undef inject_trust_cache
    stage = maxStage;
    update_stage();
    progress(localize(@"Deinitializing jailbreak..."));
    LOG("Deinitializing kernel code execution...");
    term_kexec();
    LOG("Unplatformizing...");
    _assert(set_platform_binary(myProcAddr, false), localize(@"Unable to make my task a non-platform task."), true);
    _assert(set_cs_platform_binary(myProcAddr, false), localize(@"Unable to make my codesign blob a non-platform blob."), true);
    LOG("Sandboxing...");
    myCredAddr = myOriginalCredAddr;
    _assert(give_creds_to_process_at_addr(myProcAddr, myCredAddr) == kernelCredAddr, localize(@"Unable to drop kernel's credentials."), true);
    LOG("Downgrading host port...");
    _assert(setuid(my_uid) == ERR_SUCCESS, localize(@"Unable to set user id."), true);
    _assert(getuid() == my_uid, localize(@"Unable to verify user id."), true);
    LOG("Restoring shenanigans pointer...");
    _assert(WriteKernel64(getoffset(shenanigans), Shenanigans), localize(@"Unable to restore shenanigans in kernel memory."), true);
    LOG("Deallocating ports...");
    _assert(mach_port_deallocate(mach_task_self(), myHost) == KERN_SUCCESS, localize(@"Unable to deallocate new host port."), true);
    myHost = HOST_NULL;
    _assert(mach_port_deallocate(mach_task_self(), myOriginalHost) == KERN_SUCCESS, localize(@"Unable to deallocate my original host port."), true);
    myOriginalHost = HOST_NULL;
    insertstatus(([NSString stringWithFormat:@"\nRead %zu bytes from kernel memory\nWrote %zu bytes to kernel memory\n", kreads, kwrites]));
    insertstatus(([NSString stringWithFormat:@"\nJailbroke in %ld seconds\n", time(NULL) - start_time]));
    status(localize(@"Jailbroken"), false, false);
    bool forceRespring = (prefs->exploit == mach_swap_exploit);
    forceRespring |= (prefs->exploit == mach_swap_2_exploit);
    forceRespring &= (!usedPersistedKernelTaskPort);
    forceRespring &= (!prefs->load_tweaks);
    bool willRespring = (forceRespring);
    willRespring |= (prefs->load_tweaks && !prefs->ssh_only);
    release_prefs(&prefs);
    _assert(create_file(success_file, mobile_pw->pw_uid, 644), localize(@"Unable to create success file."), true);
    showAlert(@"Jailbreak Completed", [NSString stringWithFormat:@"%@\n\n%@\n%@", localize(@"Jailbreak Completed with Status:"), status, localize(willRespring ? @"The device will now respring." : @"The app will now exit.")], true, false);
    if (sharedController.canExit) {
        if (forceRespring) {
            WriteKernel64(myCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL), ReadKernel64(kernelCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL)));
            WriteKernel64(myCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_UID), 0);
            _assert(restartSpringBoard(), localize(@"Unable to restart SpringBoard."), true);
        } else {
            exit(EXIT_SUCCESS);
            _assert(false, localize(@"Unable to exit."), true);
        }
    }
    sharedController.canExit = YES;
#undef insertstatus
}


// Don't move this - it is at the bottom so that it will list the total number of upstages
int maxStage = __COUNTER__ - 1;
