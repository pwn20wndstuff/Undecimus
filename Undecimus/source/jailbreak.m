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

#define status_with_stage(Stage, MaxStage) status(([NSString stringWithFormat:@"%@ (%d/%d)", localize(@"Exploiting"), Stage, MaxStage]), false, false)
#define upstage() do { \
    __COUNTER__; \
    stage++; \
    status_with_stage(stage, maxStage); \
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
    auto rv = 0;
    auto usedPersistedKernelTaskPort = NO;
    auto const myPid = getpid();
    auto const myUid = getuid();
    auto myHost = HOST_NULL;
    auto myOriginalHost = HOST_NULL;
    auto myProcAddr = KPTR_NULL;
    auto myOriginalCredAddr = KPTR_NULL;
    auto myCredAddr = KPTR_NULL;
    auto kernelCredAddr = KPTR_NULL;
    auto Shenanigans = KPTR_NULL;
    auto prefs = copy_prefs();
    auto needStrap = NO;
    auto needSubstrate = NO;
    auto skipSubstrate = NO;
    auto const homeDirectory = NSHomeDirectory();
    auto debsToInstall = [NSMutableArray new];
    auto status = [NSMutableString new];
    auto const betaFirmware = isBetaFirmware();
    auto const start_time = time(NULL);
    auto hud = addProgressHUD();
    JailbreakViewController *sharedController = [JailbreakViewController sharedController];
#define insertstatus(x) do { [status appendString:x]; } while (false)
#define progress(x) do { LOG("Progress: %@", x); updateProgressHUD(hud, x); } while (false)
#define sync_prefs() do { _assert(set_prefs(prefs), localize(@"Unable to synchronize app preferences. Please restart the app and try again."), true); } while (false)
#define write_test_file(file) do { \
    _assert(create_file(file, 0, 0644), localize(@"Unable to create test file."), true); \
    _assert(clean_file(file), localize(@"Unable to clean test file."), true); \
} while (false)
    
    upstage();
    
    {
        // Exploit kernel.
        
        progress(localize(@"Exploiting kernel..."));
        auto exploit_success = NO;
        myHost = mach_host_self();
        _assert(MACH_PORT_VALID(myHost), localize(NSLocalizedString(@"Unable to get host port.", nil)), true);
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
                    auto const machswap_offsets = get_machswap_offsets();
                    if (machswap_offsets != NULL &&
                        machswap_exploit(machswap_offsets) == ERR_SUCCESS &&
                        MACH_PORT_VALID(tfp0) &&
                        KERN_POINTER_VALID(kernel_base)) {
                        exploit_success = YES;
                    }
                    break;
                }
                case mach_swap_2_exploit: {
                    auto const machswap_offsets = get_machswap_offsets();
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
            auto const original_kernel_cache_path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
            auto const decompressed_kernel_cache_path = [homeDirectory stringByAppendingPathComponent:@"Documents/kernelcache.dec"].UTF8String;
            if (!canRead(decompressed_kernel_cache_path)) {
                auto const original_kernel_cache = fopen(original_kernel_cache_path, "rb");
                _assert(original_kernel_cache != NULL, localize(@"Unable to open original kernelcache for reading."), true);
                auto const decompressed_kernel_cache = fopen(decompressed_kernel_cache_path, "w+b");
                _assert(decompressed_kernel_cache != NULL, localize(@"Unable to open decompressed kernelcache for writing."), true);
                _assert(decompress_kernel(original_kernel_cache, decompressed_kernel_cache, NULL, true) == ERR_SUCCESS, localize(@"Unable to decompress kernelcache."), true);
                fclose(decompressed_kernel_cache);
                fclose(original_kernel_cache);
            }
            auto kernelVersion = getKernelVersion();
            _assert(kernelVersion != NULL, localize(@"Unable to get kernel version."), true);
            if (init_kernel(NULL, 0, decompressed_kernel_cache_path) != ERR_SUCCESS ||
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
            prefs->ssh_only = true;
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
        found_offsets = true;
        LOG("Successfully found offsets.");
        
        // Deinitialize patchfinder.
        term_kernel();
    }
    
    upstage();
    
    {
        // Initialize jailbreak.
        auto const ShenanigansPatch = (kptr_t)0xca13feba37be;
        
        progress(localize(@"Initializing jailbreak..."));
        LOG("Escaping sandbox...");
        myProcAddr = get_proc_struct_for_pid(myPid);
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
        _assert(setuid(0) == ERR_SUCCESS, localize(@"Unable to set user id."), true);
        _assert(getuid() == 0, localize(@"Unable to verify user id."), true);
        myHost = mach_host_self();
        _assert(MACH_PORT_VALID(myHost), localize(@"Unable to upgrade host port."), true);
        LOG("Successfully escaped sandbox.");
        LOG("Setting HSP4 as TFP0...");
        _assert(set_hsp4(tfp0), localize(@"Unable to set HSP4."), true);
        _assert(set_kernel_task_info(), localize(@"Unable to set kernel task info."), true);
        LOG("Successfully set HSP4 as TFP0.");
        insertstatus(localize(@"Set HSP4 as TFP0.\n"));
        LOG("Initializing kernel code execution...");
        _assert(init_kexec(), localize(@"Unable to initialize kernel code execution."), true);
        LOG("Successfully initialized kernel code execution.");
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
        auto const testFile = [NSString stringWithFormat:@"/var/mobile/test-%lu.txt", time(NULL)].UTF8String;
        write_test_file(testFile);
        LOG("Successfully wrote a test file to UserFS.");
    }
    
    upstage();
    
    {
        if (prefs->dump_apticket) {
            auto const originalFile = @"/System/Library/Caches/apticket.der";
            auto const dumpFile = [homeDirectory stringByAppendingPathComponent:@"Documents/apticket.der"];
            if (![sha1sum(originalFile) isEqualToString:sha1sum(dumpFile)]) {
                // Dump APTicket.
                
                progress(localize(@"Dumping APTicket..."));
                auto const fileData = [NSData dataWithContentsOfFile:originalFile];
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
            auto const bootNonceKey = "com.apple.System.boot-nonce";
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
        auto const file = @(SLIDE_FILE);
        auto const fileData = [[NSString stringWithFormat:@(ADDR "\n"), kernel_slide] dataUsingEncoding:NSUTF8StringEncoding];
        if (![[NSData dataWithContentsOfFile:file] isEqual:fileData]) {
            _assert(clean_file(file.UTF8String), localize(@"Unable to clean old kernel slide log."), true);
            _assert(create_file_data(file.UTF8String, 0, 0644, fileData), localize(@"Unable to log kernel slide."), true);
        }
        LOG("Successfully logged slide.");
        insertstatus(localize(@"Logged slide.\n"));
    }
    
    upstage();
    
    {
        // Log ECID.
        
        progress(localize(@"Logging ECID..."));
        auto const ECID = getECID();
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
        auto const array = @[@"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate",
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
                ensure_directory([path UTF8String], 0, 0755);
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
        auto rootfd = open("/", O_RDONLY);
        _assert(rootfd > 0, localize(@"Unable to open RootFS."), true);
        auto snapshots = snapshot_list(rootfd);
        auto systemSnapshot = copySystemSnapshot();
        _assert(systemSnapshot != NULL, localize(@"Unable to copy system snapshot."), true);
        auto const original_snapshot = "orig-fs";
        auto has_original_snapshot = NO;
        auto const thedisk = "/dev/disk0s1s1";
        auto oldest_snapshot = NULL;
        _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, localize(@"Unable to print mount list."), false);
        if (snapshots == NULL) {
            close(rootfd);
            
            // Clear dev vnode's si_flags.
            
            LOG("Clearing dev vnode's si_flags...");
            auto devVnode = get_vnode_for_path(thedisk);
            LOG("devVnode = " ADDR, devVnode);
            _assert(KERN_POINTER_VALID(devVnode), localize(@"Unable to get vnode for root device."), true);
            auto v_specinfo = ReadKernel64(devVnode + koffset(KSTRUCT_OFFSET_VNODE_VU_SPECINFO));
            LOG("v_specinfo = " ADDR, v_specinfo);
            _assert(KERN_POINTER_VALID(v_specinfo), localize(@"Unable to get specinfo for root device."), true);
            WriteKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS), 0);
            _assert(vnode_put(devVnode) == ERR_SUCCESS, localize(@"Unable to close vnode for root device."), true);
            LOG("Successfully cleared dev vnode's si_flags.");
            
            // Mount RootFS.
            
            LOG("Mounting RootFS...");
            auto const invalidRootMessage = localize(@"RootFS already mounted, delete OTA file from Settings - Storage if present and reboot.");
            _assert(!is_mountpoint("/var/MobileSoftwareUpdate/mnt1"), invalidRootMessage, true);
            auto const rootFsMountPoint = "/private/var/tmp/jb/mnt1";
            if (is_mountpoint(rootFsMountPoint)) {
                _assert(unmount(rootFsMountPoint, MNT_FORCE) == ERR_SUCCESS, localize(@"Unable to unmount old RootFS mount point."), true);
            }
            _assert(clean_file(rootFsMountPoint), localize(@"Unable to clean old RootFS mount point."), true);
            _assert(ensure_directory(rootFsMountPoint, 0, 0755), localize(@"Unable to create RootFS mount point."), true);
            const char *argv[] = {"/sbin/mount_apfs", thedisk, rootFsMountPoint, NULL};
            _assert(runCommandv(argv[0], 3, argv, ^(pid_t pid) {
                auto const procStructAddr = get_proc_struct_for_pid(pid);
                LOG("procStructAddr = " ADDR, procStructAddr);
                _assert(KERN_POINTER_VALID(procStructAddr), localize(@"Unable to find mount_apfs's process in kernel memory."), true);
                give_creds_to_process_at_addr(procStructAddr, kernelCredAddr);
            }) == ERR_SUCCESS, localize(@"Unable to mount RootFS."), true);
            _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, localize(@"Unable to print new mount list."), true);
            auto const systemSnapshotLaunchdPath = [@(rootFsMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
            _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, localize(@"Unable to verify newly mounted RootFS."), true);
            LOG("Successfully mounted RootFS.");
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot...");
            rootfd = open(rootFsMountPoint, O_RDONLY);
            _assert(rootfd > 0, localize(@"Unable to open newly mounted RootFS."), true);
            snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, localize(@"Unable to get snapshots for newly mounted RootFS."), true);
            LOG("Snapshots on newly mounted RootFS:");
            for (auto snapshot = snapshots; *snapshot; snapshot++) {
                LOG("\t%s", *snapshot);
            }
            SafeFreeNULL(snapshots);
            auto const systemVersionPlist = @"/System/Library/CoreServices/SystemVersion.plist";
            auto const rootSystemVersionPlist = [@(rootFsMountPoint) stringByAppendingPathComponent:systemVersionPlist];
            auto const snapshotSystemVersion = [NSDictionary dictionaryWithContentsOfFile:systemVersionPlist];
            _assert(snapshotSystemVersion != nil, localize(@"Unable to get SystemVersion.plist for RootFS."), true);
            auto const rootfsSystemVersion = [NSDictionary dictionaryWithContentsOfFile:rootSystemVersionPlist];
            _assert(rootfsSystemVersion != nil, localize(@"Unable to get SystemVersion.plist for newly mounted RootFS."), true);
            if (![rootfsSystemVersion[@"ProductBuildVersion"] isEqualToString:snapshotSystemVersion[@"ProductBuildVersion"]]) {
                LOG("snapshot VersionPlist: %@", snapshotSystemVersion);
                LOG("rootfs VersionPlist: %@", rootfsSystemVersion);
                _assert("BuildVersions match"==NULL, invalidRootMessage, true);
            }
            auto const test_snapshot = "test-snapshot";
            _assert(fs_snapshot_create(rootfd, test_snapshot, 0) == ERR_SUCCESS, localize(@"Unable to create test snapshot."), true);
            _assert(fs_snapshot_delete(rootfd, test_snapshot, 0) == ERR_SUCCESS, localize(@"Unable to delete test snapshot."), true);
            auto system_snapshot_vnode = KPTR_NULL;
            auto system_snapshot_vnode_v_data = KPTR_NULL;
            auto system_snapshot_vnode_v_data_flag = 0;
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
            for (auto snapshot = snapshots; *snapshot; snapshot++) {
                if (oldest_snapshot == NULL) {
                    oldest_snapshot = strdup(*snapshot);
                }
                if (strcmp(original_snapshot, *snapshot) == 0) {
                    has_original_snapshot = YES;
                }
                LOG("%s", *snapshot);
            }
        }
        
        auto rootfs_vnode = get_vnode_for_path("/");
        LOG("rootfs_vnode = " ADDR, rootfs_vnode);
        _assert(KERN_POINTER_VALID(rootfs_vnode), localize(@"Unable to get vnode for RootFS."), true);
        auto v_mount = ReadKernel64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
        LOG("v_mount = " ADDR, v_mount);
        _assert(KERN_POINTER_VALID(v_mount), localize(@"Unable to get mount info for RootFS."), true);
        auto v_flag = ReadKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG));
        if ((v_flag & MNT_RDONLY) || (v_flag & MNT_NOSUID)) {
            v_flag &= ~(MNT_RDONLY | MNT_NOSUID);
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag & ~MNT_ROOTFS);
            auto opts = strdup(thedisk);
            _assert(opts != NULL, localize(@"Unable to allocate memory for ops."), true);
            _assert(mount("apfs", "/", MNT_UPDATE, (void *)&opts) == ERR_SUCCESS, localize(@"Unable to remount RootFS."), true);
            SafeFreeNULL(opts);
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag);
        }
        _assert(vnode_put(rootfs_vnode) == ERR_SUCCESS, localize(@"Unable to close RootFS vnode."), true);
        _assert(runCommand("/sbin/mount", NULL) == ERR_SUCCESS, localize(@"Unable to print new mount list."), false);
        auto const file = [NSString stringWithContentsOfFile:@"/.installed_unc0ver" encoding:NSUTF8StringEncoding error:nil];
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
        auto const testFile = [NSString stringWithFormat:@"/test-%lu.txt", time(NULL)].UTF8String;
        write_test_file(testFile);
        LOG("Successfully wrote a test file to RootFS.");
    }
    
    upstage();
    
    {
        auto const array = @[@"/var/Keychains/ocspcache.sqlite3",
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
        _assert(ensure_directory("/jb", 0, 0755), localize(@"Unable to create jailbreak directory."), true);
        _assert(chdir("/jb") == ERR_SUCCESS, localize(@"Unable to change working directory to jailbreak directory."), true);
        LOG("Successfully created jailbreak directory.");
        insertstatus(localize(@"Created jailbreak directory.\n"));
    }
    
    upstage();
    
    {
        auto const offsetsFile = @"/jb/offsets.plist";
        auto dictionary = [NSMutableDictionary new];
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
            _assert(init_file(offsetsFile.UTF8String, 0, 0644), localize(@"Unable to set permissions for offset cache file."), true);
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
            auto const rootfd = open("/", O_RDONLY);
            _assert(rootfd > 0, localize(@"Unable to open RootFS."), true);
            auto snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, localize(@"Unable to get snapshots for RootFS."), true);
            auto snapshot = strdup(*snapshots);
            LOG("%s", snapshot);
            _assert(snapshot != NULL, localize(@"Unable to find original snapshot for RootFS."), true);
            if (!(kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber_iOS_11_3)) {
                auto systemSnapshot = copySystemSnapshot();
                _assert(systemSnapshot != NULL, localize(@"Unable to copy system snapshot."), true);
                _assert(fs_snapshot_rename(rootfd, snapshot, systemSnapshot, 0) == ERR_SUCCESS, localize(@"Unable to rename original snapshot."), true);
                SafeFreeNULL(snapshot);
                snapshot = strdup(systemSnapshot);
                _assert(snapshot != NULL, localize(@"Unable to duplicate string."), true);
                SafeFreeNULL(systemSnapshot);
            }
            auto const systemSnapshotMountPoint = "/private/var/tmp/jb/mnt2";
            if (is_mountpoint(systemSnapshotMountPoint)) {
                _assert(unmount(systemSnapshotMountPoint, MNT_FORCE) == ERR_SUCCESS, localize(@"Unable to unmount old snapshot mount point."), true);
            }
            _assert(clean_file(systemSnapshotMountPoint), localize(@"Unable to clean old snapshot mount point."), true);
            _assert(ensure_directory(systemSnapshotMountPoint, 0, 0755), localize(@"Unable to create snapshot mount point."), true);
            _assert(fs_snapshot_mount(rootfd, systemSnapshotMountPoint, snapshot, 0) == ERR_SUCCESS, localize(@"Unable to mount original snapshot."), true);
            auto const systemSnapshotLaunchdPath = [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
            _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, localize(@"Unable to verify mounted snapshot."), true);
            _assert(extractDebsForPkg(@"rsync", nil, false), localize(@"Unable to extract rsync."), true);
            _assert(extractDebsForPkg(@"uikittools", nil, false), localize(@"Unable to extract uikittools."), true);
            _assert(injectTrustCache(@[@"/usr/bin/rsync", @"/usr/bin/uicache"], getoffset(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, localize(@"Unable to inject rsync and uicache to trust cache."), true);
            if (kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber_iOS_11_3) {
                _assert(runCommand("/usr/bin/rsync", "-vaxcH", "--progress", "--delete-after", "--exclude=/Developer", "--exclude=/usr/bin/uicache", [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"."].UTF8String, "/", NULL) == 0, localize(@"Unable to sync /Applications."), true);
            } else {
                _assert(runCommand("/usr/bin/rsync", "-vaxcH", "--progress", "--delete", [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"Applications/."].UTF8String, "/Applications", NULL) == 0, localize(@"Unable to sync /."), true);
            }
            _assert(unmount(systemSnapshotMountPoint, MNT_FORCE) == ERR_SUCCESS, localize(@"Unable to unmount original snapshot mount point."), true);
            close(rootfd);
            SafeFreeNULL(snapshot);
            SafeFreeNULL(snapshots);
            _assert(runCommand("/usr/bin/uicache", NULL) == ERR_SUCCESS, localize(@"Unable to refresh icon cache."), true);
            _assert(clean_file("/usr/bin/uicache"), localize(@"Unable to clean uicache binary."), true);
            LOG("Successfully reverted back RootFS remount.");
            
            // Clean up.
            
            LOG("Cleaning up...");
            auto const cleanUpFileList = @[@"/var/cache",
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
        auto toInject = [NSMutableArray new];
        if (!verifySums(pathForResource(@"binpack64-256.md5sums"), HASHTYPE_MD5)) {
            auto binpack64 = [ArchiveFile archiveWithFile:pathForResource(@"binpack64-256.tar.lzma")];
            _assert(binpack64 != nil, localize(@"Unable to open binpack."), true);
            _assert([binpack64 extractToPath:@"/jb"], localize(@"Unable to extract binpack."), true);
            for (id file in binpack64.files.allKeys) {
                auto const path = [@"/jb" stringByAppendingPathComponent:file];
                if (cdhashFor(path) != nil) {
                    if (![toInject containsObject:path]) {
                        [toInject addObject:path];
                    }
                }
            }
        }
        auto const fileManager = [NSFileManager defaultManager];
        auto directoryEnumerator = [fileManager enumeratorAtURL:[NSURL URLWithString:@"/jb"] includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:nil];
        _assert(directoryEnumerator != nil, localize(@"Unable to create directory enumerator."), true);
        for (id URL in directoryEnumerator) {
            auto path = [URL path];
            if (cdhashFor(path) != nil) {
                if (![toInject containsObject:path]) {
                    [toInject addObject:path];
                }
            }
        }
        for (id file in [fileManager contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
            auto path = [@"/Applications" stringByAppendingPathComponent:file];
            auto info_plist = [NSMutableDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
            if (info_plist == nil) continue;
            if ([info_plist[@"CFBundleIdentifier"] hasPrefix:@"com.apple."]) continue;
            directoryEnumerator = [fileManager enumeratorAtURL:[NSURL URLWithString:path] includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:nil];
            if (directoryEnumerator == nil) continue;
            for (id URL in directoryEnumerator) {
                auto path = [URL path];
                if (cdhashFor(path) != nil) {
                    if (![toInject containsObject:path]) {
                        [toInject addObject:path];
                    }
                }
            }
        }
        if (toInject.count > 0) {
            _assert(injectTrustCache(toInject, getoffset(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, localize(@"Unable to inject binaries to trust cache."), true);
        }
        auto const binpackMessage = localize(@"Unable to setup binpack.");
        _assert(ensure_symlink("/jb/usr/bin/scp", "/usr/bin/scp"), binpackMessage, true);
        _assert(ensure_directory("/usr/local/lib", 0, 0755), binpackMessage, true);
        _assert(ensure_directory("/usr/local/lib/zsh", 0, 0755), binpackMessage, true);
        _assert(ensure_directory("/usr/local/lib/zsh/5.0.8", 0, 0755), binpackMessage, true);
        _assert(ensure_symlink("/jb/usr/local/lib/zsh/5.0.8/zsh", "/usr/local/lib/zsh/5.0.8/zsh"), binpackMessage, true);
        _assert(ensure_symlink("/jb/bin/zsh", "/bin/zsh"), binpackMessage, true);
        _assert(ensure_symlink("/jb/etc/zshrc", "/etc/zshrc"), binpackMessage, true);
        _assert(ensure_symlink("/jb/usr/share/terminfo", "/usr/share/terminfo"), binpackMessage, true);
        _assert(ensure_symlink("/jb/usr/local/bin", "/usr/local/bin"), binpackMessage, true);
        _assert(ensure_symlink("/jb/etc/profile", "/etc/profile"), binpackMessage, true);
        _assert(ensure_directory("/etc/dropbear", 0, 0755), binpackMessage, true);
        _assert(ensure_directory("/jb/Library", 0, 0755), binpackMessage, true);
        _assert(ensure_directory("/jb/Library/LaunchDaemons", 0, 0755), binpackMessage, true);
        _assert(ensure_directory("/jb/etc/rc.d", 0, 0755), binpackMessage, true);
        if (access("/jb/Library/LaunchDaemons/dropbear.plist", F_OK) != ERR_SUCCESS) {
            auto dropbear_plist = [NSMutableDictionary new];
            _assert(dropbear_plist, localize(@"Unable to allocate memory for dropbear plist."), true);
            dropbear_plist[@"Program"] = @"/jb/usr/local/bin/dropbear";
            dropbear_plist[@"RunAtLoad"] = @YES;
            dropbear_plist[@"Label"] = @"ShaiHulud";
            dropbear_plist[@"KeepAlive"] = @YES;
            dropbear_plist[@"ProgramArguments"] = [NSMutableArray new];
            dropbear_plist[@"ProgramArguments"][0] = @"/usr/local/bin/dropbear";
            dropbear_plist[@"ProgramArguments"][1] = @"-F";
            dropbear_plist[@"ProgramArguments"][2] = @"-R";
            dropbear_plist[@"ProgramArguments"][3] = @"--shell";
            dropbear_plist[@"ProgramArguments"][4] = @"/jb/bin/bash";
            dropbear_plist[@"ProgramArguments"][5] = @"-p";
            dropbear_plist[@"ProgramArguments"][6] = @"22";
            _assert([dropbear_plist writeToFile:@"/jb/Library/LaunchDaemons/dropbear.plist" atomically:YES], localize(@"Unable to create dropbear launch daemon."), true);
            _assert(init_file("/jb/Library/LaunchDaemons/dropbear.plist", 0, 0644), localize(@"Unable to initialize dropbear launch daemon."), true);
        }
        if (prefs->load_daemons) {
            for (id file in [fileManager contentsOfDirectoryAtPath:@"/jb/Library/LaunchDaemons" error:nil]) {
                auto const path = [@"/jb/Library/LaunchDaemons" stringByAppendingPathComponent:file];
                runCommand("/jb/bin/launchctl", "load", path.UTF8String, NULL);
            }
            for (id file in [fileManager contentsOfDirectoryAtPath:@"/jb/etc/rc.d" error:nil]) {
                auto const path = [@"/jb/etc/rc.d" stringByAppendingPathComponent:file];
                if ([fileManager isExecutableFileAtPath:path]) {
                    runCommand("/jb/bin/bash", "-c", path.UTF8String, NULL);
                }
            }
        }
        if (prefs->run_uicache) {
            _assert(runCommand("/jb/usr/bin/uicache", NULL) == ERR_SUCCESS, localize(@"Unable to refresh icon cache."), true);
        }
        _assert(runCommand("/jb/bin/launchctl", "stop", "com.apple.cfprefsd.xpc.daemon", NULL) == ERR_SUCCESS, localize(@"Unable to flush preference cache."), true);
        LOG("Successfully enabled SSH.");
        insertstatus(localize(@"Enabled SSH.\n"));
    }
    
    if (auth_ptrs || prefs->ssh_only) {
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
        
        needSubstrate = ( needStrap ||
                         (access("/usr/libexec/substrate", F_OK) != ERR_SUCCESS) ||
                         !verifySums(@"/var/lib/dpkg/info/mobilesubstrate.md5sums", HASHTYPE_MD5)
                         );
        if (needSubstrate) {
            LOG(@"We need substrate.");
            auto const substrateDeb = debForPkg(@"mobilesubstrate");
            _assert(substrateDeb != nil, localize(@"Unable to get deb for Substrate."), true);
            if (pidOfProcess("/usr/libexec/substrated") == 0) {
                _assert(extractDeb(substrateDeb), localize(@"Unable to extract Substrate."), true);
            } else {
                skipSubstrate = YES;
                LOG("Substrate is running, not extracting again for now.");
            }
            [debsToInstall addObject:substrateDeb];
        }
        
        auto resourcesPkgs = resolveDepsForPkg(@"jailbreak-resources", true);
        _assert(resourcesPkgs != nil, localize(@"Unable to get resource packages."), true);
        resourcesPkgs = [@[@"system-memory-reset-fix"] arrayByAddingObjectsFromArray:resourcesPkgs];
        if (betaFirmware) {
            resourcesPkgs = [@[@"com.parrotgeek.nobetaalert"] arrayByAddingObjectsFromArray:resourcesPkgs];
        }
        if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
            resourcesPkgs = [@[@"com.ps.letmeblock"] arrayByAddingObjectsFromArray:resourcesPkgs];
        }
        
        auto pkgsToRepair = [NSMutableArray new];
        LOG("Resource Pkgs: \"%@\".", resourcesPkgs);
        for (id pkg in resourcesPkgs) {
            // Ignore mobilesubstrate because we just handled that separately.
            if ([pkg isEqualToString:@"mobilesubstrate"] || [pkg isEqualToString:@"firmware"])
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
            auto const debsToRepair = debsForPkgs(pkgsToRepair);
            _assert(debsToRepair.count == pkgsToRepair.count, localize(@"Unable to get debs for packages to repair."), true);
            _assert(extractDebs(debsToRepair), localize(@"Unable to repair packages."), true);
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
        clean_file("/jb/jailbreakd.plist");
        clean_file("/jb/amfid_payload.dylib");
        clean_file("/jb/libjailbreak.dylib");
        
        LOG("Successfully copied over resources to RootFS.");
        insertstatus(localize(@"Copied over resources to RootFS.\n"));
    }
    
    upstage();
    
    {
        // Inject trust cache
        
        progress(localize(@"Injecting trust cache..."));
        auto resources = [NSArray arrayWithContentsOfFile:@"/usr/share/jailbreak/injectme.plist"];
        // If substrate is already running but was broken, skip injecting again
        if (!skipSubstrate) {
            resources = [@[@"/usr/libexec/substrate"] arrayByAddingObjectsFromArray:resources];
        }
        resources = [@[@"/usr/libexec/substrated"] arrayByAddingObjectsFromArray:resources];
        for (id file in resources) {
            if (![toInjectToTrustCache containsObject:file]) {
                [toInjectToTrustCache addObject:file];
            }
        }
        _assert(injectTrustCache(toInjectToTrustCache, getoffset(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, localize(@"Unable to inject binaries to trust cache."), true);
        [toInjectToTrustCache removeAllObjects];
        injectedToTrustCache = true;
        LOG("Successfully injected trust cache.");
        insertstatus(localize(@"Injected trust cache.\n"));
    }
    
    upstage();
    
    {
        // Repair filesystem.
        
        progress(localize(@"Repairing filesystem..."));
        
        _assert(ensure_directory("/var/lib", 0, 0755), localize(@"Unable to repair state information directory"), true);
        
        // Make sure dpkg is not corrupted
        if (is_directory("/var/lib/dpkg")) {
            if (is_directory("/Library/dpkg")) {
                LOG(@"Removing /var/lib/dpkg...");
                _assert(clean_file("/var/lib/dpkg"), localize(@"Unable to clean old dpkg database."), true);
            } else {
                LOG(@"Moving /var/lib/dpkg to /Library/dpkg...");
                _assert([[NSFileManager defaultManager] moveItemAtPath:@"/var/lib/dpkg" toPath:@"/Library/dpkg" error:nil], localize(@"Unable to restore dpkg database."), true);
            }
        }
        
        _assert(ensure_symlink("/Library/dpkg", "/var/lib/dpkg"), localize(@"Unable to symlink dpkg database."), true);
        _assert(ensure_directory("/Library/dpkg", 0, 0755), localize(@"Unable to repair dpkg database."), true);
        _assert(ensure_file("/var/lib/dpkg/status", 0, 0644), localize(@"Unable to repair dpkg status file."), true);
        _assert(ensure_file("/var/lib/dpkg/available", 0, 0644), localize(@"Unable to repair dpkg available file."), true);
        
        // Make sure firmware-sbin package is not corrupted.
        auto file = [NSString stringWithContentsOfFile:@"/var/lib/dpkg/info/firmware-sbin.list" encoding:NSUTF8StringEncoding error:nil];
        if ([file containsString:@"/sbin/fstyp"] || [file containsString:@"\n\n"]) {
            // This is not a stock file for iOS11+
            file = [file stringByReplacingOccurrencesOfString:@"/sbin/fstyp\n" withString:@""];
            file = [file stringByReplacingOccurrencesOfString:@"\n\n" withString:@"\n"];
            [file writeToFile:@"/var/lib/dpkg/info/firmware-sbin.list" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        
        // Make sure this is a symlink - usually handled by ncurses pre-inst
        _assert(ensure_symlink("/usr/lib", "/usr/lib/_ncurses"), localize(@"Unable to repair ncurses."), true);
        
        // This needs to be there for Substrate to work properly
        _assert(ensure_directory("/Library/Caches", 0, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO), localize(@"Unable to repair caches directory for Substrate."), true);
        LOG("Successfully repaired filesystem.");
        
        insertstatus(localize(@"Repaired Filesystem.\n"));
    }
    
    upstage();
    
    {
        // Load Substrate
        
        // Set Disable Loader.
        progress(localize(@"Setting Disable Loader..."));
        if (prefs->load_tweaks) {
            clean_file("/var/tmp/.substrated_disable_loader");
        } else {
            _assert(create_file("/var/tmp/.substrated_disable_loader", 0, 644), localize(@"Unable to disable Substrate's loader."), true);
        }
        LOG("Successfully set Disable Loader.");
        
        // Run substrate
        progress(localize(@"Starting Substrate..."));
        if (access("/usr/lib/substrate", F_OK) == ERR_SUCCESS && !is_symlink("/usr/lib/substrate")) {
            _assert(clean_file("/Library/substrate"), localize(@"Unable to clean old Substrate directory."), true);
            _assert([[NSFileManager defaultManager] moveItemAtPath:@"/usr/lib/substrate" toPath:@"/Library/substrate" error:nil], localize(@"Unable to move Substrate directory."), true);
        }
        _assert(ensure_symlink("/Library/substrate", "/usr/lib/substrate"), localize(@"Unable to symlink Substrate directory."), true);
        _assert(runCommand("/usr/libexec/substrate", NULL) == ERR_SUCCESS, localize(skipSubstrate?@"Unable to restart Substrate.":@"Unable to start Substrate."), skipSubstrate?false:true);
        LOG("Successfully started Substrate.");
        
        insertstatus(localize(@"Loaded Substrate.\n"));
    }
    
    upstage();
    
    {
        // Extract bootstrap.
        progress(localize(@"Extracting bootstrap..."));
        
        if (!pkgIsConfigured("xz")) {
            removePkg("lzma", true);
            extractDebsForPkg(@"lzma", debsToInstall, false);
            _assert(injectTrustCache(toInjectToTrustCache, getoffset(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, localize(@"Unable to inject newly extracted lzma to trust cache."), true);
            [toInjectToTrustCache removeAllObjects];
            injectedToTrustCache = true;
        }
        
        if (pkgIsInstalled("openssl") && compareInstalledVersion("openssl", "lt", "1.0.2q")) {
            removePkg("openssl", true);
        }
        
        // Test dpkg
        if (!pkgIsConfigured("dpkg")) {
            LOG("Extracting dpkg...");
            _assert(extractDebsForPkg(@"dpkg", debsToInstall, false), localize(@"Unable to extract dpkg."), true);
            _assert(injectTrustCache(toInjectToTrustCache, getoffset(trustcache), pmap_load_trust_cache) == ERR_SUCCESS, localize(@"Unable to inject newly extracted dpkg to trust cache."), true);
            [toInjectToTrustCache removeAllObjects];
            injectedToTrustCache = true;
            auto const dpkg_deb = debForPkg(@"dpkg");
            _assert(installDeb(dpkg_deb.UTF8String, true), localize(@"Unable to install deb for dpkg."), true);
            [debsToInstall removeObject:dpkg_deb];
        }
        
        if (needStrap || !pkgIsConfigured("firmware")) {
            LOG("Extracting Cydia...");
            if (access("/usr/libexec/cydia/firmware.sh", F_OK) != ERR_SUCCESS || !pkgIsConfigured("cydia")) {
                auto const fwDebs = debsForPkgs(@[@"cydia", @"cydia-lproj", @"darwintools", @"uikittools", @"system-cmds"]);
                _assert(fwDebs != nil, localize(@"Unable to get firmware debs."), true);
                _assert(installDebs(fwDebs, true, false), localize(@"Unable to install firmware debs."), true);
                rv = _system("/usr/libexec/cydia/firmware.sh");
                _assert(WEXITSTATUS(rv) == 0, localize(@"Unable to create virtual dependencies."), true);
            }
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
            auto const apt7debs = debsForPkgs(@[@"apt7", @"apt7-key", @"apt7-lib"]);
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
        
        _assert(ensure_directory("/etc/apt/undecimus", 0, 0755), localize(@"Unable to create local repo."), true);
        clean_file("/etc/apt/sources.list.d/undecimus.list");
        auto const listPath = "/etc/apt/undecimus/undecimus.list";
        auto const listContents = @"deb file:///var/lib/undecimus/apt ./\n";
        auto const existingList = [NSString stringWithContentsOfFile:@(listPath) encoding:NSUTF8StringEncoding error:nil];
        if (![listContents isEqualToString:existingList]) {
            clean_file(listPath);
            [listContents writeToFile:@(listPath) atomically:NO encoding:NSUTF8StringEncoding error:nil];
        }
        init_file(listPath, 0, 0644);
        const char *prefsPath = "/etc/apt/undecimus/preferences";
        NSString *prefsContents = @"Package: *\nPin: release o=Undecimus\nPin-Priority: 1001\n";
        NSString *existingPrefs = [NSString stringWithContentsOfFile:@(prefsPath) encoding:NSUTF8StringEncoding error:nil];
        if (![prefsContents isEqualToString:existingPrefs]) {
            clean_file(prefsPath);
            [prefsContents writeToFile:@(prefsPath) atomically:NO encoding:NSUTF8StringEncoding error:nil];
        }
        init_file(prefsPath, 0, 0644);
        auto const repoPath = pathForResource(@"apt");
        _assert(repoPath != nil, localize(@"Unable to get repo path."), true);
        ensure_directory("/var/lib/undecimus", 0, 0755);
        ensure_symlink([repoPath UTF8String], "/var/lib/undecimus/apt");
        if (!pkgIsConfigured("apt1.4") || !aptUpdate()) {
            auto const aptNeeded = resolveDepsForPkg(@"apt1.4", false);
            _assert(aptNeeded != nil && aptNeeded.count > 0, localize(@"Unable to resolve dependencies for apt."), true);
            auto const aptDebs = debsForPkgs(aptNeeded);
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
        if (needSubstrate) {
            if (pkgIsInstalled("com.ex.substitute")) {
                _assert(removePkg("com.ex.substitute", true), localize(@"Unable to remove Substitute."), true);
            }
            _assert(aptInstall(@[@"mobilesubstrate"]), localize(@"Unable to install Substrate."), true);
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
        
        auto const file_data = [[NSString stringWithFormat:@"%f\n", kCFCoreFoundationVersionNumber] dataUsingEncoding:NSUTF8StringEncoding];
        if (![[NSData dataWithContentsOfFile:@"/.installed_unc0ver"] isEqual:file_data]) {
            _assert(clean_file("/.installed_unc0ver"), localize(@"Unable to clean old bootstrap marker file."), true);
            _assert(create_file_data("/.installed_unc0ver", 0, 0644, file_data), localize(@"Unable to create bootstrap marker file."), true);
        }
        
        _assert(ensure_file("/.cydia_no_stash", 0, 0644), localize(@"Unable to disable stashing."), true);
        
        // Make sure everything's at least as new as what we bundled
        rv = system("dpkg --configure -a");
        _assert(WEXITSTATUS(rv) == ERR_SUCCESS, localize(@"Unable to configure installed packages."), true);
        _assert(aptUpgrade(), localize(@"Unable to upgrade apt packages."), true);
        
        clean_file("/jb/tar");
        clean_file("/jb/lzma");
        clean_file("/jb/substrate.tar.lzma");
        clean_file("/electra");
        clean_file("/chimera");
        clean_file("/.bootstrapped_electra");
        clean_file([NSString stringWithFormat:@"/etc/.installed-chimera-%@", getUDID()].UTF8String);
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
        auto targettype = sysctlWithName("hw.targettype");
        _assert(targettype != NULL, localize(@"Unable to get hardware targettype."), true);
        auto const jetsamFile = [NSString stringWithFormat:@"/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", targettype];
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
            auto const cydiaVer = versionOfPkg(@"cydia");
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
            // Substrate is already running, no need to run it again
            system("for file in /etc/rc.d/*; do "
                   "if [[ -x \"$file\" && \"$file\" != \"/etc/rc.d/substrate\" ]]; then "
                   "\"$file\";"
                   "fi;"
                   "done");
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
        if (prefs->run_uicache || !canOpen("cydia://")) {
            // Run uicache.
            
            progress(localize(@"Refreshing icon cache..."));
            _assert(runCommand("/usr/bin/uicache", NULL) == ERR_SUCCESS, localize(@"Unable to refresh icon cache."), true);
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
            if (prefs->reload_system_daemons) {
                rv = system("nohup bash -c \""
                            "sleep 1 ;"
                            "launchctl unload /System/Library/LaunchDaemons/com.apple.backboardd.plist && "
                            "ldrestart ;"
                            "launchctl load /System/Library/LaunchDaemons/com.apple.backboardd.plist"
                            "\" >/dev/null 2>&1 &");
            } else {
                rv = system("nohup bash -c \""
                            "sleep 1 ;"
                            "launchctl stop com.apple.mDNSResponder ;"
                            "launchctl stop com.apple.backboardd"
                            "\" >/dev/null 2>&1 &");
            }
            _assert(WEXITSTATUS(rv) == ERR_SUCCESS, localize(@"Unable to load tweaks."), true);
            LOG("Successfully loaded Tweaks.");
            
            insertstatus(localize(@"Loaded Tweaks.\n"));
        }
    }
    
out:;
#undef sync_prefs
#undef write_test_file
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
    _assert(setuid(myUid) == ERR_SUCCESS, localize(@"Unable to set user id."), true);
    _assert(getuid() == myUid, localize(@"Unable to verify user id."), true);
    LOG("Restoring shenanigans pointer...");
    _assert(WriteKernel64(getoffset(shenanigans), Shenanigans), localize(@"Unable to restore shenanigans in kernel memory."), true);
    LOG("Deallocating ports...");
    _assert(mach_port_deallocate(mach_task_self(), myHost) == KERN_SUCCESS, localize(@"Unable to deallocate new host port."), true);
    myHost = HOST_NULL;
    _assert(mach_port_deallocate(mach_task_self(), myOriginalHost) == KERN_SUCCESS, localize(@"Unable to deallocate my original host port."), true);
    myOriginalHost = HOST_NULL;
#undef progress
    removeProgressHUD(hud);
    insertstatus(([NSString stringWithFormat:@"\nRead %zu bytes from kernel memory\nWrote %zu bytes to kernel memory\n", kreads, kwrites]));
    insertstatus(([NSString stringWithFormat:@"\nJailbroke in %ld seconds\n", time(NULL) - start_time]));
    status(localize(@"Jailbroken"), false, false);
    showAlert(@"Jailbreak Completed", [NSString stringWithFormat:@"%@\n\n%@\n%@", localize(@"Jailbreak Completed with Status:"), status, localize((prefs->exploit == mach_swap_exploit || prefs->exploit == mach_swap_2_exploit) && !usedPersistedKernelTaskPort ? @"The device will now respring." : @"The app will now exit.")], true, false);
    if (sharedController.canExit) {
        if ((prefs->exploit == mach_swap_exploit || prefs->exploit == mach_swap_2_exploit) && !usedPersistedKernelTaskPort) {
            WriteKernel64(myCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL), ReadKernel64(kernelCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL)));
            WriteKernel64(myCredAddr + koffset(KSTRUCT_OFFSET_UCRED_CR_UID), 0);
            release_prefs(&prefs);
            _assert(restartSpringBoard(), localize(@"Unable to restart SpringBoard."), true);
        } else {
            release_prefs(&prefs);
            exit(EXIT_SUCCESS);
            _assert(false, localize(@"Unable to exit."), true);
        }
    }
    sharedController.canExit = YES;
    release_prefs(&prefs);
#undef insertstatus
}


// Don't move this - it is at the bottom so that it will list the total number of upstages
int maxStage = __COUNTER__ - 1;
