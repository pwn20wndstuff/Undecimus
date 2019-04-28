#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>

#include <common.h>
#include <iokit.h>
#include <patchfinder64.h>
#include <sys/mount.h>
#include <libproc.h>

#include "KernelMemory.h"
#include "KernelStructureOffsets.h"
#include "KernelUtilities.h"
#include "find_port.h"
#include "KernelExecution.h"
#include "pac.h"
#include "kernel_call.h"

#define off_OSDictionary_SetObjectWithCharP (sizeof(void*) * 0x1F)
#define off_OSDictionary_GetObjectWithCharP (sizeof(void*) * 0x26)
#define off_OSDictionary_Merge (sizeof(void*) * 0x23)
#define off_OSArray_Merge (sizeof(void*) * 0x1E)
#define off_OSArray_RemoveObject (sizeof(void*) * 0x20)
#define off_OSArray_GetObject (sizeof(void*) * 0x22)
#define off_OSObject_Release (sizeof(void*) * 0x05)
#define off_OSObject_GetRetainCount (sizeof(void*) * 0x03)
#define off_OSObject_Retain (sizeof(void*) * 0x04)
#define off_OSString_GetLength (sizeof(void*) * 0x11)

#define P_MEMSTAT_INTERNAL 0x00001000 /* Process is a system-critical-not-be-jetsammed process i.e. launchd */

#define CS_VALID 0x0000001 /* dynamically valid */
#define CS_GET_TASK_ALLOW 0x0000004 /* has get-task-allow entitlement */
#define CS_INSTALLER 0x0000008 /* has installer entitlement */
#define CS_HARD 0x0000100 /* don't load invalid pages */
#define CS_KILL 0x0000200 /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION 0x0000400 /* force expiration checking */
#define CS_RESTRICT 0x0000800 /* tell dyld to treat restricted */
#define CS_REQUIRE_LV 0x0002000 /* require library validation */
#define CS_KILLED 0x1000000 /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM 0x2000000 /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY 0x4000000 /* this is a platform binary */
#define CS_DEBUGGED 0x10000000 /* process is currently or has previously been debugged and allowed to run with invalid pages */

#define TF_PLATFORM 0x00000400 /* task is a platform binary */

#define IO_ACTIVE 0x80000000

#define IKOT_HOST 3
#define IKOT_HOST_PRIV 4

#define CS_OPS_STATUS 0
#define CS_OPS_ENTITLEMENTS_BLOB 7
#define FILE_EXC_KEY "com.apple.security.exception.files.absolute-path.read-only"

const char *abs_path_exceptions[] = {
    "/Library",
    "/private/var/mobile/Library",
    "/System/Library/Caches",
    "/private/var/mnt",
    NULL
};

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6

int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

uint64_t the_realhost;
uint64_t kernel_base = -1;
uint64_t offset_options = 0;
bool found_offsets = false;

uint64_t cached_task_self_addr = 0;
uint64_t task_self_addr()
{
    if (cached_task_self_addr == 0) {
        cached_task_self_addr = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), mach_task_self()) : find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
        LOG("task self: 0x%llx", cached_task_self_addr);
    }
    return cached_task_self_addr;
}

uint64_t ipc_space_kernel()
{
    return ReadKernel64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

uint64_t current_thread()
{
    thread_t thread = mach_thread_self();
    uint64_t thread_port = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), thread) : find_port_address(thread, MACH_MSG_TYPE_COPY_SEND);
    mach_port_deallocate(mach_task_self(), thread);
    thread = THREAD_NULL;
    return ReadKernel64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
}

uint64_t find_kernel_base()
{
    host_t host = mach_host_self();
    uint64_t hostport_addr = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), host) : find_port_address(host, MACH_MSG_TYPE_COPY_SEND);
    mach_port_deallocate(mach_task_self(), host);
    uint64_t realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    the_realhost = realhost;

    uint64_t base = realhost & ~0xfffULL;
    // walk down to find the magic:
    for (int i = 0; i < 0x10000; i++) {
        if (ReadKernel32(base) == MACH_HEADER_MAGIC) {
            return base;
        }
        base -= 0x1000;
    }
    return 0;
}
mach_port_t fake_host_priv_port = MACH_PORT_NULL;

// build a fake host priv port
mach_port_t fake_host_priv()
{
    if (fake_host_priv_port != MACH_PORT_NULL) {
        return fake_host_priv_port;
    }
    // get the address of realhost:
    host_t host = mach_host_self();
    uint64_t hostport_addr = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), host) : find_port_address(host, MACH_MSG_TYPE_COPY_SEND);
    mach_port_deallocate(mach_task_self(), host);
    uint64_t realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));

    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        LOG("failed to allocate port");
        return MACH_PORT_NULL;
    }

    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);

    // locate the port
    uint64_t port_addr = have_kmem_read() && found_offsets ? get_address_of_port(getpid(), port) : find_port_address(port, MACH_MSG_TYPE_COPY_SEND);

    // change the type of the port
    WriteKernel32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE | IKOT_HOST_PRIV);

    // change the space of the port
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());

    // set the kobject
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);

    fake_host_priv_port = port;

    return port;
}

uint64_t get_kernel_proc_struct_addr() {
    static uint64_t kernproc = 0;
    if (kernproc == 0) {
        kernproc = ReadKernel64(ReadKernel64(GETOFFSET(kernel_task)) + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        LOG("kernproc = " ADDR, kernproc);
        if (!KERN_POINTER_VALID(kernproc)) {
            LOG("failed to get kernproc!");
            return 0;
        }
    }
    return kernproc;
}

void iterate_proc_list(void (^handler)(uint64_t, pid_t, bool *)) {
    assert(handler != NULL);
    uint64_t proc = get_kernel_proc_struct_addr();
    if (proc == 0) {
        LOG("failed to get proc!");
        return;
    }
    bool iterate = true;
    while (proc && iterate) {
        pid_t pid = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
        handler(proc, pid, &iterate);
        if (!iterate) {
            break;
        }
        proc = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_P_LIST) + sizeof(void *));
    }
}

uint64_t get_proc_struct_for_pid(pid_t pid)
{
    __block uint64_t proc = 0;
    iterate_proc_list(^(uint64_t found_proc, pid_t found_pid, bool *iterate) {
        if (found_pid == pid) {
            proc = found_proc;
            *iterate = false;
        }
    });
    return proc;
}

uint64_t get_address_of_port(pid_t pid, mach_port_t port)
{
    
    static uint64_t proc_struct_addr = 0;
    static uint64_t task_addr = 0;
    static uint64_t itk_space = 0;
    static uint64_t is_table = 0;
    if (proc_struct_addr == 0) {
        proc_struct_addr = get_proc_struct_for_pid(pid);
        LOG("proc_struct_addr = " ADDR, proc_struct_addr);
        if (!KERN_POINTER_VALID(proc_struct_addr)) {
            LOG("failed to get proc_struct_addr!");
            return 0;
        }
    }
    if (task_addr == 0) {
        task_addr = ReadKernel64(proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_TASK));
        LOG("task_addr = " ADDR, task_addr);
        if (!KERN_POINTER_VALID(task_addr)) {
            LOG("failed to get task_addr!");
            return 0;
        }
    }
    if (itk_space == 0) {
        itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
        LOG("itk_space = " ADDR, itk_space);
        if (!KERN_POINTER_VALID(itk_space)) {
            LOG("failed to get itk_space!");
            return 0;
        }
    }
    if (is_table == 0) {
        is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
        LOG("is_table = " ADDR, is_table);
        if (!KERN_POINTER_VALID(is_table)) {
            LOG("failed to get is_table!");
            return 0;
        }
    }
    uint64_t port_addr = ReadKernel64(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)));
    LOG("port_addr = " ADDR, port_addr);
    if (!KERN_POINTER_VALID(port_addr)) {
        LOG("failed to get port_addr!");
        return 0;
    }
    return port_addr;
}

uint64_t get_kernel_cred_addr()
{
    static uint64_t kernel_proc_struct_addr = 0;
    static uint64_t kernel_ucred_struct_addr = 0;
    if (kernel_proc_struct_addr == 0) {
        kernel_proc_struct_addr = get_proc_struct_for_pid(0);
        LOG("kernel_proc_struct_addr = " ADDR, kernel_proc_struct_addr);
        if (!KERN_POINTER_VALID(kernel_proc_struct_addr)) {
            LOG("failed to get kernel_proc_struct_addr!");
            return 0;
        }
    }
    if (kernel_ucred_struct_addr == 0) {
        kernel_ucred_struct_addr = ReadKernel64(kernel_proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_UCRED));
        LOG("kernel_ucred_struct_addr = " ADDR, kernel_ucred_struct_addr);
        if (!KERN_POINTER_VALID(kernel_ucred_struct_addr)) {
            LOG("failed to get kernel_ucred_struct_addr!");
            return 0;
        }
    }
    return kernel_ucred_struct_addr;
}

uint64_t give_creds_to_process_at_addr(uint64_t proc, uint64_t cred_addr)
{
    uint64_t orig_creds = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    LOG("orig_creds = " ADDR, orig_creds);
    if (!KERN_POINTER_VALID(orig_creds)) {
        LOG("failed to get orig_creds!");
        return 0;
    }
    WriteKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), cred_addr);
    return orig_creds;
}

void set_platform_binary(uint64_t proc, bool set)
{
    uint64_t task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    LOG("task_struct_addr = " ADDR, task_struct_addr);
    if (!KERN_POINTER_VALID(task_struct_addr)) {
        LOG("failed to get task_struct_addr!");
        return;
    }
    uint32_t task_t_flags = ReadKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS));
    if (set) {
        task_t_flags |= TF_PLATFORM;
    } else {
        task_t_flags &= ~(TF_PLATFORM);
    }
    WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags);
}

// Thanks to @Siguza

uint64_t zm_fix_addr(uint64_t addr) {
    typedef struct {
        uint64_t prev;
        uint64_t next;
        uint64_t start;
        uint64_t end;
    } kmap_hdr_t;
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    if (zm_hdr.start == 0) {
        uint64_t zone_map = ReadKernel64(GETOFFSET(zone_map_ref));
        LOG("zone_map: %llx ", zone_map);
        // hdr is at offset 0x10, mutexes at start
        size_t r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        LOG("zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            LOG("kread of zone_map failed!");
            return 0;
        }
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            LOG("zone_map is too big, sorry.");
            return 0;
        }
    }
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}

bool verify_tfp0() {
    size_t test_size = sizeof(uint64_t);
    uint64_t test_kptr = kmem_alloc(test_size);
    if (!KERN_POINTER_VALID(test_kptr)) {
        LOG("failed to allocate kernel memory!");
        return false;
    }
    uint64_t test_write_data = 0x4141414141414141;
    if (!wkbuffer(test_kptr, (void *)&test_write_data, test_size)) {
        LOG("failed to write to kernel memory!");
        return false;
    }
    uint64_t test_read_data = 0;
    if (!rkbuffer(test_kptr, (void *)&test_read_data, test_size)) {
        LOG("failed to read kernel memory!");
        return false;
    }
    if (test_write_data != test_read_data) {
        LOG("failed to verify kernel memory read data!");
        return false;
    }
    if (!kmem_free(test_kptr, test_size)) {
        LOG("failed to deallocate kernel memory!");
        return false;
    }
    return true;
}

int (*pmap_load_trust_cache)(uint64_t kernel_trust, size_t length) = NULL;
int _pmap_load_trust_cache(uint64_t kernel_trust, size_t length) {
    return (int)kexecute(GETOFFSET(pmap_load_trust_cache), kernel_trust, length, 0, 0, 0, 0, 0);
}

void set_host_type(host_t host, uint32_t type) {
    uint64_t hostport_addr = get_address_of_port(getpid(), host);
    uint32_t old = ReadKernel32(hostport_addr);
    LOG("old host type: 0x%08x", old);
    if ((old & type) != type) {
        WriteKernel32(hostport_addr, type);
        uint32_t new = ReadKernel32(hostport_addr);
        LOG("new host type: 0x%08x", new);
    }
}

void export_tfp0(host_t host) {
    set_host_type(host, IO_ACTIVE | IKOT_HOST_PRIV);
}

void unexport_tfp0(host_t host) {
    set_host_type(host, IO_ACTIVE | IKOT_HOST);
}

void set_csflags(uint64_t proc, uint32_t flags, bool value) {
    uint32_t csflags = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS));
    if (value == true) {
        csflags |= flags;
    } else {
        csflags &= ~flags;
    }
    WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS), csflags);
}

void set_cs_platform_binary(uint64_t proc, bool value) {
    set_csflags(proc, CS_PLATFORM_BINARY, value);
}

bool execute_with_credentials(uint64_t proc, uint64_t credentials, void (^function)(void)) {
    assert(function != NULL);
    uint64_t saved_credentials = give_creds_to_process_at_addr(proc, credentials);
    function();
    return (give_creds_to_process_at_addr(proc, saved_credentials) == saved_credentials);
}

uint32_t get_proc_memstat_state(uint64_t proc) {
    return ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_MEMSTAT_STATE));
}

void set_proc_memstat_state(uint64_t proc, uint32_t memstat_state) {
    WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_MEMSTAT_STATE), memstat_state);
}

void set_proc_memstat_internal(uint64_t proc, bool set) {
    uint32_t memstat_state = get_proc_memstat_state(proc);
    if (set) {
        memstat_state |= P_MEMSTAT_INTERNAL;
    } else {
        memstat_state &= ~P_MEMSTAT_INTERNAL;
    }
    set_proc_memstat_state(proc, memstat_state);
}

bool get_proc_memstat_internal(uint64_t proc) {
    return (get_proc_memstat_state(proc) & P_MEMSTAT_INTERNAL);
}

size_t kstrlen(uint64_t ptr) {
    size_t kstrlen = (size_t)kexecute(GETOFFSET(strlen), ptr, 0, 0, 0, 0, 0, 0);
    return kstrlen;
}

uint64_t kstralloc(const char *str) {
    size_t str_kptr_size = strlen(str) + 1;
    uint64_t str_kptr = kmem_alloc(str_kptr_size);
    if (str_kptr != 0) {
        kwrite(str_kptr, str, str_kptr_size);
    }
    return str_kptr;
}

void kstrfree(uint64_t ptr) {
    if (ptr != 0) {
        size_t size = kstrlen(ptr);
        kmem_free(ptr, size);
    }
}

uint64_t sstrdup(const char *str) {
    uint64_t sstrdup = 0;
    uint64_t kstr = kstralloc(str);
    if (kstr != 0) {
        sstrdup = kexecute(GETOFFSET(sstrdup), kstr, 0, 0, 0, 0, 0, 0);
        sstrdup = zm_fix_addr(sstrdup);
        kstrfree(kstr);
    }
    return sstrdup;
}

uint64_t smalloc(size_t size) {
    uint64_t smalloc = kexecute(GETOFFSET(smalloc), (uint64_t)size, 0, 0, 0, 0, 0, 0);
    smalloc = zm_fix_addr(smalloc);
    return smalloc;
}

void sfree(uint64_t ptr) {
    kexecute(GETOFFSET(sfree), ptr, 0, 0, 0, 0, 0, 0);
}

int extension_create_file(uint64_t saveto, uint64_t sb, const char *path, size_t path_len, uint32_t subtype) {
    int extension_create_file = -1;
    uint64_t kstr = kstralloc(path);
    if (kstr != 0) {
        extension_create_file = (int)kexecute(GETOFFSET(extension_create_file), saveto, sb, kstr, (uint64_t)path_len, (uint64_t)subtype, 0, 0);
        kstrfree(kstr);
    }
    return extension_create_file;
}

int extension_create_mach(uint64_t saveto, uint64_t sb, const char *name, uint32_t subtype) {
    int extension_create_mach = -1;
    uint64_t kstr = kstralloc(name);
    if (kstr != 0) {
        extension_create_mach = (int)kexecute(GETOFFSET(extension_create_mach), saveto, sb, kstr, (uint64_t)subtype, 0, 0, 0);
        kstrfree(kstr);
    }
    return extension_create_mach;
}

int extension_add(uint64_t ext, uint64_t sb, const char *desc) {
    int extension_add = -1;
    uint64_t kstr = kstralloc(desc);
    if (kstr != 0) {
        extension_add = (int)kexecute(GETOFFSET(extension_add), ext, sb, kstr, 0, 0, 0, 0);
        kstrfree(kstr);
    }
    return extension_add;
}

void extension_release(uint64_t ext) {
    kexecute(GETOFFSET(extension_release), ext, 0, 0, 0, 0, 0, 0);
}

void extension_destroy(uint64_t ext) {
    kexecute(GETOFFSET(extension_destroy), ext, 0, 0, 0, 0, 0, 0);
}

bool set_file_extension(uint64_t sandbox, const char *exc_key, const char *path) {
    bool set_file_extension = false;
    if (sandbox != 0) {
        uint64_t ext = smalloc(SIZEOF_STRUCT_EXTENSION);
        if (ext != 0) {
            int ret_extension_create_file = extension_create_file(ext, sandbox, path, strlen(path) + 1, 0);
            if (ret_extension_create_file == 0) {
                int ret_extension_add = extension_add(ext, sandbox, exc_key);
                if (ret_extension_add == 0) {
                    set_file_extension = true;
                }
            }
            extension_release(ext);
        }
    } else {
        set_file_extension = true;
    }
    return set_file_extension;
}

bool set_mach_extension(uint64_t sandbox, const char *exc_key, const char *name) {
    bool set_mach_extension = false;
    if (sandbox != 0) {
        uint64_t ext = smalloc(SIZEOF_STRUCT_EXTENSION);
        if (ext != 0) {
            int ret_extension_create_mach = extension_create_mach(ext, sandbox, name, 0);
            if (ret_extension_create_mach == 0) {
                int ret_extension_add = extension_add(ext, sandbox, exc_key);
                if (ret_extension_add == 0) {
                    set_mach_extension = true;
                }
            }
            extension_release(ext);
        }
    } else {
        set_mach_extension = true;
    }
    return set_mach_extension;
}

uint64_t proc_find(pid_t pid) {
    uint64_t proc_find = kexecute(GETOFFSET(proc_find), (uint64_t)pid, 0, 0, 0, 0, 0, 0);
    if (proc_find != 0) {
        proc_find = zm_fix_addr(proc_find);
    }
    return proc_find;
}

void proc_rele(uint64_t proc) {
    kexecute(GETOFFSET(proc_rele), proc, 0, 0, 0, 0, 0, 0);
}

void proc_lock(uint64_t proc) {
    uint64_t function = GETOFFSET(proc_lock);
    if (function != 0) {
        kexecute(function, proc, 0, 0, 0, 0, 0, 0);
    }
}

void proc_unlock(uint64_t proc) {
    uint64_t function = GETOFFSET(proc_unlock);
    if (function != 0) {
        kexecute(function, proc, 0, 0, 0, 0, 0, 0);
    }
}

void proc_ucred_lock(uint64_t proc) {
    uint64_t function = GETOFFSET(proc_ucred_lock);
    if (function != 0) {
        kexecute(function, proc, 0, 0, 0, 0, 0, 0);
    }
}

void proc_ucred_unlock(uint64_t proc) {
    uint64_t function = GETOFFSET(proc_ucred_unlock);
    if (function != 0) {
        kexecute(function, proc, 0, 0, 0, 0, 0, 0);
    }
}

void vnode_lock(uint64_t vp) {
    uint64_t function = GETOFFSET(vnode_lock);
    if (function != 0) {
        kexecute(function, vp, 0, 0, 0, 0, 0, 0);
    }
}

void vnode_unlock(uint64_t vp) {
    uint64_t function = GETOFFSET(vnode_unlock);
    if (function != 0) {
        kexecute(function, vp, 0, 0, 0, 0, 0, 0);
    }
}

void mount_lock(uint64_t mp) {
    uint64_t function = GETOFFSET(mount_lock);
    if (function != 0) {
        kexecute(function, mp, 0, 0, 0, 0, 0, 0);
    }
}

void mount_unlock(uint64_t mp) {
    uint64_t function = GETOFFSET(mount_unlock);
    if (function != 0) {
        kexecute(function, mp, 0, 0, 0, 0, 0, 0);
    }
}

void task_set_platform_binary(uint64_t task, boolean_t is_platform) {
    uint64_t function = GETOFFSET(task_set_platform_binary);
    if (function != 0) {
        kexecute(function, task, (uint64_t)is_platform, 0, 0, 0, 0, 0);
    }
}

int chgproccnt(uid_t uid, int diff) {
    int chgproccnt = 0;
    uint64_t function = GETOFFSET(chgproccnt);
    if (function != 0) {
        chgproccnt = (int)kexecute(function, (uint64_t)uid, (uint64_t)diff, 0, 0, 0, 0, 0);
    }
    return chgproccnt;
}

void kauth_cred_ref(uint64_t cred) {
    uint64_t function = GETOFFSET(kauth_cred_ref);
    if (function != 0) {
        kexecute(function, cred, 0, 0, 0, 0, 0, 0);
    }
}

void kauth_cred_unref(uint64_t cred) {
    uint64_t function = GETOFFSET(kauth_cred_unref);
    if (function != 0) {
        kexecute(function, cred, 0, 0, 0, 0, 0, 0);
    }
}

uint64_t vfs_context_current() {
    uint64_t vfs_context_current = kexecute(GETOFFSET(vfs_context_current), 1, 0, 0, 0, 0, 0, 0);
    vfs_context_current = zm_fix_addr(vfs_context_current);
    return vfs_context_current;
}

int vnode_lookup(const char *path, int flags, uint64_t *vpp, uint64_t ctx) {
    int vnode_lookup = -1;
    uint64_t kstr = kstralloc(path);
    if (kstr != 0) {
        size_t vpp_kptr_size = sizeof(uint64_t);
        uint64_t vpp_kptr = kmem_alloc(vpp_kptr_size);
        if (vpp_kptr != 0) {
            vnode_lookup = (int)kexecute(GETOFFSET(vnode_lookup), kstr, (uint64_t)flags, vpp_kptr, ctx, 0, 0, 0);
            if (vnode_lookup == 0) {
                if (vpp != NULL) {
                    *vpp = ReadKernel64(vpp_kptr);
                }
            }
            kmem_free(vpp_kptr, vpp_kptr_size);
        }
        kstrfree(kstr);
    }
    return vnode_lookup;
}

int vnode_put(uint64_t vp) {
    int vnode_put = (int)kexecute(GETOFFSET(vnode_put), vp, 0, 0, 0, 0, 0, 0);
    return vnode_put;
}

bool OSDictionary_SetItem(uint64_t OSDictionary, const char *key, uint64_t val) {
    bool OSDictionary_SetItem = false;
    uint64_t function = OSObjectFunc(OSDictionary, off_OSDictionary_SetObjectWithCharP);
    if (function != 0) {
        uint64_t kstr = kstralloc(key);
        if (kstr != 0) {
            OSDictionary_SetItem = (bool)kexecute(function, OSDictionary, kstr, val, 0, 0, 0, 0);
            kstrfree(kstr);
        }
    }
    return OSDictionary_SetItem;
}

uint64_t OSDictionary_GetItem(uint64_t OSDictionary, const char *key) {
    uint64_t OSDictionary_GetItem = false;
    uint64_t function = OSObjectFunc(OSDictionary, off_OSDictionary_GetObjectWithCharP);
    if (function != 0) {
        uint64_t kstr = kstralloc(key);
        if (kstr != 0) {
            OSDictionary_GetItem = kexecute(function, OSDictionary, kstr, 0, 0, 0, 0, 0);
            if (OSDictionary_GetItem != 0 && (OSDictionary_GetItem >> 32) == 0) {
                OSDictionary_GetItem = zm_fix_addr(OSDictionary_GetItem);
            }
            kstrfree(kstr);
        }
    }
    return OSDictionary_GetItem;
}

bool OSDictionary_Merge(uint64_t OSDictionary, uint64_t OSDictionary2) {
    bool OSDictionary_Merge = false;
    uint64_t function = OSObjectFunc(OSDictionary, off_OSDictionary_Merge);
    if (function != 0) {
        OSDictionary_Merge = (bool)kexecute(function, OSDictionary, OSDictionary2, 0, 0, 0, 0, 0);
    }
    return OSDictionary_Merge;
}

uint32_t OSDictionary_ItemCount(uint64_t OSDictionary) {
    uint32_t OSDictionary_ItemCount = 0;
    if (OSDictionary != 0) {
        OSDictionary_ItemCount = ReadKernel32(OSDictionary + 20);
    }
    return OSDictionary_ItemCount;
}

uint64_t OSDictionary_ItemBuffer(uint64_t OSDictionary) {
    uint64_t OSDictionary_ItemBuffer = 0;
    if (OSDictionary != 0) {
        OSDictionary_ItemBuffer = ReadKernel64(OSDictionary + 32);
    }
    return OSDictionary_ItemBuffer;
}

uint64_t OSDictionary_ItemKey(uint64_t buffer, uint32_t idx) {
    uint64_t OSDictionary_ItemKey = 0;
    if (buffer != 0) {
        OSDictionary_ItemKey = ReadKernel64(buffer + 16 + idx);
    }
    return OSDictionary_ItemKey;
}

uint64_t OSDictionary_ItemValue(uint64_t buffer, uint32_t idx) {
    uint64_t OSDictionary_ItemValue = 0;
    if (buffer != 0) {
        OSDictionary_ItemValue = ReadKernel64(buffer + 16 * idx + 8);
    }
    return OSDictionary_ItemValue;
}

bool OSArray_Merge(uint64_t OSArray, uint64_t OSArray2) {
    bool OSArray_Merge = false;
    uint64_t function = OSObjectFunc(OSArray, off_OSArray_Merge);
    if (function != 0) {
        OSArray_Merge = (bool)kexecute(function, OSArray, OSArray2, 0, 0, 0, 0, 0);
    }
    return OSArray_Merge;
}

uint64_t OSArray_GetObject(uint64_t OSArray, uint32_t idx) {
    uint64_t OSArray_GetObject = 0;
    uint64_t function = OSObjectFunc(OSArray, off_OSArray_GetObject);
    if (function != 0) {
        OSArray_GetObject = kexecute(OSArray, idx, 0, 0, 0, 0, 0, 0);
        if (OSArray_GetObject != 0) {
            OSArray_GetObject = zm_fix_addr(OSArray_GetObject);
        }
    }
    return OSArray_GetObject;
}

void OSArray_RemoveObject(uint64_t OSArray, uint32_t idx) {
    uint64_t function = OSObjectFunc(OSArray, off_OSArray_RemoveObject);
    if (function != 0) {
        kexecute(function, OSArray, idx, 0, 0, 0, 0, 0);
    }
}

uint32_t OSArray_ItemCount(uint64_t OSArray) {
    uint32_t OSArray_ItemCount = 0;
    if (OSArray != 0) {
        OSArray_ItemCount = ReadKernel32(OSArray + 0x14);
    }
    return OSArray_ItemCount;
}

uint64_t OSArray_ItemBuffer(uint64_t OSArray) {
    uint64_t OSArray_ItemBuffer = 0;
    if (OSArray != 0) {
        OSArray_ItemBuffer = ReadKernel64(OSArray + 32);
    }
    return OSArray_ItemBuffer;
}

uint64_t OSObjectFunc(uint64_t OSObject, uint32_t off) {
    uint64_t OSObjectFunc = 0;
    uint64_t vtable = ReadKernel64(OSObject);
    vtable = kernel_xpacd(vtable);
    if (vtable != 0) {
        OSObjectFunc = ReadKernel64(vtable + off);
        OSObjectFunc = kernel_xpaci(OSObjectFunc);
    }
    return OSObjectFunc;
}

void OSObject_Release(uint64_t OSObject) {
    uint64_t function = OSObjectFunc(OSObject, off_OSObject_Release);
    if (function != 0) {
        kexecute(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
}

void OSObject_Retain(uint64_t OSObject) {
    uint64_t function = OSObjectFunc(OSObject, off_OSObject_Retain);
    if (function != 0) {
        kexecute(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
}

uint32_t OSObject_GetRetainCount(uint64_t OSObject) {
    uint32_t OSObject_GetRetainCount = 0;
    uint64_t function = OSObjectFunc(OSObject, off_OSObject_GetRetainCount);
    if (function != 0) {
        OSObject_GetRetainCount = (uint32_t)kexecute(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
    return OSObject_GetRetainCount;
}

uint32_t OSString_GetLength(uint64_t OSString) {
    uint32_t OSString_GetLength = 0;
    uint64_t function = OSObjectFunc(OSString, off_OSString_GetLength);
    if (function != 0) {
        OSString_GetLength = (uint32_t)kexecute(function, OSString, 0, 0, 0, 0, 0, 0);
    }
    return OSString_GetLength;
}

uint64_t OSString_CStringPtr(uint64_t OSString) {
    uint64_t OSString_CStringPtr = 0;
    if (OSString != 0) {
        OSString_CStringPtr = ReadKernel64(OSString + 0x10);
    }
    return OSString_CStringPtr;
}

char *OSString_CopyString(uint64_t OSString) {
    char *OSString_CopyString = NULL;
    uint32_t length = OSString_GetLength(OSString);
    if (length != 0) {
        char *str = malloc(length + 1);
        if (str != NULL) {
            str[length] = 0;
            uint64_t CStringPtr = OSString_CStringPtr(OSString);
            if (CStringPtr != 0) {
                if (kread(CStringPtr, str, length) == length) {
                    OSString_CopyString = strdup(str);
                }
            }
            free(str);
        }
    }
    return OSString_CopyString;
}

uint64_t OSUnserializeXML(const char *buffer) {
    uint64_t OSUnserializeXML = 0;
    uint64_t kstr = kstralloc(buffer);
    if (kstr != 0) {
        uint64_t error_kptr = 0;
        OSUnserializeXML = kexecute(GETOFFSET(osunserializexml), kstr, error_kptr, 0, 0, 0, 0, 0);
        if (OSUnserializeXML != 0) {
            OSUnserializeXML = zm_fix_addr(OSUnserializeXML);
        }
        kstrfree(kstr);
    }
    return OSUnserializeXML;
}

uint64_t get_exception_osarray(const char **exceptions) {
    uint64_t exception_osarray = 0;
    size_t xmlsize = 0x1000;
    size_t len=0;
    ssize_t written=0;
    char *ents = malloc(xmlsize);
    if (ents == NULL) {
        return 0;
    }
    size_t xmlused = sprintf(ents, "<array>");
    for (const char **exception = exceptions; *exception; exception++) {
        len = strlen(*exception);
        len += strlen("<string></string>");
        while (xmlused + len >= xmlsize) {
            xmlsize += 0x1000;
            ents = reallocf(ents, xmlsize);
            if (!ents) {
                return 0;
            }
        }
        written = sprintf(ents + xmlused, "<string>%s/</string>", *exception);
        if (written < 0) {
            free(ents);
            return 0;
        }
        xmlused += written;
    }
    len = strlen("</array>");
    if (xmlused + len >= xmlsize) {
        xmlsize += len;
        ents = reallocf(ents, xmlsize);
        if (!ents) {
            return 0;
        }
    }
    written = sprintf(ents + xmlused, "</array>");
    
    exception_osarray = OSUnserializeXML(ents);
    free(ents);
    return exception_osarray;
}

char **copy_amfi_entitlements(uint64_t present) {
    unsigned int itemCount = OSArray_ItemCount(present);
    uint64_t itemBuffer = OSArray_ItemBuffer(present);
    size_t bufferSize = 0x1000;
    size_t bufferUsed = 0;
    size_t arraySize = (itemCount + 1) * sizeof(char *);
    char **entitlements = malloc(arraySize + bufferSize);
    if (!entitlements) {
        return NULL;
    }
    entitlements[itemCount] = NULL;
    
    for (int i = 0; i < itemCount; i++) {
        uint64_t item = ReadKernel64(itemBuffer + (i * sizeof(void *)));
        char *entitlementString = OSString_CopyString(item);
        if (!entitlementString) {
            free(entitlements);
            return NULL;
        }
        size_t len = strlen(entitlementString) + 1;
        while (bufferUsed + len > bufferSize) {
            bufferSize += 0x1000;
            entitlements = realloc(entitlements, arraySize + bufferSize);
            if (!entitlements) {
                free(entitlementString);
                return NULL;
            }
        }
        entitlements[i] = (char*)entitlements + arraySize + bufferUsed;
        strcpy(entitlements[i], entitlementString);
        bufferUsed += len;
        free(entitlementString);
    }
    return entitlements;
}

uint64_t getOSBool(bool value) {
    uint64_t OSBool = 0;
    if (value) {
        OSBool = ReadKernel64(GETOFFSET(OSBoolean_True));
    } else {
        OSBool = ReadKernel64(GETOFFSET(OSBoolean_True)) + sizeof(void *);
    }
    return OSBool;
}

bool entitleProcess(uint64_t amfi_entitlements, const char *key, uint64_t val) {
    bool entitleProcess = false;
    if (amfi_entitlements != 0) {
        if (OSDictionary_GetItem(amfi_entitlements, key) != val) {
            entitleProcess = OSDictionary_SetItem(amfi_entitlements, key, val);
        }
    }
    return entitleProcess;
}

bool exceptionalizeProcess(uint64_t sandbox, uint64_t amfi_entitlements, const char **exceptions) {
    bool exceptionalizeProcess = true;
    if (sandbox != 0) {
        for (const char **exception = exceptions; *exception; exception++) {
            if (!set_file_extension(sandbox, FILE_EXC_KEY, *exception)) {
                exceptionalizeProcess = false;
            }
        }
        if (amfi_entitlements != 0) {
            uint64_t presentExceptionOSArray = OSDictionary_GetItem(amfi_entitlements, FILE_EXC_KEY);
            if (presentExceptionOSArray != 0) {
                char **currentExceptions = copy_amfi_entitlements(presentExceptionOSArray);
                if (currentExceptions != NULL) {
                    for (const char **exception = exceptions; *exception; exception++) {
                        bool foundException = false;
                        for (char **entitlementString = currentExceptions; *entitlementString && !foundException; entitlementString++) {
                            char *ent = strdup(*entitlementString);
                            if (ent != NULL) {
                                size_t lastchar = strlen(ent) - 1;
                                if (ent[lastchar] == '/') ent[lastchar] = '\0';
                                if (strcasecmp(ent, *exception) == 0) {
                                    foundException = true;
                                }
                                free(ent);
                            }
                        }
                        if (!foundException) {
                            const char **exception_array = malloc(((1 + 1) * sizeof(char *)) + MAXPATHLEN);
                            if (exception_array != NULL) {
                                exception_array[0] = *exception;
                                exception_array[1] = NULL;
                                uint64_t exceptionOSArray = get_exception_osarray(exception_array);
                                if (exceptionOSArray != 0) {
                                    if (!OSArray_Merge(presentExceptionOSArray, exceptionOSArray)) {
                                        exceptionalizeProcess = false;
                                    }
                                    OSObject_Release(exceptionOSArray);
                                }
                                free(exception_array);
                            }
                        }
                    }
                    free(currentExceptions);
                }
            } else {
                uint64_t exceptionOSArray = get_exception_osarray(exceptions);
                if (exceptionOSArray != 0) {
                    if (!OSDictionary_SetItem(amfi_entitlements, FILE_EXC_KEY, exceptionOSArray)) {
                        exceptionalizeProcess = false;
                    }
                    OSObject_Release(exceptionOSArray);
                }
            }
        }
    }
    return exceptionalizeProcess;
}

bool unrestrictProcess(pid_t pid) {
    bool unrestrictProcess = true;
    LOG("%s(%d): Unrestricting", __FUNCTION__, pid);
    uint64_t proc = proc_find(pid);
    if (proc != 0) {
        LOG("%s(%d): Found proc: 0x%llx", __FUNCTION__, pid, proc);
        uint64_t proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
        LOG("%s(%d): Found proc_ucred: 0x%llx", __FUNCTION__, pid, proc_ucred);
        if (proc_ucred != 0) {
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
            bzero(pathbuf, sizeof(pathbuf));
            if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
                LOG("%s(%d): Found path: %s", __FUNCTION__, pid, pathbuf);
                struct stat statbuf;
                if (lstat(pathbuf, &statbuf) == 0) {
                    LOG("%s(%d): Got stat for path", __FUNCTION__, pid);
                    if ((statbuf.st_mode & S_ISUID)) {
                        LOG("%s(%d): Enabling setuid", __FUNCTION__, pid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_SVUID), statbuf.st_uid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_UCRED_CR_SVUID), statbuf.st_uid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_UCRED_CR_UID), statbuf.st_uid);
                    }
                    if ((statbuf.st_mode & S_ISGID)) {
                        LOG("%s(%d): Enabling setgid", __FUNCTION__, pid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_SVGID), statbuf.st_gid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_UCRED_CR_SVGID), statbuf.st_gid);
                        WriteKernel32(proc + koffset(KSTRUCT_OFFSET_UCRED_CR_GROUPS), statbuf.st_gid);
                    }
                } else {
                    LOG("%s(%d): Unable to get stat for path", __FUNCTION__, pid);
                    unrestrictProcess = false;
                }
            } else {
                LOG("%s(%d): Unable to find path", __FUNCTION__, pid);
                unrestrictProcess = false;
            }
            uint64_t cr_label = ReadKernel64(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
            if (cr_label != 0) {
                LOG("%s(%d): Found cr_label: 0x%llx", __FUNCTION__, pid, cr_label);
                uint64_t amfi_entitlements = get_amfi_entitlements(cr_label);
                uint64_t sandbox = get_sandbox(cr_label);
                LOG("%s(%d): Entitling process with: %s", __FUNCTION__, pid, "com.apple.private.skip-library-validation");
                entitleProcess(amfi_entitlements, "com.apple.private.skip-library-validation", OSBoolTrue);
                if (OPT(GET_TASK_ALLOW)) {
                    LOG("%s(%d): Entitling process with: %s", __FUNCTION__, pid, "get-task-allow");
                    entitleProcess(amfi_entitlements, "get-task-allow", OSBoolTrue);
                }
                LOG("%s(%d): Exceptionalizing process with: %s", __FUNCTION__, pid, "abs_path_exceptions");
                if (!exceptionalizeProcess(sandbox, amfi_entitlements, abs_path_exceptions)) {
                    LOG("%s(%d): Unable to exceptionalize process");
                    unrestrictProcess = false;
                }
                if (amfi_entitlements != 0) {
                    if (OSDictionary_GetItem(amfi_entitlements, "platform-application") == OSBoolTrue) {
                        LOG("%s(%d): Setting TF_PLATFORM", __FUNCTION__, pid);
                        set_platform_binary(proc, true);
                    }
                }
            } else {
                LOG("%s(%d): Unable to find cr_label", __FUNCTION__, pid);
                unrestrictProcess = false;
            }
        } else {
            LOG("%s(%d): Unable to find proc_ucred", __FUNCTION__, pid);
            unrestrictProcess = false;
        }
        uint32_t cs_flags = 0;
        if (csops(pid, CS_OPS_STATUS, (void *)&cs_flags, sizeof(cs_flags)) == 0) {
            LOG("%s(%d): Found cs_flags: 0x%x", __FUNCTION__, pid, cs_flags);
            if (!(cs_flags & CS_PLATFORM_BINARY)) {
                LOG("%s(%d): Setting CS_PLATFORM_BINARY", __FUNCTION__, pid);
                set_csflags(proc, CS_PLATFORM_BINARY, true);
            }
            if ((cs_flags & CS_REQUIRE_LV)) {
                LOG("%s(%d): Unsetting CS_REQUIRE_LV", __FUNCTION__, pid);
                set_csflags(proc, CS_REQUIRE_LV, false);
            }
            if ((cs_flags & CS_CHECK_EXPIRATION)) {
                LOG("%s(%d): Unsetting CS_CHECK_EXPIRATION", __FUNCTION__, pid);
                set_csflags(proc, CS_CHECK_EXPIRATION, false);
            }
            if (!(cs_flags & CS_DYLD_PLATFORM)) {
                LOG("%s(%d): Setting CS_DYLD_PLATFORM", __FUNCTION__, pid);
                set_csflags(proc, CS_DYLD_PLATFORM, true);
            }
            if (OPT(GET_TASK_ALLOW)) {
                if (!(cs_flags & CS_GET_TASK_ALLOW)) {
                    LOG("%s(%d): Setting CS_GET_TASK_ALLOW", __FUNCTION__, pid);
                    set_csflags(proc, CS_GET_TASK_ALLOW, true);
                }
                if (!(cs_flags & CS_INSTALLER)) {
                    LOG("%s(%d): Setting CS_INSTALLER", __FUNCTION__, pid);
                    set_csflags(proc, CS_INSTALLER, true);
                }
                if ((cs_flags & CS_RESTRICT)) {
                    LOG("%s(%d): Unsetting CS_RESTRICT", __FUNCTION__, pid);
                    set_csflags(proc, CS_RESTRICT, false);
                }
            }
            if (OPT(CS_DEBUGGED)) {
                if (!(cs_flags & CS_DEBUGGED)) {
                    LOG("%s(%d): Setting CS_DEBUGGED", __FUNCTION__, pid);
                    set_csflags(proc, CS_DEBUGGED, true);
                }
                if ((cs_flags & CS_HARD)) {
                    LOG("%s(%d): Unsetting CS_HARD", __FUNCTION__, pid);
                    set_csflags(proc, CS_HARD, false);
                }
                if ((cs_flags & CS_KILL)) {
                    LOG("%s(%d): Unsetting CS_KILL", __FUNCTION__, pid);
                    set_csflags(proc, CS_KILL, false);
                }
            }
        } else {
            LOG("%s(%d): Unable to find cs_flags", __FUNCTION__, pid);
            unrestrictProcess = false;
        }
        LOG("%s(%d): Releasing proc", __FUNCTION__, pid);
        proc_rele(proc);
    } else {
        LOG("%s(%d): Unable to find proc", __FUNCTION__, pid);
        unrestrictProcess = false;
    }
    if (unrestrictProcess) {
        LOG("%s(%d): Unrestricted process", __FUNCTION__, pid);
    } else {
        LOG("%s(%d): Unable to unrestrict process", __FUNCTION__, pid);
    }
    return unrestrictProcess;
}

bool unrestrictProcessWithTaskPort(mach_port_t task_port) {
    bool unrestrictProcessWithTaskPort = false;
    pid_t pid = 0;
    if (pid_for_task(mach_task_self(), &pid) == KERN_SUCCESS) {
        unrestrictProcessWithTaskPort = unrestrictProcess(pid);
    }
    return unrestrictProcessWithTaskPort;
}

bool revalidateProcess(pid_t pid) {
    bool revalidateProcess = true;
    LOG("%s(%d): Revalidating", __FUNCTION__, pid);
    uint32_t cs_flags = 0;
    if (csops(pid, CS_OPS_STATUS, (void *)&cs_flags, sizeof(cs_flags)) == 0) {
        if (!(cs_flags & CS_VALID)) {
            uint64_t proc = proc_find(pid);
            if (proc != 0) {
                LOG("%s(%d): Found proc: 0x%llx", __FUNCTION__, pid, proc);
                LOG("%s(%d): Setting CS_VALID", __FUNCTION__, pid);
                set_csflags(proc, CS_VALID, true);
                LOG("%s(%d): Releasing proc", __FUNCTION__, pid);
                proc_rele(proc);
            } else {
                LOG("%s(%d): Unable to find proc", __FUNCTION__, pid);
                revalidateProcess = false;
            }
        }
    }
    if (revalidateProcess) {
        LOG("%s(%d): Revalidated process", __FUNCTION__, pid);
    } else {
        LOG("%s(%d): Unable to revalidate process", __FUNCTION__, pid);
    }
    return revalidateProcess;
}

bool revalidateProcessWithTaskPort(mach_port_t task_port) {
    bool revalidateProcessWithTaskPort = false;
    pid_t pid = 0;
    if (pid_for_task(mach_task_self(), &pid) == KERN_SUCCESS) {
        revalidateProcessWithTaskPort = revalidateProcess(pid);
    }
    return revalidateProcessWithTaskPort;
}

uint64_t get_amfi_entitlements(uint64_t cr_label) {
    uint64_t amfi_entitlements = 0;
    amfi_entitlements = ReadKernel64(cr_label + 0x8);
    return amfi_entitlements;
}

uint64_t get_sandbox(uint64_t cr_label) {
    uint64_t sandbox = 0;
    sandbox = ReadKernel64(cr_label + 0x8 + 0x8);
    return sandbox;
}

bool entitleProcessWithPid(pid_t pid, const char *key, uint64_t val) {
    bool entitleProcessWithPid = true;
    uint64_t proc = proc_find(pid);
    if (proc != 0) {
        LOG("%s: Found proc: 0x%llx", __FUNCTION__, proc);
        uint64_t proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
        if (proc_ucred != 0) {
            LOG("%s: Found proc_ucred: 0x%llx", __FUNCTION__, proc_ucred);
            uint64_t cr_label = ReadKernel64(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
            if (cr_label != 0) {
                LOG("%s: Found cr_label: 0x%llx", __FUNCTION__, cr_label);
                uint64_t amfi_entitlements = get_amfi_entitlements(cr_label);
                if (amfi_entitlements != 0) {
                    LOG("%s: Found amfi_entitlements: 0x%llx", __FUNCTION__, amfi_entitlements);
                    entitleProcessWithPid = entitleProcess(amfi_entitlements, key, val);
                } else {
                    LOG("%s: Unable to find amfi_entitlements", __FUNCTION__);
                    entitleProcessWithPid = false;
                }
            } else {
                LOG("%s: Unable to find cr_label", __FUNCTION__);
                entitleProcessWithPid = false;
            }
        } else {
            LOG("%s: Unable to find proc_ucred", __FUNCTION__);
            entitleProcessWithPid = false;
        }
        LOG("%s: Releasing proc: 0x%llx", __FUNCTION__, proc);
        proc_rele(proc);
    } else {
        LOG("%s: Unable to find proc", __FUNCTION__);
        entitleProcessWithPid = false;
    }
    return entitleProcessWithPid;
}

bool removeMemoryLimit() {
    bool removeMemoryLimit = false;
    if (entitleProcessWithPid(getpid(), "com.apple.private.memorystatus", OSBoolTrue)) {
        if (memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid(), 0, NULL, 0) == 0) {
            removeMemoryLimit = true;
        }
    }
    return removeMemoryLimit;
}
