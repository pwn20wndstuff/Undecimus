#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>

#include <common.h>
#include <iokit.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>

#include "KernelMemory.h"
#include "KernelOffsets.h"
#include "KernelUtilities.h"
#if __has_include("find_port.h")
#include "find_port.h"
#else
#define find_port_address(port, disposition) KPTR_NULL
#endif
#include "KernelExecution.h"
#include "pac.h"
#include "kernel_call.h"
#ifdef UNDECIMUS
extern char *get_path_for_pid(pid_t pid);
extern bool is_symlink(const char *filename);
extern bool is_directory(const char *filename);
#else
#include "utils.h"
#endif

#define _assert(test) do { \
    if (test) break; \
    int saved_errno = errno; \
    LOG("_assert(%d:%s)@%s:%u[%s]", saved_errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
    errno = saved_errno; \
    goto out; \
} while(false)

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

#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)

#define CS_OPS_STATUS 0
#define CS_OPS_ENTITLEMENTS_BLOB 7

#define VSHARED_DYLD 0x000200 /* vnode is a dyld shared cache file */

#define FILE_READ_EXC_KEY "com.apple.security.exception.files.absolute-path.read-only"
#define FILE_READ_WRITE_EXC_KEY "com.apple.security.exception.files.absolute-path.read-write"
#define MACH_LOOKUP_EXC_KEY "com.apple.security.exception.mach-lookup.global-name"
#define MACH_REGISTER_EXC_KEY "com.apple.security.exception.mach-register.global-name"

static const char *file_read_exceptions[] = {
    "/Library",
    "/System",
    "/private/var/mnt",
    NULL
};

static const char *file_read_write_exceptions[] = {
    "/private/var/mobile/Library",
    NULL
};

static const char *mach_lookup_exceptions[] = {
    "cy:com.saurik.substrated",
    "ch.ringwald.hidsupport.backboard",
    "com.rpetrich.rocketbootstrapd",
    "com.apple.BTLEAudioController.xpc",
    "com.apple.backboard.hid.services",
    "com.apple.commcenter.coretelephony.xpc",
    NULL
};

static const char *mach_register_exceptions[] = {
    "ch.ringwald.hidsupport.backboard",
    NULL
};

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6

int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

kptr_t kernel_base = KPTR_NULL;
kptr_t offset_options = KPTR_NULL;
bool found_offsets = false;
kptr_t cached_task_self_addr = KPTR_NULL;
kptr_t cached_proc_struct_addr = KPTR_NULL;
static bool weird_offsets = false;

#define find_port(port, disposition) (have_kmem_read() && found_offsets ? get_address_of_port(proc_struct_addr(), port) : find_port_address(port, disposition))

kptr_t task_self_addr()
{
    kptr_t ret = KPTR_NULL;
    if (KERN_POINTER_VALID((ret = cached_task_self_addr))) goto out;
    cached_task_self_addr = find_port(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
out:;
    return cached_task_self_addr;
}

kptr_t ipc_space_kernel()
{
    kptr_t ret = KPTR_NULL;
    kptr_t const task_self = task_self_addr();
    _assert(KERN_POINTER_VALID(task_self));
    kptr_t const ipc_space = ReadKernel64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
    _assert(KERN_POINTER_VALID(ipc_space));
    ret = ipc_space;
out:;
    return ret;
}

kptr_t current_thread()
{
    kptr_t ret = KPTR_NULL;
    thread_t thread = THREAD_NULL;
    thread = mach_thread_self();
    _assert(MACH_PORT_VALID(thread));
    kptr_t const thread_port = find_port(thread, MACH_MSG_TYPE_COPY_SEND);
    _assert(KERN_POINTER_VALID(thread_port));
    kptr_t const thread_addr = ReadKernel64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    _assert(thread_addr);
    ret = thread_addr;
out:;
    if (MACH_PORT_VALID(thread)) mach_port_deallocate(mach_task_self(), thread); thread = THREAD_NULL;
    return ret;
}

kptr_t find_kernel_base()
{
    kptr_t ret = KPTR_NULL;
    host_t host = HOST_NULL;
    host = mach_host_self();
    _assert(MACH_PORT_VALID(host));
    kptr_t const hostport_addr = find_port(host, MACH_MSG_TYPE_COPY_SEND);
    _assert(KERN_POINTER_VALID(hostport_addr));
    kptr_t const realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    _assert(KERN_POINTER_VALID(realhost));
    kptr_t base = realhost & ~0xfffULL;
    // walk down to find the magic:
    for (int i = 0; i < 0x10000; i++) {
        if (ReadKernel32(base) == MACH_HEADER_MAGIC) {
            ret = base;
            goto out;
        }
        base -= 0x1000;
    }
out:;
    if (MACH_PORT_VALID(host)) mach_port_deallocate(mach_task_self(), host); host = HOST_NULL;
    return ret;
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
    kptr_t hostport_addr = find_port(host, MACH_MSG_TYPE_COPY_SEND);
    mach_port_deallocate(mach_task_self(), host);
    kptr_t realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));

    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err = KERN_FAILURE;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        LOG("failed to allocate port");
        return MACH_PORT_NULL;
    }

    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);

    // locate the port
    kptr_t port_addr = find_port(port, MACH_MSG_TYPE_COPY_SEND);

    // change the type of the port
    WriteKernel32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_BITS_ACTIVE | IKOT_HOST_PRIV);

    // change the space of the port
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());

    // set the kobject
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);

    fake_host_priv_port = port;

    return port;
}

#undef find_port

kptr_t get_kernel_proc_struct_addr() {
    kptr_t ret = KPTR_NULL;
    kptr_t const symbol = getoffset(kernel_task);
    _assert(KERN_POINTER_VALID(symbol));
    kptr_t const task = ReadKernel64(symbol);
    _assert(KERN_POINTER_VALID(task));
    kptr_t const bsd_info = ReadKernel64(task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    _assert(KERN_POINTER_VALID(bsd_info));
    ret = bsd_info;
out:;
    return ret;
}

bool iterate_proc_list(void (^handler)(kptr_t, pid_t, bool *)) {
    bool ret = false;
    _assert(handler != NULL);
    bool iterate = true;
    kptr_t proc = get_kernel_proc_struct_addr();
    _assert(KERN_POINTER_VALID(proc));
    while (KERN_POINTER_VALID(proc) && iterate) {
        pid_t const pid = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
        handler(proc, pid, &iterate);
        if (!iterate) break;
        proc = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_P_LIST) + sizeof(kptr_t));
    }
    ret = true;
out:;
    return ret;
}

kptr_t get_proc_struct_for_pid(pid_t pid)
{
    __block kptr_t proc = KPTR_NULL;
    void (^const handler)(kptr_t, pid_t, bool *) = ^(kptr_t found_proc, pid_t found_pid, bool *iterate) {
        if (found_pid == pid) {
            proc = found_proc;
            *iterate = false;
        }
    };
    _assert(iterate_proc_list(handler));
out:;
    return proc;
}

kptr_t proc_struct_addr()
{
    kptr_t ret = KPTR_NULL;
    if (KERN_POINTER_VALID((ret = cached_proc_struct_addr))) goto out;
    cached_proc_struct_addr = get_proc_struct_for_pid(getpid());
out:;
    return cached_proc_struct_addr;
}

kptr_t get_address_of_port(kptr_t proc, mach_port_t port)
{
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(proc));
    _assert(MACH_PORT_VALID(port));
    kptr_t const task_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    _assert(KERN_POINTER_VALID(task_addr));
    kptr_t const itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    _assert(KERN_POINTER_VALID(itk_space));
    kptr_t const is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    _assert(KERN_POINTER_VALID(is_table));
    kptr_t const port_addr = ReadKernel64(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)));
    _assert(KERN_POINTER_VALID(port_addr));
    ret = port_addr;
out:;
    return ret;
}

kptr_t get_kernel_cred_addr()
{
    kptr_t ret = KPTR_NULL;
    kptr_t const kernel_proc_struct_addr = get_kernel_proc_struct_addr();
    _assert(KERN_POINTER_VALID(kernel_proc_struct_addr));
    kptr_t const kernel_ucred_struct_addr = ReadKernel64(kernel_proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    _assert(KERN_POINTER_VALID(kernel_ucred_struct_addr));
    ret = kernel_ucred_struct_addr;
out:;
    return ret;
}

kptr_t give_creds_to_process_at_addr(kptr_t proc, kptr_t cred_addr)
{
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(proc));
    _assert(KERN_POINTER_VALID(cred_addr));
    kptr_t const proc_cred_addr = proc + koffset(KSTRUCT_OFFSET_PROC_UCRED);
    kptr_t const current_cred_addr = ReadKernel64(proc_cred_addr);
    _assert(KERN_POINTER_VALID(current_cred_addr));
    _assert(WriteKernel64(proc_cred_addr, cred_addr));
    ret = current_cred_addr;
out:;
    return ret;
}

bool set_platform_binary(kptr_t proc, bool set)
{
    bool ret = false;
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    _assert(KERN_POINTER_VALID(task_struct_addr));
    kptr_t const task_t_flags_addr = task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS);
    uint32_t task_t_flags = ReadKernel32(task_t_flags_addr);
    if (set) {
        task_t_flags |= TF_PLATFORM;
    } else {
        task_t_flags &= ~(TF_PLATFORM);
    }
    _assert(WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags));
    ret = true;
out:;
    return ret;
}

kptr_t zm_fix_addr(kptr_t addr) {
    typedef struct {
        uint64_t prev;
        uint64_t next;
        uint64_t start;
        uint64_t end;
    } kmap_hdr_t;
    kptr_t zm_fixed_addr = KPTR_NULL;
    kmap_hdr_t *zm_hdr = NULL;
    kptr_t const symbol = getoffset(zone_map_ref);
    _assert(KERN_POINTER_VALID(symbol));
    zm_hdr = malloc(sizeof(kmap_hdr_t));
    _assert(zm_hdr != NULL);
    kptr_t const zone_map = ReadKernel64(symbol);
    _assert(KERN_POINTER_VALID(zone_map));
    _assert(rkbuffer(zone_map + 0x10, zm_hdr, sizeof(kmap_hdr_t)));
    _assert(zm_hdr->end - zm_hdr->start <= 0x100000000);
    kptr_t const zm_tmp = (zm_hdr->start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    zm_fixed_addr = zm_tmp < zm_hdr->start ? zm_tmp + 0x100000000 : zm_tmp;
out:;
    SafeFreeNULL(zm_hdr);
    return zm_fixed_addr;
}

bool verify_tfp0() {
    bool ret = false;
    size_t test_kptr_size = 0;
    kptr_t test_kptr = KPTR_NULL;
    kptr_t const test_data = 0x4141414141414141;
    test_kptr_size = sizeof(kptr_t);
    test_kptr = kmem_alloc(test_kptr_size);
    _assert(KERN_POINTER_VALID(test_kptr));
    _assert(WriteKernel64(test_kptr, test_data));
    _assert(ReadKernel64(test_kptr) == test_data);
    ret = true;
out:;
    if (KERN_POINTER_VALID(test_kptr)) kmem_free(test_kptr, test_kptr_size); test_kptr = KPTR_NULL;
    return ret;
}

int (*pmap_load_trust_cache)(kptr_t kernel_trust, size_t length) = NULL;
int _pmap_load_trust_cache(kptr_t kernel_trust, size_t length) {
    int ret = -1;
    _assert(KERN_POINTER_VALID(kernel_trust));
    kptr_t const function = getoffset(pmap_load_trust_cache);
    _assert(KERN_POINTER_VALID(function));
    ret = (int)kexec(function, kernel_trust, (kptr_t)length, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

bool set_host_type(host_t host, uint32_t type) {
    bool ret = false;
    _assert(MACH_PORT_VALID(host));
    kptr_t const hostport_addr = get_address_of_port(proc_struct_addr(), host);
    _assert(KERN_POINTER_VALID(hostport_addr));
    _assert(WriteKernel32(hostport_addr, type));
    ret = true;
out:;
    return ret;
}

bool export_tfp0(host_t host) {
    bool ret = false;
    _assert(MACH_PORT_VALID(host));
    uint32_t const type = IO_BITS_ACTIVE | IKOT_HOST_PRIV;
    _assert(set_host_type(host, type));
    ret = true;
out:;
    return ret;
}

bool unexport_tfp0(host_t host) {
    bool ret = false;
    _assert(MACH_PORT_VALID(host));
    uint32_t const type = IO_BITS_ACTIVE | IKOT_HOST;
    _assert(set_host_type(host, type));
    ret = true;
out:;
    return ret;
}

bool set_csflags(kptr_t proc, uint32_t flags, bool value) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const proc_csflags_addr = proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS);
    uint32_t csflags = ReadKernel32(proc_csflags_addr);
    if (value == true) {
        csflags |= flags;
    } else {
        csflags &= ~flags;
    }
    _assert(WriteKernel32(proc_csflags_addr, csflags));
    ret = true;
out:;
    return ret;
}

bool set_cs_platform_binary(kptr_t proc, bool value) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(proc));
    _assert(set_csflags(proc, CS_PLATFORM_BINARY, value));
    ret = true;
out:;
    return ret;
}

bool execute_with_credentials(kptr_t proc, kptr_t credentials, void (^function)(void)) {
    bool ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(proc));
    _assert(KERN_POINTER_VALID(credentials));
    _assert(function != NULL);
    kptr_t const saved_credentials = give_creds_to_process_at_addr(proc, credentials);
    _assert(KERN_POINTER_VALID(saved_credentials));
    function();
    ret = give_creds_to_process_at_addr(proc, saved_credentials);
out:;
    return ret;
}

uint32_t get_proc_memstat_state(kptr_t proc) {
    uint32_t ret = 0;
    _assert(KERN_POINTER_VALID(proc));
    uint32_t const p_memstat_state = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_MEMSTAT_STATE));
    ret = p_memstat_state;
out:;
    return ret;
}

bool set_proc_memstat_state(kptr_t proc, uint32_t memstat_state) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(proc));
    _assert(WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_MEMSTAT_STATE), memstat_state));
    ret = true;
out:;
    return ret;
}

bool set_proc_memstat_internal(kptr_t proc, bool set) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(proc));
    uint32_t memstat_state = get_proc_memstat_state(proc);
    if (set) {
        memstat_state |= P_MEMSTAT_INTERNAL;
    } else {
        memstat_state &= ~P_MEMSTAT_INTERNAL;
    }
    _assert(set_proc_memstat_state(proc, memstat_state));
    ret = true;
out:;
    return ret;
}

bool get_proc_memstat_internal(kptr_t proc) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(proc));
    uint32_t const p_memstat_state = get_proc_memstat_state(proc);
    ret = (p_memstat_state & P_MEMSTAT_INTERNAL);
out:;
    return ret;
}

size_t kstrlen(kptr_t ptr) {
    size_t size = 0;
    _assert(KERN_POINTER_VALID(ptr));
    kptr_t const function = getoffset(strlen);
    _assert(KERN_POINTER_VALID(function));
    size = (size_t)kexec(function, ptr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return size;
}

kptr_t sstrdup(const char *str) {
    kptr_t ret = KPTR_NULL;
    kptr_t kstr = KPTR_NULL;
    size_t kstr_size = 0;
    _assert(str != NULL);
    kptr_t const function = getoffset(sstrdup);
    _assert(KERN_POINTER_VALID(function));
    kstr_size = strlen(str) + 1;
    kstr = IOMalloc(kstr_size);
    _assert(KERN_POINTER_VALID(kstr));
    _assert(wkbuffer(kstr, (void *)str, kstr_size));
    ret = kexec(function, kstr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    SafeIOFreeNULL(kstr, kstr_size);
    return ret;
}

kptr_t smalloc(size_t size) {
    kptr_t ret = KPTR_NULL;
    kptr_t const function = getoffset(smalloc);
    _assert(KERN_POINTER_VALID(function));
    ret = kexec(function, (kptr_t)size, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    return ret;
}

void sfree(kptr_t ptr) {
    _assert(KERN_POINTER_VALID(ptr));
    kptr_t const function = getoffset(sfree);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, ptr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}


kptr_t IOMalloc(vm_size_t size) {
    kptr_t ret = KPTR_NULL;
    kptr_t const function = getoffset(IOMalloc);
    _assert(KERN_POINTER_VALID(function));
    ret = kexec(function, (kptr_t)size, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    return ret;
}

void IOFree(kptr_t address, vm_size_t size) {
    _assert(KERN_POINTER_VALID(address));
    _assert(size > 0);
    kptr_t const function = getoffset(IOFree);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, address, (kptr_t)size, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

int extension_create_file(kptr_t saveto, kptr_t sb, const char *path, size_t path_len, uint32_t subtype) {
    int ret = -1;
    kptr_t kstr = KPTR_NULL;
    _assert(KERN_POINTER_VALID(saveto));
    _assert(KERN_POINTER_VALID(sb));
    _assert(path != NULL);
    _assert(path_len > 0);
    kptr_t const function = getoffset(extension_create_file);
    _assert(KERN_POINTER_VALID(function));
    kstr = sstrdup(path);
    _assert(KERN_POINTER_VALID(kstr));
    ret = (int)kexec(function, saveto, sb, kstr, (kptr_t)path_len, (kptr_t)subtype, KPTR_NULL, KPTR_NULL);
out:;
    SafeSFreeNULL(kstr);
    return ret;
}

int extension_create_mach(kptr_t saveto, kptr_t sb, const char *name, uint32_t subtype) {
    int ret = -1;
    kptr_t kstr = KPTR_NULL;
    kptr_t const function = getoffset(extension_create_mach);
    _assert(KERN_POINTER_VALID(function));
    kstr = KPTR_NULL;
    _assert(KERN_POINTER_VALID(saveto));
    _assert(KERN_POINTER_VALID(sb));
    _assert(name != NULL);
    kstr = sstrdup(name);
    _assert(KERN_POINTER_VALID(kstr));
    ret = (int)kexec(function, saveto, sb, kstr, (kptr_t)subtype, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    SafeSFreeNULL(kstr);
    return ret;
}

int extension_add(kptr_t ext, kptr_t sb, const char *desc) {
    int ret = -1;
    kptr_t kstr = KPTR_NULL;
    _assert(KERN_POINTER_VALID(ext));
    _assert(KERN_POINTER_VALID(sb));
    _assert(desc != NULL);
    kptr_t const function = getoffset(extension_add);
    _assert(KERN_POINTER_VALID(function));
    kstr = sstrdup(desc);
    _assert(KERN_POINTER_VALID(kstr));
    ret = (int)kexec(function, ext, sb, kstr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    SafeSFreeNULL(kstr);
    return ret;
}

void extension_release(kptr_t ext) {
    _assert(KERN_POINTER_VALID(ext));
    kptr_t const function = getoffset(extension_release);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, ext, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void extension_destroy(kptr_t ext) {
    _assert(KERN_POINTER_VALID(ext));
    kptr_t const function = getoffset(extension_destroy);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, ext, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

bool set_file_extension(kptr_t sandbox, const char *exc_key, const char *path) {
    bool ret = false;
    kptr_t ext_kptr = KPTR_NULL;
    kptr_t ext = KPTR_NULL;
    _assert(KERN_POINTER_VALID(sandbox));
    _assert(exc_key != NULL);
    _assert(path != NULL);
    ext_kptr = smalloc(sizeof(kptr_t));
    _assert(KERN_POINTER_VALID(ext_kptr));
    _assert(extension_create_file(ext_kptr, sandbox, path, strlen(path), 0) == 0);
    ext = ReadKernel64(ext_kptr);
    _assert(KERN_POINTER_VALID(ext));
    _assert(extension_add(ext, sandbox, exc_key) == 0);
    ret = true;
out:;
    if (KERN_POINTER_VALID(ext_kptr) && (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0 || ext == KPTR_NULL)) extension_release(ext_kptr);
    ext_kptr = KPTR_NULL;
    ext = KPTR_NULL;
    return ret;
}

bool set_mach_extension(kptr_t sandbox, const char *exc_key, const char *name) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(sandbox));
    _assert(exc_key != NULL);
    _assert(name != NULL);
    _assert(issue_extension_for_mach_service(sandbox, KPTR_NULL, name, (void *)exc_key) == 0);
    ret = true;
out:;
    return ret;
}

kptr_t proc_find(pid_t pid) {
    kptr_t ret = KPTR_NULL;
    kptr_t const function = getoffset(proc_find);
    _assert(KERN_POINTER_VALID(function));
    ret = kexec(function, (kptr_t)pid, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    return ret;
}

void proc_rele(kptr_t proc) {
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const function = getoffset(proc_rele);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void proc_lock(kptr_t proc) {
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const function = getoffset(proc_lock);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void proc_unlock(kptr_t proc) {
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const function = getoffset(proc_unlock);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void proc_ucred_lock(kptr_t proc) {
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const function = getoffset(proc_ucred_lock);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void proc_ucred_unlock(kptr_t proc) {
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const function = getoffset(proc_ucred_unlock);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void vnode_lock(kptr_t vp) {
    _assert(KERN_POINTER_VALID(vp));
    kptr_t const function = getoffset(vnode_lock);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, vp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void vnode_unlock(kptr_t vp) {
    _assert(KERN_POINTER_VALID(vp));
    kptr_t const function = getoffset(vnode_unlock);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, vp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void mount_lock(kptr_t mp) {
    _assert(KERN_POINTER_VALID(mp));
    kptr_t const function = getoffset(mount_lock);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, mp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void mount_unlock(kptr_t mp) {
    _assert(KERN_POINTER_VALID(mp));
    kptr_t const function = getoffset(mount_unlock);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, mp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void task_set_platform_binary(kptr_t task, boolean_t is_platform) {
    _assert(KERN_POINTER_VALID(task));
    kptr_t const function = getoffset(task_set_platform_binary);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, task, (kptr_t)is_platform, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

int chgproccnt(uid_t uid, int diff) {
    int ret = -1;
    kptr_t const function = getoffset(chgproccnt);
    _assert(KERN_POINTER_VALID(function));
    ret = (int)kexec(function, (kptr_t)uid, (kptr_t)diff, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

void kauth_cred_ref(kptr_t cred) {
    _assert(KERN_POINTER_VALID(cred));
    kptr_t const function = getoffset(kauth_cred_ref);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, cred, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void kauth_cred_unref(kptr_t cred) {
    _assert(KERN_POINTER_VALID(cred));
    kptr_t const function = getoffset(kauth_cred_unref);
    _assert(KERN_POINTER_VALID(function));
    kexec(function, cred, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

kptr_t vfs_context_current() {
    kptr_t ret = KPTR_NULL;
    kptr_t const function = getoffset(vfs_context_current);
    _assert(KERN_POINTER_VALID(function));
    ret = kexec(function, (kptr_t)1, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    return ret;
}

int vnode_lookup(const char *path, int flags, kptr_t *vpp, kptr_t ctx) {
    int ret = -1;
    kptr_t kstr = KPTR_NULL;
    size_t vpp_kptr_size = 0;
    kptr_t vpp_kptr = KPTR_NULL;
    _assert(path != NULL);
    _assert(vpp != NULL);
    _assert(KERN_POINTER_VALID(ctx));
    kptr_t const function = getoffset(vnode_lookup);
    _assert(KERN_POINTER_VALID(function));
    kstr = sstrdup(path);
    _assert(KERN_POINTER_VALID(kstr));
    vpp_kptr_size = sizeof(kptr_t);
    vpp_kptr = smalloc(vpp_kptr_size);
    _assert(KERN_POINTER_VALID(vpp_kptr));
    ret = (int)kexec(function, kstr, (kptr_t)flags, vpp_kptr, ctx, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    _assert(rkbuffer(vpp_kptr, vpp, vpp_kptr_size));
out:;
    SafeSFreeNULL(kstr);
    SafeSFreeNULL(vpp_kptr);
    return ret;
}

int vnode_getfromfd(kptr_t ctx, int fd, kptr_t *vpp) {
    int ret = -1;
    size_t vpp_kptr_size = 0;
    kptr_t vpp_kptr = KPTR_NULL;
    _assert(KERN_POINTER_VALID(ctx));
    _assert(fd > 0);
    _assert(vpp != NULL);
    kptr_t const function = getoffset(vnode_getfromfd);
    _assert(KERN_POINTER_VALID(function));
    vpp_kptr_size = sizeof(kptr_t);
    vpp_kptr = smalloc(vpp_kptr_size);
    _assert(KERN_POINTER_VALID(vpp_kptr));
    ret = (int)kexec(function, ctx, (kptr_t)fd, vpp_kptr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    _assert(rkbuffer(vpp_kptr, vpp, vpp_kptr_size));
out:;
    SafeSFreeNULL(vpp_kptr);
    return ret;
}

int vn_getpath(kptr_t vp, char *pathbuf, int *len) {
    int ret = -1;
    size_t pathbuf_kptr_size = 0;
    kptr_t pathbuf_kptr = KPTR_NULL;
    size_t len_kptr_size = 0;
    kptr_t len_kptr = KPTR_NULL;
    _assert(KERN_POINTER_VALID(vp));
    _assert(pathbuf != NULL);
    _assert(len != NULL);
    kptr_t const function = getoffset(vn_getpath);
    _assert(KERN_POINTER_VALID(function));
    pathbuf_kptr_size = *len;
    pathbuf_kptr = smalloc(pathbuf_kptr_size);
    _assert(KERN_POINTER_VALID(pathbuf_kptr));
    len_kptr_size = sizeof(*len);
    len_kptr = smalloc(len_kptr_size);
    _assert(KERN_POINTER_VALID(len_kptr));
    _assert(wkbuffer(len_kptr, len, len_kptr_size));
    ret = (int)kexec(function, vp, pathbuf_kptr, len_kptr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    _assert(rkbuffer(pathbuf_kptr, pathbuf, pathbuf_kptr_size));
    _assert(rkbuffer(len_kptr, len, len_kptr_size));
out:;
    SafeSFreeNULL(pathbuf_kptr);
    SafeSFreeNULL(len_kptr);
    return ret;
}

int vnode_put(kptr_t vp) {
    int ret = -1;
    _assert(KERN_POINTER_VALID(vp));
    kptr_t const function = getoffset(vnode_put);
    _assert(KERN_POINTER_VALID(function));
    ret = (int)kexec(function, vp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

bool OSDictionary_SetItem(kptr_t OSDictionary, const char *key, kptr_t val) {
    bool ret = false;
    kptr_t kstr = KPTR_NULL;
    _assert(KERN_POINTER_VALID(OSDictionary));
    _assert(key != NULL);
    _assert(KERN_POINTER_VALID(val));
    kptr_t const function = OSObjectFunc(OSDictionary, koffset(KVTABLE_OFFSET_OSDICTIONARY_SETOBJECTWITHCHARP));
    _assert(KERN_POINTER_VALID(function));
    kstr = sstrdup(key);
    _assert(KERN_POINTER_VALID(kstr));
    ret = (bool)kexec(function, OSDictionary, kstr, val, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    SafeSFreeNULL(kstr);
    return ret;
}

kptr_t OSDictionary_GetItem(kptr_t OSDictionary, const char *key) {
    kptr_t ret = KPTR_NULL;
    kptr_t kstr = KPTR_NULL;
    _assert(KERN_POINTER_VALID(OSDictionary));
    kptr_t const function = OSObjectFunc(OSDictionary, koffset(KVTABLE_OFFSET_OSDICTIONARY_GETOBJECTWITHCHARP));
    _assert(KERN_POINTER_VALID(function));
    kstr = sstrdup(key);
    _assert(KERN_POINTER_VALID(kstr));
    ret = kexec(function, OSDictionary, kstr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL && (ret>>32) == KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    SafeSFreeNULL(kstr);
    return ret;
}

bool OSDictionary_Merge(kptr_t OSDictionary, kptr_t OSDictionary2) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(OSDictionary));
    _assert(KERN_POINTER_VALID(OSDictionary2));
    kptr_t const function = OSObjectFunc(OSDictionary, koffset(KVTABLE_OFFSET_OSDICTIONARY_MERGE));
    _assert(KERN_POINTER_VALID(function));
    ret = (bool)kexec(function, OSDictionary, OSDictionary2, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

uint32_t OSDictionary_ItemCount(kptr_t OSDictionary) {
    uint32_t ret = 0;
    _assert(KERN_POINTER_VALID(OSDictionary));
    ret = ReadKernel32(OSDictionary + 20);
out:;
    return ret;
}

kptr_t OSDictionary_ItemBuffer(kptr_t OSDictionary) {
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(OSDictionary));
    ret = ReadKernel64(OSDictionary + 32);
out:;
    return ret;
}

kptr_t OSDictionary_ItemKey(kptr_t buffer, uint32_t idx) {
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(buffer));
    ret = ReadKernel64(buffer + 16 * idx);
out:;
    return ret;
}

kptr_t OSDictionary_ItemValue(kptr_t buffer, uint32_t idx) {
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(buffer));
    ret = ReadKernel64(buffer + 16 * idx + 8);
out:;
    return ret;
}

bool OSArray_Merge(kptr_t OSArray, kptr_t OSArray2) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(OSArray));
    _assert(KERN_POINTER_VALID(OSArray2));
    kptr_t const function = OSObjectFunc(OSArray, koffset(KVTABLE_OFFSET_OSARRAY_MERGE));
    _assert(KERN_POINTER_VALID(function));
    ret = (bool)kexec(function, OSArray, OSArray2, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

kptr_t OSArray_GetObject(kptr_t OSArray, uint32_t idx) {
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(OSArray));
    kptr_t const function = OSObjectFunc(OSArray, koffset(KVTABLE_OFFSET_OSARRAY_GETOBJECT));
    _assert(KERN_POINTER_VALID(function));
    ret = kexec(OSArray, idx, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
    _assert(KERN_POINTER_VALID(ret));
out:;
    return ret;
}

void OSArray_RemoveObject(kptr_t OSArray, uint32_t idx) {
    _assert(KERN_POINTER_VALID(OSArray));
    kptr_t const function = OSObjectFunc(OSArray, koffset(KVTABLE_OFFSET_OSARRAY_REMOVEOBJECT));
    _assert(KERN_POINTER_VALID(function));
    kexec(function, OSArray, idx, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

uint32_t OSArray_ItemCount(kptr_t OSArray) {
    uint32_t ret = 0;
    _assert(KERN_POINTER_VALID(OSArray));
    ret = ReadKernel32(OSArray + 0x14);
out:;
    return ret;
}

kptr_t OSArray_ItemBuffer(kptr_t OSArray) {
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(OSArray));
    ret = ReadKernel64(OSArray + 32);
out:;
    return ret;
}

kptr_t OSObjectFunc(kptr_t OSObject, uint32_t off) {
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(OSObject));
    kptr_t vtable = ReadKernel64(OSObject);
    if (vtable != KPTR_NULL) vtable = kernel_xpacd(vtable);
    _assert(KERN_POINTER_VALID(vtable));
    ret = ReadKernel64(vtable + (sizeof(kptr_t) * off));
    if (ret != KPTR_NULL) ret = kernel_xpaci(ret);
    _assert(KERN_POINTER_VALID(ret));
out:;
    return ret;
}

void OSObject_Release(kptr_t OSObject) {
    _assert(KERN_POINTER_VALID(OSObject));
    kptr_t const function = OSObjectFunc(OSObject, koffset(KVTABLE_OFFSET_OSOBJECT_RELEASE));
    _assert(KERN_POINTER_VALID(function));
    kexec(function, OSObject, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void OSObject_Retain(kptr_t OSObject) {
    _assert(KERN_POINTER_VALID(OSObject));
    kptr_t const function = OSObjectFunc(OSObject, koffset(KVTABLE_OFFSET_OSOBJECT_RETAIN));
    _assert(KERN_POINTER_VALID(function));
    kexec(function, OSObject, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

uint32_t OSObject_GetRetainCount(kptr_t OSObject) {
    uint32_t ret = 0;
    _assert(KERN_POINTER_VALID(OSObject));
    kptr_t const function = OSObjectFunc(OSObject, koffset(KVTABLE_OFFSET_OSOBJECT_GETRETAINCOUNT));
    _assert(KERN_POINTER_VALID(function));
    ret = (uint32_t)kexec(function, OSObject, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

uint32_t OSString_GetLength(kptr_t OSString) {
    uint32_t ret = 0;
    _assert(KERN_POINTER_VALID(OSString));
    kptr_t const function = OSObjectFunc(OSString, koffset(KVTABLE_OFFSET_OSSTRING_GETLENGTH));
    _assert(KERN_POINTER_VALID(function));
    ret = (uint32_t)kexec(function, OSString, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

kptr_t OSString_CStringPtr(kptr_t OSString) {
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(OSString));
    ret = ReadKernel64(OSString + 0x10);
out:;
    return ret;
}

char *OSString_CopyString(kptr_t OSString) {
    char *ret = NULL;
    char *str = NULL;
    _assert(KERN_POINTER_VALID(OSString));
    uint32_t const length = OSString_GetLength(OSString);
    _assert(length > 0);
    str = malloc(length + 1);
    _assert(str != NULL);
    str[length] = 0;
    kptr_t const CStringPtr = OSString_CStringPtr(OSString);
    _assert(KERN_POINTER_VALID(CStringPtr));
    _assert(rkbuffer(CStringPtr, str, length));
    ret = strdup(str);
    _assert(ret != NULL);
out:;
    SafeFreeNULL(str);
    return ret;
}

kptr_t OSUnserializeXML(const char *buffer) {
    kptr_t ret = KPTR_NULL;
    kptr_t kstr = KPTR_NULL;
    _assert(buffer != NULL);
    kptr_t const function = getoffset(osunserializexml);
    _assert(KERN_POINTER_VALID(function));
    kstr = sstrdup(buffer);
    _assert(KERN_POINTER_VALID(kstr));
    kptr_t const error_kptr = KPTR_NULL;
    ret = kexec(function, kstr, error_kptr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
    _assert(KERN_POINTER_VALID(ret));
out:;
    SafeSFreeNULL(kstr);
    return ret;
}

kptr_t get_exception_osarray(const char **exceptions, bool is_file_extension) {
    kptr_t exception_osarray = KPTR_NULL;
    size_t xmlsize = 0x1000;
    size_t len = 0;
    size_t written = 0;
    char *ents = malloc(xmlsize);
    if (ents == NULL) return KPTR_NULL;
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
        written = sprintf(ents + xmlused, "<string>%s%s</string>", *exception, is_file_extension ? "/" : "");
        if (written < 0) {
            SafeFreeNULL(ents);
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
    SafeFreeNULL(ents);
    return exception_osarray;
}

char **copy_amfi_entitlements(kptr_t present) {
    uint32_t itemCount = OSArray_ItemCount(present);
    kptr_t itemBuffer = OSArray_ItemBuffer(present);
    size_t bufferSize = 0x1000;
    size_t bufferUsed = 0;
    size_t arraySize = (itemCount + 1) * sizeof(char *);
    char **entitlements = malloc(arraySize + bufferSize);
    if (entitlements == NULL) return NULL;
    entitlements[itemCount] = NULL;
    
    for (int i = 0; i < itemCount; i++) {
        kptr_t item = ReadKernel64(itemBuffer + (i * sizeof(kptr_t)));
        char *entitlementString = OSString_CopyString(item);
        if (!entitlementString) {
            SafeFreeNULL(entitlements);
            return NULL;
        }
        size_t len = strlen(entitlementString) + 1;
        while (bufferUsed + len > bufferSize) {
            bufferSize += 0x1000;
            entitlements = realloc(entitlements, arraySize + bufferSize);
            if (!entitlements) {
                SafeFreeNULL(entitlementString);
                return NULL;
            }
        }
        entitlements[i] = (char*)entitlements + arraySize + bufferUsed;
        strcpy(entitlements[i], entitlementString);
        bufferUsed += len;
        SafeFreeNULL(entitlementString);
    }
    return entitlements;
}

kptr_t getOSBool(bool value) {
    kptr_t ret = KPTR_NULL;
    if (weird_offsets) {
        if (value) {
            ret = getoffset(OSBoolean_True);
        } else {
            ret = getoffset(OSBoolean_False);
        }
        goto out;
    }
    kptr_t const symbol = getoffset(OSBoolean_True);
    _assert(KERN_POINTER_VALID(symbol));
    kptr_t OSBool = ReadKernel64(symbol);
    _assert(KERN_POINTER_VALID(OSBool));
    if (!value) OSBool += sizeof(kptr_t);
    ret = OSBool;
out:;
    return ret;
}

bool entitle_process(kptr_t amfi_entitlements, const char *key, kptr_t val) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(amfi_entitlements));
    _assert(key != NULL);
    _assert(KERN_POINTER_VALID(val));
    _assert((ret = OSDictionary_SetItem(amfi_entitlements, key, val)));
out:;
    return ret;
}

bool set_sandbox_exceptions(kptr_t sandbox) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(sandbox));
    for (const char **exception = file_read_exceptions; *exception; exception++) {
        _assert(set_file_extension(sandbox, FILE_READ_EXC_KEY, *exception));
    }
    for (const char **exception = file_read_write_exceptions; *exception; exception++) {
        _assert(set_file_extension(sandbox, FILE_READ_WRITE_EXC_KEY, *exception));
    }
    for (const char **exception = mach_lookup_exceptions; *exception; exception++) {
        _assert(set_mach_extension(sandbox, MACH_LOOKUP_EXC_KEY, *exception));
    }
    for (const char **exception = mach_register_exceptions; *exception; exception++) {
        _assert(set_mach_extension(sandbox, MACH_REGISTER_EXC_KEY, *exception));
    }
    ret = true;
out:;
    return ret;
}

bool check_for_exception(char **current_exceptions, const char *exception) {
    bool ret = false;
    _assert(current_exceptions != NULL);
    _assert(exception != NULL);
    for (char **entitlement_string = current_exceptions; *entitlement_string && !ret; entitlement_string++) {
        char *ent = strdup(*entitlement_string);
        _assert(ent != NULL);
        size_t lastchar = strlen(ent) - 1;
        if (ent[lastchar] == '/') ent[lastchar] = '\0';
        if (strcmp(ent, exception) == 0) {
            ret = true;
        }
        SafeFreeNULL(ent);
    }
out:;
    return ret;
}

bool set_amfi_exceptions(kptr_t amfi_entitlements, const char *exc_key, const char **exceptions, bool is_file_extension) {
    bool ret = false;
    char **current_exceptions = NULL;
    _assert(KERN_POINTER_VALID(amfi_entitlements));
    _assert(exceptions != NULL);
    kptr_t const present_exception_osarray = OSDictionary_GetItem(amfi_entitlements, exc_key);
    if (present_exception_osarray == KPTR_NULL) {
        kptr_t osarray = get_exception_osarray(exceptions, is_file_extension);
        _assert(KERN_POINTER_VALID(osarray));
        ret = OSDictionary_SetItem(amfi_entitlements, exc_key, osarray);
        OSObject_Release(osarray);
        goto out;
    }
    current_exceptions = copy_amfi_entitlements(present_exception_osarray);
    _assert(current_exceptions != NULL);
    for (const char **exception = exceptions; *exception; exception++) {
        if (check_for_exception(current_exceptions, *exception)) {
            ret = true;
            continue;
        }
        const char *array[] = {*exception, NULL};
        kptr_t const osarray = get_exception_osarray(array, is_file_extension);
        if (!KERN_POINTER_VALID(osarray)) continue;
        ret = OSArray_Merge(present_exception_osarray, osarray);
        OSObject_Release(osarray);
    }
out:;
    SafeFreeNULL(current_exceptions);
    return ret;
}

bool set_exceptions(kptr_t sandbox, kptr_t amfi_entitlements) {
    bool ret = false;
    if (KERN_POINTER_VALID(sandbox)) {
        _assert(set_sandbox_exceptions(sandbox));
        if (KERN_POINTER_VALID(amfi_entitlements)) {
            _assert(set_amfi_exceptions(amfi_entitlements, FILE_READ_EXC_KEY, file_read_exceptions, true));
            _assert(set_amfi_exceptions(amfi_entitlements, FILE_READ_WRITE_EXC_KEY, file_read_write_exceptions, true));
            _assert(set_amfi_exceptions(amfi_entitlements, MACH_LOOKUP_EXC_KEY, mach_lookup_exceptions, false));
            _assert(set_amfi_exceptions(amfi_entitlements, MACH_REGISTER_EXC_KEY, mach_register_exceptions, false));
        }
    }
    ret = true;
out:;
    return ret;
}

kptr_t get_amfi_entitlements(kptr_t cr_label) {
    kptr_t amfi_entitlements = KPTR_NULL;
    _assert(KERN_POINTER_VALID(cr_label));
    amfi_entitlements = ReadKernel64(cr_label + 0x8);
out:;
    return amfi_entitlements;
}

kptr_t get_sandbox(kptr_t cr_label) {
    kptr_t sandbox = KPTR_NULL;
    _assert(KERN_POINTER_VALID(cr_label));
    sandbox = ReadKernel64(cr_label + 0x8 + 0x8);
out:;
    return sandbox;
}

bool entitle_process_with_pid(pid_t pid, const char *key, kptr_t val) {
    bool ret = false;
    kptr_t proc = KPTR_NULL;
    _assert(pid > 0);
    _assert(key != NULL);
    _assert(KERN_POINTER_VALID(val));
    proc = proc_find(pid);
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    _assert(KERN_POINTER_VALID(proc_ucred));
    kptr_t const cr_label = ReadKernel64(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
    _assert(KERN_POINTER_VALID(cr_label));
    kptr_t const amfi_entitlements = get_amfi_entitlements(cr_label);
    _assert(KERN_POINTER_VALID(amfi_entitlements));
    _assert(entitle_process(amfi_entitlements, key, val));
    ret = true;
out:;
    if (KERN_POINTER_VALID(proc)) proc_rele(proc);
    return ret;
}

bool remove_memory_limit() {
    kptr_t ret = false;
    size_t kstr_size = 0;
    kptr_t kstr = KPTR_NULL;
    pid_t const pid = getpid();
    char *const entitlement_key = "com.apple.private.memorystatus";
    kptr_t const entitlement_val = OSBoolTrue;
    _assert(KERN_POINTER_VALID(entitlement_val));
    kptr_t const proc = get_proc_struct_for_pid(pid);
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    _assert(KERN_POINTER_VALID(proc_ucred));
    kptr_t const cr_label = ReadKernel64(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
    _assert(KERN_POINTER_VALID(cr_label));
    kptr_t const amfi_entitlements = get_amfi_entitlements(cr_label);
    _assert(KERN_POINTER_VALID(amfi_entitlements));
    kptr_t function = OSObjectFunc(amfi_entitlements, koffset(KVTABLE_OFFSET_OSDICTIONARY_SETOBJECTWITHCHARP));
    _assert(KERN_POINTER_VALID(function));
    kstr_size = strlen(entitlement_key) + 1;
    kstr = kmem_alloc(kstr_size);
    _assert(KERN_POINTER_VALID(kstr));
    _assert(kexec(function, amfi_entitlements, kstr, entitlement_val, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL));
    _assert(memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, pid, 0, NULL, 0) == 0);
    ret = true;
out:;
    if (kstr_size != 0 && KERN_POINTER_VALID(kstr)) kmem_free(kstr, kstr_size); kstr = KPTR_NULL;
    return ret;
}

bool restore_kernel_task_port(task_t *out_kernel_task_port) {
    bool restored_kernel_task_port = false;
    kern_return_t kr = KERN_FAILURE;
    task_t *kernel_task_port = NULL;
    host_t host = HOST_NULL;
    _assert(out_kernel_task_port != NULL);
    kernel_task_port = malloc(sizeof(task_t *));
    _assert(kernel_task_port != NULL);
    bzero(kernel_task_port, sizeof(task_t));
    host = mach_host_self();
    _assert(MACH_PORT_VALID(host));
    kr = task_for_pid(mach_task_self(), 0, kernel_task_port);
    if (kr != KERN_SUCCESS) kr = host_get_special_port(host, HOST_LOCAL_NODE, 4, kernel_task_port);
    _assert(kr == KERN_SUCCESS);
    _assert(MACH_PORT_VALID(*kernel_task_port));
    *out_kernel_task_port = *kernel_task_port;
    restored_kernel_task_port = true;
out:;
    SafeFreeNULL(kernel_task_port);
    if (MACH_PORT_VALID(host)) mach_port_deallocate(mach_task_self(), host); host = HOST_NULL;
    return restored_kernel_task_port;
}

bool restore_kernel_base(uint64_t *out_kernel_base, uint64_t *out_kernel_slide) {
    bool restored_kernel_base = false;
    kern_return_t kr = KERN_FAILURE;
    kptr_t *kernel_task_base = NULL;
    uint64_t *kernel_task_slide = NULL;
    struct task_dyld_info *task_dyld_info = NULL;
    mach_msg_type_number_t *task_dyld_info_count = NULL;
    _assert(out_kernel_base != NULL);
    _assert(out_kernel_slide != NULL);
    kernel_task_base = malloc(sizeof(kptr_t));
    _assert(kernel_task_base != NULL);
    bzero(kernel_task_base, sizeof(kptr_t));
    kernel_task_slide = malloc(sizeof(uint64_t));
    _assert(kernel_task_slide != NULL);
    bzero(kernel_task_slide, sizeof(uint64_t));
    task_dyld_info = malloc(sizeof(struct task_dyld_info));
    _assert(task_dyld_info != NULL);
    bzero(task_dyld_info, sizeof(struct task_dyld_info));
    task_dyld_info_count = malloc(sizeof(mach_msg_type_number_t));
    _assert(task_dyld_info_count != NULL);
    bzero(task_dyld_info_count, sizeof(mach_msg_type_number_t));
    *task_dyld_info_count = TASK_DYLD_INFO_COUNT;
    kr = task_info(tfp0, TASK_DYLD_INFO, (task_info_t)task_dyld_info, task_dyld_info_count);
    _assert(kr == KERN_SUCCESS);
    *kernel_task_slide = task_dyld_info->all_image_info_size;
    *kernel_task_base = *kernel_task_slide + STATIC_KERNEL_BASE_ADDRESS;
    *out_kernel_base = *kernel_task_base;
    *out_kernel_slide = *kernel_task_slide;
    restored_kernel_base = true;
out:;
    SafeFreeNULL(kernel_task_base);
    SafeFreeNULL(kernel_task_slide);
    SafeFreeNULL(task_dyld_info);
    SafeFreeNULL(task_dyld_info_count);
    return restored_kernel_base;
}

bool restore_kernel_offset_cache() {
    bool restored_kernel_offset_cache = false;
    kern_return_t kr = KERN_FAILURE;
    struct task_dyld_info *task_dyld_info = NULL;
    mach_msg_type_number_t *task_dyld_info_count = NULL;
    kptr_t offset_cache_addr = KPTR_NULL;
    kptr_t offset_cache_size_addr = KPTR_NULL;
    size_t *offset_cache_size = NULL;
    struct cache_blob *offset_cache_blob = NULL;
    task_dyld_info = malloc(sizeof(struct task_dyld_info));
    _assert(task_dyld_info != NULL);
    bzero(task_dyld_info, sizeof(struct task_dyld_info));
    task_dyld_info_count = malloc(sizeof(mach_msg_type_number_t));
    _assert(task_dyld_info_count != NULL);
    bzero(task_dyld_info_count, sizeof(mach_msg_type_number_t));
    offset_cache_size = malloc(sizeof(size_t));
    _assert(offset_cache_size != NULL);
    bzero(offset_cache_size, sizeof(size_t));
    *task_dyld_info_count = TASK_DYLD_INFO_COUNT;
    kr = task_info(tfp0, TASK_DYLD_INFO, (task_info_t)task_dyld_info, task_dyld_info_count);
    _assert(kr == KERN_SUCCESS);
    _assert(KERN_POINTER_VALID(task_dyld_info->all_image_info_addr));
    offset_cache_addr = task_dyld_info->all_image_info_addr;
    _assert(offset_cache_addr != kernel_base);
    offset_cache_size_addr = offset_cache_addr + offsetof(struct cache_blob, size);
    _assert(rkbuffer(offset_cache_size_addr, offset_cache_size, sizeof(*offset_cache_size)));
    offset_cache_blob = create_cache_blob(*offset_cache_size);
    _assert(offset_cache_blob != NULL);
    _assert(rkbuffer(offset_cache_addr, offset_cache_blob, *offset_cache_size));
    import_cache_blob(offset_cache_blob);
    found_offsets = true;
    restored_kernel_offset_cache = true;
out:;
    SafeFreeNULL(task_dyld_info);
    SafeFreeNULL(task_dyld_info_count);
    SafeFreeNULL(offset_cache_size);
    SafeFreeNULL(offset_cache_blob);
    return restored_kernel_offset_cache;
}

bool restore_file_offset_cache(const char *offset_cache_file_path, kptr_t *out_kernel_base, uint64_t *out_kernel_slide) {
    bool restored_file_offset_cache = false;
    CFStringRef offset_cache_file_name = NULL;
    CFURLRef offset_cache_file_url = NULL;
    CFDataRef offset_cache_file_data = NULL;
    CFPropertyListRef offset_cache_property_list = NULL;
    Boolean status = false;
    kptr_t offset_kernel_base = KPTR_NULL;
    kptr_t offset_kernel_slide = KPTR_NULL;
    _assert(offset_cache_file_path != NULL);
    _assert(out_kernel_base != NULL);
    _assert(out_kernel_slide != NULL);
    offset_cache_file_name = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, offset_cache_file_path, kCFStringEncodingUTF8, kCFAllocatorDefault);
    _assert(offset_cache_file_name != NULL);
    offset_cache_file_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, offset_cache_file_name, kCFURLPOSIXPathStyle, false);
    _assert(offset_cache_file_url != NULL);
    status = CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, offset_cache_file_url, &offset_cache_file_data, NULL, NULL, NULL);
    _assert(status);
    offset_cache_property_list = CFPropertyListCreateWithData(kCFAllocatorDefault, offset_cache_file_data, kCFPropertyListImmutable, NULL, NULL);
    _assert(offset_cache_property_list);
    _assert(CFGetTypeID(offset_cache_property_list) == CFDictionaryGetTypeID());
#define restore_offset(entry_name, out_offset) do { \
    const void *value = CFDictionaryGetValue(offset_cache_property_list, CFSTR(entry_name)); \
    if (value == NULL) break; \
    const char *string = CFStringGetCStringPtr((CFStringRef)value, kCFStringEncodingUTF8); \
    if (string == NULL) break; \
    uint64_t offset = strtoull(string, NULL, 16); \
    if (!KERN_POINTER_VALID(offset)) break; \
    out_offset = offset; \
} while (false)
#define restore_and_set_offset(entry_name, offset_name) do { \
    kptr_t restored_offset = KPTR_NULL; \
    restore_offset(entry_name, restored_offset); \
    set_offset(offset_name, restored_offset); \
} while (false)
    restore_offset("KernelBase", offset_kernel_base);
    restore_offset("KernelSlide", offset_kernel_slide);
    restore_and_set_offset("TrustChain", "trustcache");
    restore_and_set_offset("OSBooleanTrue", "OSBoolean_True");
    restore_and_set_offset("OSBooleanFalse", "OSBoolean_False");
    restore_and_set_offset("OSUnserializeXML", "osunserializexml");
    restore_and_set_offset("Smalloc", "smalloc");
    restore_and_set_offset("AddRetGadget", "add_x0_x0_0x40_ret");
    restore_and_set_offset("ZoneMapOffset", "zone_map_ref");
    restore_and_set_offset("VfsContextCurrent", "vfs_context_current");
    restore_and_set_offset("VnodeLookup", "vnode_lookup");
    restore_and_set_offset("VnodePut", "vnode_put");
    restore_and_set_offset("KernelTask", "kernel_task");
    restore_and_set_offset("KernProc", "kernproc");
    restore_and_set_offset("Shenanigans", "shenanigans");
    restore_and_set_offset("LckMtxLock", "lck_mtx_lock");
    restore_and_set_offset("LckMtxUnlock", "lck_mtx_unlock");
    restore_and_set_offset("VnodeGetSnapshot", "vnode_get_snapshot");
    restore_and_set_offset("FsLookupSnapshotMetadataByNameAndReturnName", "fs_lookup_snapshot_metadata_by_name_and_return_name");
    restore_and_set_offset("PmapLoadTrustCache", "pmap_load_trust_cache");
    restore_and_set_offset("APFSJhashGetVnode", "apfs_jhash_getvnode");
    restore_and_set_offset("PacizaPointerL2TPDomainModuleStart", "paciza_pointer__l2tp_domain_module_start");
    restore_and_set_offset("PacizaPointerL2TPDomainModuleStop", "paciza_pointer__l2tp_domain_module_stop");
    restore_and_set_offset("L2TPDomainInited", "l2tp_domain_inited");
    restore_and_set_offset("SysctlNetPPPL2TP", "sysctl__net_ppp_l2tp");
    restore_and_set_offset("SysctlUnregisterOid", "sysctl_unregister_oid");
    restore_and_set_offset("MovX0X4BrX5", "mov_x0_x4__br_x5");
    restore_and_set_offset("MovX9X0BrX1", "mov_x9_x0__br_x1");
    restore_and_set_offset("MovX10X3BrX6", "mov_x10_x3__br_x6");
    restore_and_set_offset("KernelForgePaciaGadget", "kernel_forge_pacia_gadget");
    restore_and_set_offset("KernelForgePacdaGadget", "kernel_forge_pacda_gadget");
    restore_and_set_offset("IOUserClientVtable", "IOUserClient__vtable");
    restore_and_set_offset("IORegistryEntryGetRegistryEntryID", "IORegistryEntry__getRegistryEntryID");
    restore_and_set_offset("ProcFind", "proc_find");
    restore_and_set_offset("ProcRele", "proc_rele");
    restore_and_set_offset("ExtensionCreateFile", "extension_create_file");
    restore_and_set_offset("ExtensionAdd", "extension_add");
    restore_and_set_offset("ExtensionRelease", "extension_release");
    restore_and_set_offset("Sfree", "sfree");
    restore_and_set_offset("Sstrdup", "sstrdup");
    restore_and_set_offset("Strlen", "strlen");
#undef restore_offset
#undef restore_and_set_offset
    *out_kernel_base = offset_kernel_base;
    *out_kernel_slide = offset_kernel_slide;
    weird_offsets = true;
    found_offsets = true;
    restored_file_offset_cache = true;
out:;
    CFSafeReleaseNULL(offset_cache_file_url);
    CFSafeReleaseNULL(offset_cache_file_data);
    CFSafeReleaseNULL(offset_cache_property_list);
    return restored_file_offset_cache;
}

bool convert_port_to_task_port(mach_port_t port, kptr_t space, kptr_t task_kaddr) {
    bool ret = false;
    _assert(MACH_PORT_VALID(port));
    _assert(KERN_POINTER_VALID(space));
    _assert(KERN_POINTER_VALID(task_kaddr));
    kptr_t const port_kaddr = get_address_of_port(proc_struct_addr(), port);
    _assert(KERN_POINTER_VALID(port_kaddr));
    _assert(WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_BITS_ACTIVE | IKOT_TASK));
    _assert(WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d));
    _assert(WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d));
    _assert(WriteKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space));
    _assert(WriteKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr));
    kptr_t const task_port_addr = task_self_addr();
    _assert(KERN_POINTER_VALID(task_port_addr));
    kptr_t const task_addr = ReadKernel64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    _assert(KERN_POINTER_VALID(task_addr));
    kptr_t const itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    _assert(KERN_POINTER_VALID(itk_space));
    kptr_t const is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    _assert(KERN_POINTER_VALID(is_table));
    uint32_t bits = ReadKernel32(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)) + koffset(KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS));
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    _assert(WriteKernel32(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)) + koffset(KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS), bits));
    ret = true;
out:;
    return ret;
}

kptr_t make_fake_task(kptr_t vm_map) {
    kptr_t ret = KPTR_NULL;
    size_t fake_task_size = 0;
    kptr_t fake_task_kaddr = KPTR_NULL;
    void *fake_task = NULL;
    _assert(KERN_POINTER_VALID(vm_map));
    fake_task_size = 0x1000;
    fake_task_kaddr = IOMalloc(fake_task_size);
    _assert(KERN_POINTER_VALID(fake_task_kaddr));
    fake_task = malloc(fake_task_size);
    _assert(fake_task != NULL);
    memset(fake_task, 0, fake_task_size);
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d;
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    _assert(wkbuffer(fake_task_kaddr, fake_task, fake_task_size));
    ret = fake_task_kaddr;
out:;
    if (!KERN_POINTER_VALID(ret) && KERN_POINTER_VALID(fake_task_kaddr)) SafeIOFreeNULL(fake_task_kaddr, fake_task_size);
    SafeFreeNULL(fake_task);
    return ret;
}

bool make_port_fake_task_port(mach_port_t port, kptr_t task_kaddr) {
    bool ret = false;
    _assert(MACH_PORT_VALID(port));
    _assert(KERN_POINTER_VALID(task_kaddr));
    kptr_t const space = ipc_space_kernel();
    _assert(KERN_POINTER_VALID(space));
    _assert(convert_port_to_task_port(port, space, task_kaddr));
    ret = true;
out:;
    return ret;
}

bool set_hsp4(task_t port) {
    bool ret = false;
    host_t host = HOST_NULL;
    kern_return_t kr = KERN_FAILURE;
    _assert(MACH_PORT_VALID(port));
    host = mach_host_self();
    _assert(MACH_PORT_VALID(host));
    size_t const sizeof_task = 0x1000;
    kptr_t const kernel_task_offset = getoffset(kernel_task);
    _assert(KERN_POINTER_VALID(kernel_task_offset));
    kptr_t const kernel_task_addr = ReadKernel64(kernel_task_offset);
    _assert(KERN_POINTER_VALID(kernel_task_addr));
    task_t zm_fake_task_port = TASK_NULL;
    task_t km_fake_task_port = TASK_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    _assert(kr == KERN_SUCCESS);
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    _assert(kr == KERN_SUCCESS);
    kptr_t const zone_map_offset = getoffset(zone_map_ref);
    _assert(KERN_POINTER_VALID(zone_map_offset));
    kptr_t const zone_map = ReadKernel64(zone_map_offset);
    _assert(KERN_POINTER_VALID(zone_map));
    kptr_t const kernel_map = ReadKernel64(kernel_task_addr + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    _assert(KERN_POINTER_VALID(kernel_map));
    kptr_t const zm_fake_task_addr = make_fake_task(zone_map);
    _assert(KERN_POINTER_VALID(zm_fake_task_addr));
    kptr_t const km_fake_task_addr = make_fake_task(kernel_map);
    _assert(KERN_POINTER_VALID(km_fake_task_addr));
    _assert(make_port_fake_task_port(zm_fake_task_port, zm_fake_task_addr));
    _assert(make_port_fake_task_port(km_fake_task_port, km_fake_task_addr));
    km_fake_task_port = zm_fake_task_port;
    vm_prot_t cur = VM_PROT_NONE, max = VM_PROT_NONE;
    kptr_t remapped_task_addr = KPTR_NULL;
    kr = mach_vm_remap(km_fake_task_port, &remapped_task_addr, sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, zm_fake_task_port, kernel_task_addr, 0, &cur, &max, VM_INHERIT_NONE);
    _assert(kr == KERN_SUCCESS);
    _assert(remapped_task_addr != kernel_task_addr);
    kr = mach_vm_wire(host, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    _assert(kr == KERN_SUCCESS);
    kptr_t const port_addr = get_address_of_port(proc_struct_addr(), port);
    _assert(KERN_POINTER_VALID(port_addr));
    _assert(make_port_fake_task_port(port, remapped_task_addr));
    _assert(ReadKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) == remapped_task_addr);
    kptr_t const host_priv_addr = get_address_of_port(proc_struct_addr(), host);
    _assert(KERN_POINTER_VALID(host_priv_addr));
    kptr_t const realhost_addr = ReadKernel64(host_priv_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    _assert(KERN_POINTER_VALID(realhost_addr));
    int const slot = 4;
    _assert(WriteKernel64(realhost_addr + koffset(KSTRUCT_OFFSET_HOST_SPECIAL) + slot * sizeof(kptr_t), port_addr));
    ret = true;
out:;
    if (MACH_PORT_VALID(host)) mach_port_deallocate(mach_task_self(), host); host = HOST_NULL;
    return ret;
}

kptr_t get_vnode_for_path(const char *path) {
    kptr_t ret = KPTR_NULL;
    kptr_t *vpp = NULL;
    _assert(path != NULL);
    kptr_t const vfs_context = vfs_context_current();
    _assert(KERN_POINTER_VALID(vfs_context));
    vpp = malloc(sizeof(kptr_t));
    _assert(vpp != NULL);
    bzero(vpp, sizeof(kptr_t));
    _assert(vnode_lookup(path, O_RDONLY, vpp, vfs_context) == 0);
    kptr_t const vnode = *vpp;
    _assert(KERN_POINTER_VALID(vnode));
    ret = vnode;
out:;
    SafeFreeNULL(vpp);
    return ret;
}

kptr_t get_vnode_for_fd(int fd) {
    kptr_t ret = KPTR_NULL;
    kptr_t *vpp = NULL;
    _assert(fd > 0);
    kptr_t const vfs_context = vfs_context_current();
    _assert(KERN_POINTER_VALID(vfs_context));
    vpp = malloc(sizeof(kptr_t));
    _assert(vpp != NULL);
    bzero(vpp, sizeof(kptr_t));
    _assert(vnode_getfromfd(vfs_context, fd, vpp) == 0);
    kptr_t const vnode = *vpp;
    _assert(KERN_POINTER_VALID(vnode));
    ret = vnode;
out:;
    SafeFreeNULL(vpp);
    return ret;
}

char *get_path_for_fd(int fd) {
    char *ret = NULL;
    kptr_t vnode = KPTR_NULL;
    int *len = NULL;
    char *pathbuf = NULL;
    _assert(fd > 0);
    vnode = get_vnode_for_fd(fd);
    _assert(KERN_POINTER_VALID(vnode));
    len = malloc(sizeof(int));
    _assert(len != NULL);
    *len = MAXPATHLEN;
    pathbuf = malloc(*len);
    _assert(pathbuf != NULL);
    _assert(vn_getpath(vnode, pathbuf, len) == 0);
    _assert(strlen(pathbuf) + 1 == *len);
    ret = strdup(pathbuf);
out:;
    if (KERN_POINTER_VALID(vnode)) vnode_put(vnode); vnode = KPTR_NULL;
    SafeFreeNULL(pathbuf);
    SafeFreeNULL(len);
    return ret;
}

kptr_t get_vnode_for_snapshot(int fd, char *name) {
    kptr_t ret = KPTR_NULL;
    kptr_t snap_vnode, rvpp_ptr, sdvpp_ptr, ndp_buf, sdvpp, snap_meta_ptr, old_name_ptr, ndp_old_name;
    snap_vnode = rvpp_ptr = sdvpp_ptr = ndp_buf = sdvpp = snap_meta_ptr = old_name_ptr = ndp_old_name = KPTR_NULL;
    size_t rvpp_ptr_size, sdvpp_ptr_size, ndp_buf_size, snap_meta_ptr_size, old_name_ptr_size;
    ndp_buf_size = 816;
    rvpp_ptr_size = sdvpp_ptr_size = snap_meta_ptr_size = old_name_ptr_size = sizeof(kptr_t);
    rvpp_ptr = IOMalloc(rvpp_ptr_size);
    _assert(KERN_POINTER_VALID(rvpp_ptr));
    sdvpp_ptr = IOMalloc(sdvpp_ptr_size);
    _assert(KERN_POINTER_VALID(sdvpp_ptr));
    ndp_buf = IOMalloc(ndp_buf_size);
    _assert(KERN_POINTER_VALID(ndp_buf));
    kptr_t const vfs_context = vfs_context_current();
    _assert(KERN_POINTER_VALID(vfs_context));
    _assert(kexec(getoffset(vnode_get_snapshot), fd, rvpp_ptr, sdvpp_ptr, (kptr_t)name, ndp_buf, 2, vfs_context) == 0);
    sdvpp = ReadKernel64(sdvpp_ptr);
    _assert(KERN_POINTER_VALID(sdvpp_ptr));
    kptr_t const sdvpp_v_mount = ReadKernel64(sdvpp + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
    _assert(KERN_POINTER_VALID(sdvpp_v_mount));
    kptr_t const sdvpp_v_mount_mnt_data = ReadKernel64(sdvpp_v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_DATA));
    _assert(KERN_POINTER_VALID(sdvpp_v_mount_mnt_data));
    snap_meta_ptr = IOMalloc(snap_meta_ptr_size);
    _assert(KERN_POINTER_VALID(snap_meta_ptr));
    old_name_ptr = IOMalloc(old_name_ptr_size);
    _assert(KERN_POINTER_VALID(old_name_ptr));
    ndp_old_name = ReadKernel64(ndp_buf + 336 + 40);
    _assert(KERN_POINTER_VALID(ndp_old_name));
    kptr_t const ndp_old_name_len = ReadKernel32(ndp_buf + 336 + 48);
    _assert(kexec(getoffset(fs_lookup_snapshot_metadata_by_name_and_return_name), sdvpp_v_mount_mnt_data, ndp_old_name, ndp_old_name_len, snap_meta_ptr, old_name_ptr, 0, 0) == 0);
    kptr_t const snap_meta = ReadKernel64(snap_meta_ptr);
    _assert(KERN_POINTER_VALID(snap_meta));
    snap_vnode = kexec(getoffset(apfs_jhash_getvnode), sdvpp_v_mount_mnt_data, ReadKernel32(sdvpp_v_mount_mnt_data + 440), ReadKernel64(snap_meta + 8), 1, 0, 0, 0);
    if (snap_vnode != KPTR_NULL) snap_vnode = zm_fix_addr(snap_vnode);
    _assert(KERN_POINTER_VALID(snap_vnode));
    ret = snap_vnode;
out:
    if (KERN_POINTER_VALID(sdvpp)) vnode_put(sdvpp); sdvpp = KPTR_NULL;
    SafeIOFreeNULL(sdvpp_ptr, sdvpp_ptr_size);
    SafeIOFreeNULL(ndp_buf, ndp_buf_size);
    SafeIOFreeNULL(snap_meta_ptr, snap_meta_ptr_size);
    SafeIOFreeNULL(old_name_ptr, old_name_ptr_size);
    return ret;
}

bool set_kernel_task_info() {
    bool ret = false;
    kern_return_t kr = KERN_FAILURE;
    struct task_dyld_info *task_dyld_info = NULL;
    mach_msg_type_number_t *task_dyld_info_count = NULL;
    struct cache_blob *cache = NULL;
    size_t cache_size = 0;
    kptr_t kernel_cache_blob = KPTR_NULL;
    task_dyld_info = malloc(sizeof(struct task_dyld_info));
    _assert(task_dyld_info != NULL);
    bzero(task_dyld_info, sizeof(struct task_dyld_info));
    task_dyld_info_count = malloc(sizeof(mach_msg_type_number_t));
    _assert(task_dyld_info_count != NULL);
    bzero(task_dyld_info_count, sizeof(mach_msg_type_number_t));
    *task_dyld_info_count = TASK_DYLD_INFO_COUNT;
    kptr_t const kernel_task_offset = getoffset(kernel_task);
    _assert(KERN_POINTER_VALID(kernel_task_offset));
    kptr_t const kernel_task_addr = ReadKernel64(kernel_task_offset);
    _assert(KERN_POINTER_VALID(kernel_task_addr));
    kr = task_info(tfp0, TASK_DYLD_INFO, (task_info_t)task_dyld_info, task_dyld_info_count);
    _assert(kr == KERN_SUCCESS);
    if (KERN_POINTER_VALID(task_dyld_info->all_image_info_addr) && task_dyld_info->all_image_info_addr != kernel_base && task_dyld_info->all_image_info_addr > kernel_base) {
        size_t const blob_size = ReadKernel32(task_dyld_info->all_image_info_addr + offsetof(struct cache_blob, size));
        _assert(blob_size > 0);
        struct cache_blob *blob = create_cache_blob(blob_size);
        _assert(blob != NULL);
        merge_cache_blob(blob); // Adds any entries that are in kernel but we don't have
        SafeFreeNULL(blob);
        _assert(kmem_free(task_dyld_info->all_image_info_addr, blob_size)); // Free old offset cache - didn't bother comparing because it's faster to just replace it if it's the same
    }
    cache_size = export_cache_blob(&cache);
    kernel_cache_blob = kmem_alloc_wired(cache_size);
    _assert(KERN_POINTER_VALID(kernel_cache_blob));
    blob_rebase(cache, (kptr_t)cache, kernel_cache_blob);
    _assert(wkbuffer(kernel_cache_blob, cache, cache_size));
    _assert(WriteKernel64(kernel_task_addr + koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_ADDR), kernel_cache_blob));
    _assert(WriteKernel64(kernel_task_addr + koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_SIZE), kernel_slide));
    bzero(task_dyld_info, sizeof(struct task_dyld_info));
    kr = task_info(tfp0, TASK_DYLD_INFO, (task_info_t)task_dyld_info, task_dyld_info_count);
    _assert(kr == KERN_SUCCESS);
    _assert(task_dyld_info->all_image_info_addr == kernel_cache_blob);
    _assert(task_dyld_info->all_image_info_size == kernel_slide);
    ret = true;
out:;
    if (!ret && KERN_POINTER_VALID(kernel_cache_blob)) SafeIOFreeNULL(kernel_cache_blob, cache_size);
    SafeFreeNULL(task_dyld_info);
    SafeFreeNULL(task_dyld_info_count);
    SafeFreeNULL(cache);
    return ret;
}

int issue_extension_for_mach_service(kptr_t sb, kptr_t ctx, const char *entry_name, void *desc) {
    int ret = -1;
    kptr_t entry_name_kstr = KPTR_NULL;
    kptr_t desc_kstr = KPTR_NULL;
    _assert(KERN_POINTER_VALID(sb));
    _assert(entry_name != NULL);
    _assert(desc != NULL);
    kptr_t const function = getoffset(issue_extension_for_mach_service);
    _assert(KERN_POINTER_VALID(function));
    entry_name_kstr = sstrdup(entry_name);
    _assert(KERN_POINTER_VALID(entry_name_kstr));
    desc_kstr = sstrdup(desc);
    _assert(KERN_POINTER_VALID(desc_kstr));
    ret = (int)kexec(function, sb, ctx, entry_name_kstr, desc_kstr, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    SafeSFreeNULL(entry_name_kstr);
    SafeSFreeNULL(desc_kstr);
    return ret;
}

bool analyze_pid(pid_t pid,
                 kptr_t *out_proc,
                 kptr_t *out_proc_ucred,
                 kptr_t *out_cr_label,
                 kptr_t *out_amfi_entitlements,
                 kptr_t *out_sandbox,
                 char **out_path,
                 bool *out_file_is_setuid,
                 bool *out_file_is_setgid,
                 uid_t *out_file_uid,
                 gid_t *out_file_gid,
                 uint32_t *out_csflags,
                 bool *out_is_platform_application) {
    bool ret = false;
    kptr_t proc = KPTR_NULL;
    kptr_t proc_ucred = KPTR_NULL;
    kptr_t cr_label = KPTR_NULL;
    kptr_t amfi_entitlements = KPTR_NULL;
    kptr_t sandbox = KPTR_NULL;
    char *path = NULL;
    bool file_is_setuid = false;
    bool file_is_setgid = false;
    uid_t file_uid = 0;
    gid_t file_gid = 0;
    uint32_t csflags = 0;
    bool is_platform_application = false;
    struct stat *statbuf = NULL;
    LOG("Analyzing pid %d", pid);
    if (pid <= 0) {
        LOG("Invalid pid");
        goto out;
    }
    if (out_proc != NULL || out_proc_ucred != NULL || out_cr_label != NULL ||
        out_amfi_entitlements != NULL || out_sandbox != NULL ||
        out_is_platform_application != NULL) {
        proc = proc_find(pid);
        if (!KERN_POINTER_VALID(proc)) {
            LOG("Unable to get proc");
            goto out;
        }
        if (out_proc_ucred != NULL || out_cr_label != NULL ||
            out_amfi_entitlements != NULL || out_sandbox != NULL ||
            out_is_platform_application != NULL) {
            proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
            if (!KERN_POINTER_VALID(proc_ucred)) {
                LOG("Unable to get proc_ucred");
                goto out;
            }
            if (out_cr_label != NULL || out_amfi_entitlements != NULL ||
                out_sandbox != NULL || out_is_platform_application != NULL) {
                cr_label = ReadKernel64(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
                if (!KERN_POINTER_VALID(cr_label)) {
                    LOG("Unable to get cr_label");
                    goto out;
                }
                if (out_amfi_entitlements != NULL || out_is_platform_application) {
                    amfi_entitlements = get_amfi_entitlements(cr_label);
                    if (!KERN_POINTER_VALID(amfi_entitlements)) {
                        LOG("Unable to get amfi_entitlements");
                        goto out;
                    }
                    if (OSDictionary_GetItem(amfi_entitlements, "platform-application") == OSBoolTrue) {
                        is_platform_application = true;
                    }
                }
                if (out_sandbox != NULL) {
                    sandbox = get_sandbox(cr_label);
                }
            }
        }
    }
    if (out_path != NULL || out_file_is_setuid != NULL || out_file_is_setgid != NULL ||
        out_file_uid != NULL || out_file_gid != NULL) {
        path = get_path_for_pid(pid);
        if (path == NULL) {
            LOG("Unable to get path");
            goto out;
        }
        if (out_file_is_setuid != NULL || out_file_is_setgid != NULL ||
            out_file_uid != NULL || out_file_gid != NULL) {
            statbuf = malloc(sizeof(struct stat));
            if (statbuf == NULL) goto out;
            bzero(statbuf, sizeof(struct stat));
            if (lstat(path, statbuf) == -1) {
                LOG("Unable to get stat");
                goto out;
            }
            if (out_file_is_setuid != NULL) {
                file_is_setuid = (statbuf->st_mode & S_ISUID);
            }
            if (out_file_is_setgid != NULL) {
                file_is_setgid = (statbuf->st_mode & S_ISGID);
            }
            if (out_file_uid != NULL) {
                file_uid = statbuf->st_uid;
            }
            if (out_file_gid != NULL) {
                file_gid = statbuf->st_gid;
            }
        }
    }
    if (out_csflags != NULL) {
        if (csops(pid, CS_OPS_STATUS, (void *)&csflags, sizeof(csflags)) == -1) {
            LOG("Unable to get csflags");
            goto out;
        }
    }
    if (out_proc != NULL) {
        *out_proc = proc;
    }
    if (out_proc_ucred != NULL) {
        *out_proc_ucred = proc_ucred;
    }
    if (out_cr_label != NULL) {
        *out_cr_label = cr_label;
    }
    if (out_amfi_entitlements != NULL) {
        *out_amfi_entitlements = amfi_entitlements;
    }
    if (out_sandbox != NULL) {
        *out_sandbox = sandbox;
    }
    if (out_path != NULL) {
        *out_path = strdup(path);
    }
    if (out_file_is_setuid != NULL) {
        *out_file_is_setuid = file_is_setuid;
    }
    if (out_file_is_setgid != NULL) {
        *out_file_is_setgid = file_is_setgid;
    }
    if (out_file_uid != NULL) {
        *out_file_uid = file_uid;
    }
    if (out_file_gid != NULL) {
        *out_file_gid = file_gid;
    }
    if (out_csflags != NULL) {
        *out_csflags = csflags;
    }
    if (out_is_platform_application != NULL) {
        *out_is_platform_application = is_platform_application;
    }
    LOG("Analyzed pid %d", pid);
    ret = true;
out:;
    SafeFreeNULL(path);
    SafeFreeNULL(statbuf);
    return ret;
}

bool unrestrict_process(pid_t pid) {
    bool ret = true;
    kptr_t proc = KPTR_NULL;
    kptr_t proc_ucred = KPTR_NULL;
    kptr_t amfi_entitlements = KPTR_NULL;
    kptr_t sandbox = KPTR_NULL;
    bool is_setuid = false;
    bool is_setgid = false;
    uid_t file_uid = 0;
    gid_t file_gid = 0;
    uint32_t csflags = 0;
    bool is_platform_application = false;
    char *path = NULL;
    if (!analyze_pid(pid,
                    &proc,
                    &proc_ucred,
                    NULL,
                    &amfi_entitlements,
                    &sandbox,
                    &path,
                    &is_setuid,
                    &is_setgid,
                    &file_uid,
                    &file_gid,
                    &csflags,
                    &is_platform_application)) {
        LOG("Unable to analyze pid %d", pid);
        ret = false;
        goto out;
    }
    if (is_setuid) {
        LOG("Enabling setuid for pid %d", pid);
        if (!WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_SVUID), file_uid) ||
            !WriteKernel32(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_SVUID), file_uid) ||
            !WriteKernel32(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_UID), file_uid)) {
            LOG("Unable to enable setuid for pid %d", pid);
            ret = false;
        }
    }
    if (is_setgid) {
        LOG("Enabling setgid for pid %d", pid);
        if (!WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_SVGID), file_gid) ||
            !WriteKernel32(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_SVGID), file_gid) ||
            !WriteKernel32(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_GROUPS), file_gid)) {
            LOG("Unable to enable setgid for pid %d", pid);
            ret = false;
        }
    }
    LOG("Disabling library validation for pid %d", pid);
    if (!entitle_process(amfi_entitlements, "com.apple.private.skip-library-validation", OSBoolTrue)) {
        LOG("Unable to disable library validation for pid %d", pid);
        ret = false;
    }
    if (OPT(GET_TASK_ALLOW)) {
        LOG("Enabling get-task-allow entitlement for pid %d", pid);
        if (!entitle_process(amfi_entitlements, "get-task-allow", OSBoolTrue)) {
            LOG("Unable to enable get-task-allow entitlement for pid %d", pid);
            ret = false;
        }
        LOG("Setting get-task-allow codesign flag for pid %d", pid);
        if (!set_csflags(proc, CS_GET_TASK_ALLOW, true)) {
            LOG("Unable to set get-task-allow codesign flag for pid %d", pid);
            ret = false;
        }
    }
    if (is_platform_application) {
        LOG("Setting platform binary task flag for pid %d", pid);
        if (!set_platform_binary(proc, true)) {
            LOG("Unable to set platform binary task flag for pid %d", pid);
            ret = false;
        }
        LOG("Setting platform binary codesign flag for pid %d", pid);
        if (!set_cs_platform_binary(proc, true)) {
            LOG("Unable to set platform binary codesign flag for pid %d", pid);
            ret = false;
        }
    }
    if (OPT(CS_DEBUGGED)) {
        LOG("Disabling dynamic codesigning for pid %d", pid);
        if (!set_csflags(proc, CS_DEBUGGED, true) ||
            !set_csflags(proc, CS_HARD, false)) {
            LOG("Unable to disable dynamic codesigning for pid %d", pid);
            ret = false;
        }
    }
    if (strcmp(path, "/usr/libexec/securityd") == 0 &&
        access("/Library/substrate", F_OK) == 0 &&
        is_directory("/Library/substrate") &&
        access("/usr/lib/substrate", F_OK) == 0 &&
        is_symlink("/usr/lib/substrate")) {
        LOG("Skipping exceptions for pid %d", pid);
        goto out;
    }
    LOG("Setting exceptions for pid %d", pid);
    if (!set_exceptions(sandbox, amfi_entitlements)) {
        LOG("Unable to set exceptions for pid %d", pid);
        ret = false;
    }
out:;
    if (KERN_POINTER_VALID(proc)) proc_rele(proc);
    SafeFreeNULL(path);
    return ret;
}

bool unrestrict_process_with_task_port(task_t task_port) {
    bool ret = false;
    pid_t pid = 0;
    _assert(pid_for_task(task_port, &pid) == KERN_SUCCESS);
    _assert(unrestrict_process(pid));
    ret = true;
out:;
    return ret;
}

bool unrestrict_library(const char *path) {
    bool ret = false;
    _assert(path != NULL);
    _assert(enable_mapping_for_library(path));
    ret = true;
out:;
    return ret;
}

bool unrestrict_library_with_fd(int fd) {
    bool ret = false;
    char *path = NULL;
    _assert(fd > 0);
    path = get_path_for_fd(fd);
    _assert(path != NULL);
    _assert(unrestrict_library(path));
    ret = true;
out:;
    SafeFreeNULL(path);
    return ret;
}

bool revalidate_process(pid_t pid) {
    bool ret = true;
    kptr_t proc = KPTR_NULL;
    uint32_t csflags = 0;
    if (!analyze_pid(pid,
                     &proc,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     &csflags,
                     NULL)) {
        LOG("Unable to analyze pid %d", pid);
        ret = false;
        goto out;
    }
    LOG("Setting dynamic validity codesign flag for pid %d", pid);
    if (!set_csflags(proc, CS_VALID, true)) {
        LOG("Unable to set dynamic validity codesign flag for pid %d", pid);
        ret = false;
    }
out:;
    if (KERN_POINTER_VALID(proc)) proc_rele(proc);
    return ret;
}

bool revalidate_process_with_task_port(task_t task_port) {
    bool ret = false;
    pid_t pid = 0;
    _assert(pid_for_task(task_port, &pid) == KERN_SUCCESS);
    _assert(revalidate_process(pid));
    ret = true;
out:;
    return ret;
}

bool enable_mapping_for_library(const char *lib) {
    bool ret = false;
    kptr_t vnode = KPTR_NULL;
    _assert(lib != NULL);
    vnode = get_vnode_for_path(lib);
    _assert(KERN_POINTER_VALID(vnode));
    kptr_t v_flags_addr = vnode + koffset(KSTRUCT_OFFSET_VNODE_V_FLAG);
    uint32_t v_flags = ReadKernel32(v_flags_addr);
    v_flags |= VSHARED_DYLD;
    _assert(WriteKernel32(v_flags_addr, v_flags));
    ret = true;
out:;
    if (KERN_POINTER_VALID(vnode)) vnode_put(vnode); vnode = KPTR_NULL;
    return ret;
}

bool enable_mapping_for_libraries(const char *libs) {
    bool ret = false;
    CFURLRef libraries = NULL;
    CFBundleRef folder = NULL;
    _assert(libs != NULL);
    libraries = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)libs, strlen(libs), true);
    _assert(libraries != NULL);
    folder = CFBundleCreate(kCFAllocatorDefault, libraries);
    _assert(folder != NULL);
    CFArrayRef dylibs = CFBundleCopyResourceURLsOfType(folder, CFSTR("dylib"), NULL);
    _assert(dylibs != NULL);
    for (CFIndex i = 0, count = CFArrayGetCount(dylibs); i != count; i++) {
        CFURLRef dylib = (CFURLRef)CFArrayGetValueAtIndex(dylibs, i);
        char path[PATH_MAX];
        CFURLGetFileSystemRepresentation(dylib, true, (UInt8 *)path, sizeof(path));
        LOG("Enabling mapping for library: %s", path);
        _assert(enable_mapping_for_library(path));
    }
    ret = true;
out:;
    CFSafeReleaseNULL(libraries);
    CFSafeReleaseNULL(folder);
    return ret;
}

kptr_t find_vnode_with_fd(kptr_t proc, int fd) {
    kptr_t ret = KPTR_NULL;
    _assert(fd > 0);
    _assert(KERN_POINTER_VALID(proc));
    kptr_t fdp = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_P_FD));
    _assert(KERN_POINTER_VALID(fdp));
    kptr_t ofp = ReadKernel64(fdp + koffset(KSTRUCT_OFFSET_FILEDESC_FD_OFILES));
    _assert(KERN_POINTER_VALID(ofp));
    kptr_t fpp = ReadKernel64(ofp + (fd * sizeof(kptr_t)));
    _assert(KERN_POINTER_VALID(fpp));
    kptr_t fgp = ReadKernel64(fpp + koffset(KSTRUCT_OFFSET_FILEPROC_F_FGLOB));
    _assert(KERN_POINTER_VALID(fgp));
    kptr_t vnode = ReadKernel64(fgp + koffset(KSTRUCT_OFFSET_FILEGLOB_FG_DATA));
    _assert(KERN_POINTER_VALID(vnode));
    ret = vnode;
out:;
    return ret;
}

kptr_t find_vnode_with_path(const char *path) {
    kptr_t ret = KPTR_NULL;
    int fd = 0;
    _assert(path != NULL);
    kptr_t const proc = proc_struct_addr();
    _assert(KERN_POINTER_VALID(proc));
    fd = open(path, O_RDONLY);
    ret = find_vnode_with_fd(proc, fd);
out:;
    if (fd > 0) close(fd); fd = 0;
    return ret;
}

kptr_t swap_sandbox_for_proc(kptr_t proc, kptr_t sandbox) {
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    _assert(KERN_POINTER_VALID(ucred));
    kptr_t const cr_label = ReadKernel64(ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
    _assert(KERN_POINTER_VALID(cr_label));
    kptr_t const sandbox_addr = cr_label + 0x8 + 0x8;
    kptr_t const current_sandbox = ReadKernel64(sandbox_addr);
    _assert(WriteKernel64(sandbox_addr, sandbox));
    ret = current_sandbox;
out:;
    return ret;
}
