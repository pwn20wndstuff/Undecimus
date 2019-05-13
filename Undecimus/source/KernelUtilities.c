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

#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)

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

extern char *get_path_for_pid(pid_t pid);

kptr_t kernel_base = KPTR_NULL;
kptr_t offset_options = KPTR_NULL;
bool found_offsets = false;
kptr_t cached_task_self_addr = KPTR_NULL;

#define find_port(port, disposition) (have_kmem_read() && found_offsets ? get_address_of_port(getpid(), port) : find_port_address(port, disposition))

kptr_t task_self_addr()
{
    auto ret = KPTR_NULL;
    if (KERN_POINTER_VALID((ret = cached_task_self_addr))) goto out;
    cached_task_self_addr = find_port(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
out:;
    return cached_task_self_addr;
}

kptr_t ipc_space_kernel()
{
    auto ret = KPTR_NULL;
    auto const task_self = task_self_addr();
    if (!KERN_POINTER_VALID(task_self)) goto out;
    auto const ipc_space = ReadKernel64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
    if (!KERN_POINTER_VALID(ipc_space)) goto out;
    ret = ipc_space;
out:;
    return ret;
}

kptr_t current_thread()
{
    auto ret = KPTR_NULL;
    auto thread = THREAD_NULL;
    thread = mach_thread_self();
    if (!MACH_PORT_VALID(thread)) goto out;
    auto const thread_port = find_port(thread, MACH_MSG_TYPE_COPY_SEND);
    if (!KERN_POINTER_VALID(thread_port)) goto out;
    auto const thread_addr = ReadKernel64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    if (!KERN_POINTER_VALID(thread_addr)) goto out;
    ret = thread_addr;
out:;
    if (MACH_PORT_VALID(thread)) mach_port_deallocate(mach_task_self(), thread); thread = THREAD_NULL;
    return ret;
}

kptr_t find_kernel_base()
{
    auto ret = KPTR_NULL;
    auto host = HOST_NULL;
    host = mach_host_self();
    if (!MACH_PORT_VALID(host)) goto out;
    auto const hostport_addr = find_port(host, MACH_MSG_TYPE_COPY_SEND);
    if (!KERN_POINTER_VALID(hostport_addr)) goto out;
    auto const realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    if (!KERN_POINTER_VALID(realhost)) goto out;
    auto base = realhost & ~0xfffULL;
    // walk down to find the magic:
    for (auto i = 0; i < 0x10000; i++) {
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
    auto host = mach_host_self();
    auto hostport_addr = find_port(host, MACH_MSG_TYPE_COPY_SEND);
    mach_port_deallocate(mach_task_self(), host);
    auto realhost = ReadKernel64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));

    // allocate a port
    auto port = TASK_NULL;
    auto err = KERN_FAILURE;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        LOG("failed to allocate port");
        return MACH_PORT_NULL;
    }

    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);

    // locate the port
    auto port_addr = find_port(port, MACH_MSG_TYPE_COPY_SEND);

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
    auto ret = KPTR_NULL;
    auto const symbol = getoffset(kernel_task);
    if (!KERN_POINTER_VALID(symbol)) goto out;
    auto const task = ReadKernel64(symbol);
    if (!KERN_POINTER_VALID(task)) goto out;
    auto const bsd_info = ReadKernel64(task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    if (!KERN_POINTER_VALID(bsd_info)) goto out;
    ret = bsd_info;
out:;
    return ret;
}

bool iterate_proc_list(void (^handler)(kptr_t, pid_t, int *)) {
    auto ret = false;
    if (handler == NULL) goto out;
    auto iterate = true;
    auto proc = get_kernel_proc_struct_addr();
    if (!KERN_POINTER_VALID(proc)) goto out;
    while (KERN_POINTER_VALID(proc) && iterate) {
        auto const pid = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
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
    __block auto proc = KPTR_NULL;
    auto const handler = ^(kptr_t found_proc, pid_t found_pid, int *iterate) {
        if (found_pid == pid) {
            proc = found_proc;
            *iterate = false;
        }
    };
    if (!iterate_proc_list(handler)) goto out;
out:;
    return proc;
}

kptr_t get_address_of_port(pid_t pid, mach_port_t port)
{
    auto ret = KPTR_NULL;
    if (!MACH_PORT_VALID(port)) goto out;
    auto const proc_struct_addr = get_proc_struct_for_pid(pid);
    if (!KERN_POINTER_VALID(proc_struct_addr)) goto out;
    auto const task_addr = ReadKernel64(proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_TASK));
    if (!KERN_POINTER_VALID(task_addr)) goto out;
    auto const itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    if (!KERN_POINTER_VALID(itk_space)) goto out;
    auto const is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    if (!KERN_POINTER_VALID(is_table)) goto out;
    auto const port_addr = ReadKernel64(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)));
    if (!KERN_POINTER_VALID(port_addr)) goto out;
    ret = port_addr;
out:;
    return ret;
}

kptr_t get_kernel_cred_addr()
{
    auto ret = KPTR_NULL;
    auto const kernel_proc_struct_addr = get_proc_struct_for_pid(0);
    if (!KERN_POINTER_VALID(kernel_proc_struct_addr)) goto out;
    auto const kernel_ucred_struct_addr = ReadKernel64(kernel_proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    if (!KERN_POINTER_VALID(kernel_ucred_struct_addr)) goto out;
    ret = kernel_ucred_struct_addr;
out:;
    return ret;
}

kptr_t give_creds_to_process_at_addr(kptr_t proc, kptr_t cred_addr)
{
    auto ret = KPTR_NULL;
    if (!KERN_POINTER_VALID(proc) || !KERN_POINTER_VALID(cred_addr)) goto out;
    auto const proc_cred_addr = proc + koffset(KSTRUCT_OFFSET_PROC_UCRED);
    auto const current_cred_addr = ReadKernel64(proc_cred_addr);
    if (!KERN_POINTER_VALID(current_cred_addr)) goto out;
    if (!WriteKernel64(proc_cred_addr, cred_addr)) goto out;
    ret = current_cred_addr;
out:;
    return ret;
}

bool set_platform_binary(kptr_t proc, bool set)
{
    auto ret = false;
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    if (!KERN_POINTER_VALID(task_struct_addr)) goto out;
    auto const task_t_flags_addr = task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS);
    auto task_t_flags = ReadKernel32(task_t_flags_addr);
    if (set) {
        task_t_flags |= TF_PLATFORM;
    } else {
        task_t_flags &= ~(TF_PLATFORM);
    }
    if (!WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags)) goto out;
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
    auto zm_fixed_addr = KPTR_NULL;
    auto zm_hdr = (kmap_hdr_t *)NULL;
    auto const symbol = getoffset(zone_map_ref);
    if (!KERN_POINTER_VALID(symbol)) goto out;
    zm_hdr = (kmap_hdr_t *)malloc(sizeof(kmap_hdr_t));
    if (zm_hdr == NULL) goto out;
    auto const zone_map = ReadKernel64(symbol);
    if (!KERN_POINTER_VALID(zone_map)) goto out;
    if (!rkbuffer(zone_map + 0x10, zm_hdr, sizeof(kmap_hdr_t))) goto out;
    if (zm_hdr->end - zm_hdr->start > 0x100000000) goto out;
    auto const zm_tmp = (zm_hdr->start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    zm_fixed_addr = zm_tmp < zm_hdr->start ? zm_tmp + 0x100000000 : zm_tmp;
out:;
    SafeFreeNULL(zm_hdr);
    return zm_fixed_addr;
}

bool verify_tfp0() {
    auto ret = false;
    auto test_kptr_size = SIZE_NULL;
    auto test_kptr = KPTR_NULL;
    auto const test_data = (kptr_t)0x4141414141414141;
    test_kptr_size = sizeof(kptr_t);
    test_kptr = kmem_alloc(test_kptr_size);
    if (!KERN_POINTER_VALID(test_kptr)) goto out;
    if (!WriteKernel64(test_kptr, test_data)) goto out;
    if (ReadKernel64(test_kptr) != test_data) goto out;
    ret = true;
out:;
    if (KERN_POINTER_VALID(test_kptr)) kmem_free(test_kptr, test_kptr_size); test_kptr = KPTR_NULL;
    return ret;
}

int (*pmap_load_trust_cache)(kptr_t kernel_trust, size_t length) = NULL;
int _pmap_load_trust_cache(kptr_t kernel_trust, size_t length) {
    auto ret = -1;
    if (!KERN_POINTER_VALID(kernel_trust)) goto out;
    auto const function = getoffset(pmap_load_trust_cache);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = (int)kexec(function, kernel_trust, (kptr_t)length, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

bool set_host_type(host_t host, uint32_t type) {
    auto ret = false;
    if (!MACH_PORT_VALID(host)) goto out;
    auto const hostport_addr = get_address_of_port(getpid(), host);
    if (!KERN_POINTER_VALID(hostport_addr)) goto out;
    if (!WriteKernel32(hostport_addr, type)) goto out;
    ret = true;
out:;
    return ret;
}

bool export_tfp0(host_t host) {
    auto ret = false;
    if (!MACH_PORT_VALID(host)) goto out;
    const auto type = IO_BITS_ACTIVE | IKOT_HOST_PRIV;
    if (!set_host_type(host, type)) goto out;
    ret = true;
out:;
    return ret;
}

bool unexport_tfp0(host_t host) {
    auto ret = false;
    if (!MACH_PORT_VALID(host)) goto out;
    const auto type = IO_BITS_ACTIVE | IKOT_HOST;
    if (!set_host_type(host, type)) goto out;
    ret = true;
out:;
    return ret;
}

bool set_csflags(kptr_t proc, uint32_t flags, bool value) {
    auto ret = false;
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const proc_csflags_addr = proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS);
    auto csflags = ReadKernel32(proc_csflags_addr);
    if (value == true) {
        csflags |= flags;
    } else {
        csflags &= ~flags;
    }
    if (!WriteKernel32(proc_csflags_addr, csflags)) goto out;
    ret = true;
out:;
    return ret;
}

bool set_cs_platform_binary(kptr_t proc, bool value) {
    auto ret = false;
    if (!KERN_POINTER_VALID(proc)) goto out;
    if (!set_csflags(proc, CS_PLATFORM_BINARY, value)) goto out;
    ret = true;
out:;
    return ret;
}

bool execute_with_credentials(kptr_t proc, kptr_t credentials, void (^function)(void)) {
    auto ret = KPTR_NULL;
    if (!KERN_POINTER_VALID(proc) || !KERN_POINTER_VALID(credentials) || function == NULL) goto out;
    auto const saved_credentials = give_creds_to_process_at_addr(proc, credentials);
    if (!KERN_POINTER_VALID(saved_credentials)) goto out;
    function();
    ret = give_creds_to_process_at_addr(proc, saved_credentials);
out:;
    return ret;
}

uint32_t get_proc_memstat_state(kptr_t proc) {
    auto ret = (uint32_t)0;
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const p_memstat_state = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_MEMSTAT_STATE));
    ret = p_memstat_state;
out:;
    return ret;
}

bool set_proc_memstat_state(kptr_t proc, uint32_t memstat_state) {
    auto ret = false;
    if (!KERN_POINTER_VALID(proc)) goto out;
    if (!WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_MEMSTAT_STATE), memstat_state)) goto out;
    ret = true;
out:;
    return ret;
}

bool set_proc_memstat_internal(kptr_t proc, bool set) {
    auto ret = false;
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto memstat_state = get_proc_memstat_state(proc);
    if (set) {
        memstat_state |= P_MEMSTAT_INTERNAL;
    } else {
        memstat_state &= ~P_MEMSTAT_INTERNAL;
    }
    if (!set_proc_memstat_state(proc, memstat_state)) goto out;
    ret = true;
out:;
    return ret;
}

bool get_proc_memstat_internal(kptr_t proc) {
    auto ret = false;
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const p_memstat_state = get_proc_memstat_state(proc);
    ret = (p_memstat_state & P_MEMSTAT_INTERNAL);
out:;
    return ret;
}

size_t kstrlen(kptr_t ptr) {
    auto size = SIZE_NULL;
    if (!KERN_POINTER_VALID(ptr)) goto out;
    auto const function = getoffset(strlen);
    if (!KERN_POINTER_VALID(function)) goto out;
    size = (size_t)kexec(function, ptr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return size;
}

kptr_t kstralloc(const char *str) {
    auto ret = false;
    auto str_kptr = KPTR_NULL;
    auto str_kptr_size = SIZE_NULL;
    if (str == NULL) goto out;
    str_kptr_size = strlen(str) + 1;
    str_kptr = kmem_alloc(str_kptr_size);
    if (!KERN_POINTER_VALID(str_kptr)) goto out;
    if (!wkbuffer(str_kptr, (void *)str, str_kptr_size)) goto out;
    ret = true;
out:;
    if (!ret && str_kptr_size != SIZE_NULL && KERN_POINTER_VALID(str_kptr)) {
        kmem_free(str_kptr, str_kptr_size);
        str_kptr = KPTR_NULL;
        str_kptr_size = SIZE_NULL;
    }
    return str_kptr;
}

bool kstrfree(kptr_t ptr) {
    bool ret = false;
    auto size = SIZE_NULL;
    if (!KERN_POINTER_VALID(ptr)) goto out;
    size = kstrlen(ptr) + 1;
    if (!kmem_free(ptr, size)) goto out;
    ret = true;
out:;
    return ret;
}

kptr_t sstrdup(const char *str) {
    auto ret = KPTR_NULL;
    auto kstr = KPTR_NULL;
    if (str == NULL) goto out;
    auto const function = getoffset(sstrdup);
    if (!KERN_POINTER_VALID(function)) goto out;
    kstr = kstralloc(str);
    if (!KERN_POINTER_VALID(kstr)) goto out;
    ret = kexec(function, kstr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    if (KERN_POINTER_VALID(kstr)) kstrfree(kstr); kstr = KPTR_NULL;
    return ret;
}

kptr_t smalloc(size_t size) {
    auto ret = KPTR_NULL;
    auto const function = getoffset(smalloc);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = kexec(function, (kptr_t)size, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    return ret;
}

void sfree(kptr_t ptr) {
    if (!KERN_POINTER_VALID(ptr)) goto out;
    auto const function = getoffset(sfree);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, ptr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

int extension_create_file(kptr_t saveto, kptr_t sb, const char *path, size_t path_len, uint32_t subtype) {
    auto ret = -1;
    auto kstr = KPTR_NULL;
    if (!KERN_POINTER_VALID(saveto) || !KERN_POINTER_VALID(sb) || path == NULL || path_len <= 0) goto out;
    auto const function = getoffset(extension_create_file);
    if (!KERN_POINTER_VALID(function)) goto out;
    kstr = kstralloc(path);
    if (!KERN_POINTER_VALID(kstr)) goto out;
    ret = (int)kexec(function, saveto, sb, kstr, (kptr_t)path_len, (kptr_t)subtype, KPTR_NULL, KPTR_NULL);
out:;
    if (KERN_POINTER_VALID(kstr)) kstrfree(kstr); kstr = KPTR_NULL;
    return ret;
}

int extension_create_mach(kptr_t saveto, kptr_t sb, const char *name, uint32_t subtype) {
    auto ret = -1;
    auto kstr = KPTR_NULL;
    auto const function = getoffset(extension_create_mach);
    if (!KERN_POINTER_VALID(function)) goto out;
    kstr = KPTR_NULL;
    if (!KERN_POINTER_VALID(saveto) || !KERN_POINTER_VALID(sb) || name == NULL) goto out;
    kstr = kstralloc(name);
    if (!KERN_POINTER_VALID(kstr)) goto out;
    ret = (int)kexec(function, saveto, sb, kstr, (kptr_t)subtype, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    if (KERN_POINTER_VALID(kstr)) kstrfree(kstr); kstr = KPTR_NULL;
    return ret;
}

int extension_add(kptr_t ext, kptr_t sb, const char *desc) {
    auto ret = -1;
    auto kstr = KPTR_NULL;
    if (!KERN_POINTER_VALID(ext) || !KERN_POINTER_VALID(sb) || desc == NULL) goto out;
    auto const function = getoffset(extension_add);
    if (!KERN_POINTER_VALID(function)) goto out;
    kstr = kstralloc(desc);
    if (!KERN_POINTER_VALID(kstr)) goto out;
    ret = (int)kexec(function, ext, sb, kstr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    if (KERN_POINTER_VALID(kstr)) kstrfree(kstr); kstr = KPTR_NULL;
    return ret;
}

void extension_release(kptr_t ext) {
    if (!KERN_POINTER_VALID(ext)) goto out;
    auto const function = getoffset(extension_release);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, ext, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void extension_destroy(kptr_t ext) {
    if (!KERN_POINTER_VALID(ext)) goto out;
    auto const function = getoffset(extension_destroy);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, ext, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

bool set_file_extension(kptr_t sandbox, const char *exc_key, const char *path) {
    auto ret = false;
    auto ext_kptr = KPTR_NULL;
    auto ext = KPTR_NULL;
    if (!KERN_POINTER_VALID(sandbox) || exc_key == NULL || path == NULL) goto out;
    ext_kptr = smalloc(sizeof(kptr_t));
    if (!KERN_POINTER_VALID(ext_kptr)) goto out;
    auto const ret_extension_create_file = extension_create_file(ext_kptr, sandbox, path, strlen(path), 0);
    if (ret_extension_create_file != 0) goto out;
    ext = ReadKernel64(ext_kptr);
    if (!KERN_POINTER_VALID(ext)) goto out;
    auto const ret_extension_add = extension_add(ext, sandbox, exc_key);
    if (ret_extension_add != 0) goto out;
    ret = true;
out:;
    if (KERN_POINTER_VALID(ext)) extension_release(ext_kptr); ext = KPTR_NULL;
    if (KERN_POINTER_VALID(ext_kptr)) sfree(ext_kptr); ext_kptr = KPTR_NULL;
    return ret;
}

bool set_mach_extension(kptr_t sandbox, const char *exc_key, const char *name) {
    auto ret = false;
    auto ext_kptr = KPTR_NULL;
    auto ext = KPTR_NULL;
    if (!KERN_POINTER_VALID(sandbox) || exc_key == NULL || name == NULL) goto out;
    ext_kptr = smalloc(sizeof(kptr_t));
    if (!KERN_POINTER_VALID(ext_kptr)) goto out;
    auto const ret_extension_create_mach = extension_create_mach(ext_kptr, sandbox, name, 0);
    if (ret_extension_create_mach != 0) goto out;
    ext = ReadKernel64(ext_kptr);
    if (!KERN_POINTER_VALID(ext)) goto out;
    auto const ret_extension_add = extension_add(ext, sandbox, exc_key);
    if (ret_extension_add != 0) goto out;
    ret = true;
out:;
    if (KERN_POINTER_VALID(ext)) extension_release(ext_kptr); ext = KPTR_NULL;
    if (KERN_POINTER_VALID(ext_kptr)) sfree(ext_kptr); ext_kptr = KPTR_NULL;
    return ret;
}

kptr_t proc_find(pid_t pid) {
    auto ret = KPTR_NULL;
    auto const function = getoffset(proc_find);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = kexec(function, (kptr_t)pid, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    return ret;
}

void proc_rele(kptr_t proc) {
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const function = getoffset(proc_rele);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void proc_lock(kptr_t proc) {
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const function = getoffset(proc_lock);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void proc_unlock(kptr_t proc) {
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const function = getoffset(proc_unlock);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void proc_ucred_lock(kptr_t proc) {
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const function = getoffset(proc_ucred_lock);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void proc_ucred_unlock(kptr_t proc) {
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const function = getoffset(proc_ucred_unlock);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, proc, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void vnode_lock(kptr_t vp) {
    if (!KERN_POINTER_VALID(vp)) goto out;
    auto const function = getoffset(vnode_lock);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, vp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void vnode_unlock(kptr_t vp) {
    if (!KERN_POINTER_VALID(vp)) goto out;
    auto const function = getoffset(vnode_unlock);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, vp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void mount_lock(kptr_t mp) {
    if (!KERN_POINTER_VALID(mp)) goto out;
    auto const function = getoffset(mount_lock);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, mp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void mount_unlock(kptr_t mp) {
    if (!KERN_POINTER_VALID(mp)) goto out;
    auto const function = getoffset(mount_unlock);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, mp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void task_set_platform_binary(kptr_t task, boolean_t is_platform) {
    if (!KERN_POINTER_VALID(task)) goto out;
    auto const function = getoffset(task_set_platform_binary);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, task, (kptr_t)is_platform, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

int chgproccnt(uid_t uid, int diff) {
    auto ret = -1;
    auto const function = getoffset(chgproccnt);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = (int)kexec(function, (kptr_t)uid, (kptr_t)diff, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

void kauth_cred_ref(kptr_t cred) {
    if (!KERN_POINTER_VALID(cred)) goto out;
    auto const function = getoffset(kauth_cred_ref);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, cred, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void kauth_cred_unref(kptr_t cred) {
    if (!KERN_POINTER_VALID(cred)) goto out;
    auto const function = getoffset(kauth_cred_unref);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, cred, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

kptr_t vfs_context_current() {
    auto ret = KPTR_NULL;
    auto const function = getoffset(vfs_context_current);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = kexec(function, (kptr_t)1, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
out:;
    return ret;
}

int vnode_lookup(const char *path, int flags, kptr_t *vpp, kptr_t ctx) {
    auto ret = -1;
    auto kstr = KPTR_NULL;
    auto vpp_kptr_size = SIZE_NULL;
    auto vpp_kptr = KPTR_NULL;
    if (path == NULL || vpp == NULL || !KERN_POINTER_VALID(ctx)) goto out;
    auto const function = getoffset(vnode_lookup);
    if (!KERN_POINTER_VALID(function)) goto out;
    kstr = kstralloc(path);
    if (!KERN_POINTER_VALID(kstr)) goto out;
    vpp_kptr_size = sizeof(kptr_t);
    vpp_kptr = kmem_alloc(vpp_kptr_size);
    if (!KERN_POINTER_VALID(vpp_kptr)) goto out;
    ret = (int)kexec(function, kstr, (kptr_t)flags, vpp_kptr, ctx, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (!rkbuffer(vpp_kptr, vpp, vpp_kptr_size)) goto out;
out:;
    if (KERN_POINTER_VALID(kstr)) kstrfree(kstr); kstr = KPTR_NULL;
    if (KERN_POINTER_VALID(vpp_kptr)) kmem_free(vpp_kptr, vpp_kptr_size); vpp_kptr = KPTR_NULL;
    return ret;
}

int vnode_put(kptr_t vp) {
    auto ret = -1;
    if (!KERN_POINTER_VALID(vp)) goto out;
    auto const function = getoffset(vnode_put);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = (int)kexec(function, vp, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

bool OSDictionary_SetItem(kptr_t OSDictionary, const char *key, kptr_t val) {
    auto ret = false;
    auto kstr = KPTR_NULL;
    if (!KERN_POINTER_VALID(OSDictionary) || key == NULL || !KERN_POINTER_VALID(val)) goto out;
    auto const function = OSObjectFunc(OSDictionary, off_OSDictionary_SetObjectWithCharP);
    if (!KERN_POINTER_VALID(function)) goto out;
    kstr = kstralloc(key);
    if (!KERN_POINTER_VALID(kstr)) goto out;
    ret = (bool)kexec(function, OSDictionary, kstr, val, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    if (KERN_POINTER_VALID(kstr)) kstrfree(kstr); kstr = KPTR_NULL;
    return ret;
}

kptr_t OSDictionary_GetItem(kptr_t OSDictionary, const char *key) {
    auto ret = KPTR_NULL;
    auto kstr = KPTR_NULL;
    if (!KERN_POINTER_VALID(OSDictionary) || key == NULL) goto out;
    auto const function = OSObjectFunc(OSDictionary, off_OSDictionary_GetObjectWithCharP);
    if (!KERN_POINTER_VALID(function)) goto out;
    kstr = kstralloc(key);
    if (!KERN_POINTER_VALID(kstr)) goto out;
    ret = kexec(function, OSDictionary, kstr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL && (ret>>32) == KPTR_NULL) ret = zm_fix_addr(ret);
    if (!KERN_POINTER_VALID(ret)) goto out;
out:;
    if (KERN_POINTER_VALID(kstr)) kstrfree(kstr); kstr = KPTR_NULL;
    return ret;
}

bool OSDictionary_Merge(kptr_t OSDictionary, kptr_t OSDictionary2) {
    auto ret = false;
    if (!KERN_POINTER_VALID(OSDictionary) || !KERN_POINTER_VALID(OSDictionary2)) goto out;
    auto const function = OSObjectFunc(OSDictionary, off_OSDictionary_Merge);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = (bool)kexec(function, OSDictionary, OSDictionary2, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

uint32_t OSDictionary_ItemCount(kptr_t OSDictionary) {
    auto ret = (uint32_t)0;
    if (!KERN_POINTER_VALID(OSDictionary)) goto out;
    ret = ReadKernel32(OSDictionary + 20);
out:;
    return ret;
}

kptr_t OSDictionary_ItemBuffer(kptr_t OSDictionary) {
    auto ret = KPTR_NULL;
    if (!KERN_POINTER_VALID(OSDictionary)) goto out;
    ret = ReadKernel64(OSDictionary + 32);
out:;
    return ret;
}

kptr_t OSDictionary_ItemKey(kptr_t buffer, uint32_t idx) {
    auto ret = KPTR_NULL;
    if (!KERN_POINTER_VALID(buffer)) goto out;
    ret = ReadKernel64(buffer + 16 * idx);
out:;
    return ret;
}

kptr_t OSDictionary_ItemValue(kptr_t buffer, uint32_t idx) {
    auto ret = KPTR_NULL;
    if (!KERN_POINTER_VALID(buffer)) goto out;
    ret = ReadKernel64(buffer + 16 * idx + 8);
out:;
    return ret;
}

bool OSArray_Merge(kptr_t OSArray, kptr_t OSArray2) {
    auto ret = false;
    if (!KERN_POINTER_VALID(OSArray) || !KERN_POINTER_VALID(OSArray2)) goto out;
    auto const function = OSObjectFunc(OSArray, off_OSArray_Merge);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = (bool)kexec(function, OSArray, OSArray2, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

kptr_t OSArray_GetObject(kptr_t OSArray, uint32_t idx) {
    auto ret = KPTR_NULL;
    if (!KERN_POINTER_VALID(OSArray)) goto out;
    auto const function = OSObjectFunc(OSArray, off_OSArray_GetObject);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = kexec(OSArray, idx, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
    if (!KERN_POINTER_VALID(ret)) goto out;
out:;
    return ret;
}

void OSArray_RemoveObject(kptr_t OSArray, uint32_t idx) {
    if (!KERN_POINTER_VALID(OSArray)) goto out;
    auto const function = OSObjectFunc(OSArray, off_OSArray_RemoveObject);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, OSArray, idx, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

uint32_t OSArray_ItemCount(kptr_t OSArray) {
    auto ret = (uint32_t)0;
    if (!KERN_POINTER_VALID(OSArray)) goto out;
    ret = ReadKernel32(OSArray + 0x14);
out:;
    return ret;
}

kptr_t OSArray_ItemBuffer(kptr_t OSArray) {
    auto ret = KPTR_NULL;
    if (!KERN_POINTER_VALID(OSArray)) goto out;
    ret = ReadKernel64(OSArray + 32);
out:;
    return ret;
}

kptr_t OSObjectFunc(kptr_t OSObject, uint32_t off) {
    auto ret = KPTR_NULL;
    if (!KERN_POINTER_VALID(OSObject)) goto out;
    auto vtable = ReadKernel64(OSObject);
    if (vtable != KPTR_NULL) vtable = kernel_xpacd(vtable);
    if (!KERN_POINTER_VALID(vtable)) goto out;
    ret = ReadKernel64(vtable + off);
    if (ret != KPTR_NULL) ret = kernel_xpaci(ret);
    if (!KERN_POINTER_VALID(ret)) goto out;
out:;
    return ret;
}

void OSObject_Release(kptr_t OSObject) {
    if (!KERN_POINTER_VALID(OSObject)) goto out;
    auto const function = OSObjectFunc(OSObject, off_OSObject_Release);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, OSObject, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

void OSObject_Retain(kptr_t OSObject) {
    if (!KERN_POINTER_VALID(OSObject)) goto out;
    auto const function = OSObjectFunc(OSObject, off_OSObject_Retain);
    if (!KERN_POINTER_VALID(function)) goto out;
    kexec(function, OSObject, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
}

uint32_t OSObject_GetRetainCount(kptr_t OSObject) {
    auto ret = (uint32_t)0;
    if (!KERN_POINTER_VALID(OSObject)) goto out;
    auto const function = OSObjectFunc(OSObject, off_OSObject_GetRetainCount);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = (uint32_t)kexec(function, OSObject, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

uint32_t OSString_GetLength(kptr_t OSString) {
    auto ret = (uint32_t)0;
    if (!KERN_POINTER_VALID(OSString)) goto out;
    auto const function = OSObjectFunc(OSString, off_OSString_GetLength);
    if (!KERN_POINTER_VALID(function)) goto out;
    ret = (uint32_t)kexec(function, OSString, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
out:;
    return ret;
}

kptr_t OSString_CStringPtr(kptr_t OSString) {
    auto ret = KPTR_NULL;
    if (!KERN_POINTER_VALID(OSString)) goto out;
    ret = ReadKernel64(OSString + 0x10);
out:;
    return ret;
}

char *OSString_CopyString(kptr_t OSString) {
    auto ret = (char *)NULL;
    auto str = (char *)NULL;
    if (!KERN_POINTER_VALID(OSString)) goto out;
    auto const length = OSString_GetLength(OSString);
    if (length <= 0) goto out;
    str = (char *)malloc(length + 1);
    if (str == NULL) goto out;
    str[length] = 0;
    auto const CStringPtr = OSString_CStringPtr(OSString);
    if (!KERN_POINTER_VALID(CStringPtr)) goto out;
    if (!rkbuffer(CStringPtr, str, length)) goto out;
    ret = strdup(str);
    if (ret == NULL) goto out;
out:;
    SafeFreeNULL(str);
    return ret;
}

kptr_t OSUnserializeXML(const char *buffer) {
    auto ret = KPTR_NULL;
    auto kstr = KPTR_NULL;
    if (buffer == NULL) goto out;
    auto const function = getoffset(osunserializexml);
    if (!KERN_POINTER_VALID(function)) goto out;
    kstr = kstralloc(buffer);
    if (!KERN_POINTER_VALID(kstr)) goto out;
    auto const error_kptr = KPTR_NULL;
    ret = kexec(function, kstr, error_kptr, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL, KPTR_NULL);
    if (ret != KPTR_NULL) ret = zm_fix_addr(ret);
    if (!KERN_POINTER_VALID(ret)) goto out;
out:;
    if (KERN_POINTER_VALID(kstr)) kstrfree(kstr); kstr = KPTR_NULL;
    return ret;
}

kptr_t get_exception_osarray(const char **exceptions) {
    auto exception_osarray = KPTR_NULL;
    auto xmlsize = (size_t)0x1000;
    auto len = SIZE_NULL;
    auto written = SIZE_NULL;
    auto ents = (char *)malloc(xmlsize);
    if (!ents) {
        return 0;
    }
    auto xmlused = sprintf(ents, "<array>");
    for (auto exception = exceptions; *exception; exception++) {
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
    auto itemCount = OSArray_ItemCount(present);
    auto itemBuffer = OSArray_ItemBuffer(present);
    auto bufferSize = 0x1000;
    auto bufferUsed = 0;
    auto arraySize = (itemCount + 1) * sizeof(char *);
    auto entitlements = (char **)malloc(arraySize + bufferSize);
    if (!entitlements) {
        return NULL;
    }
    entitlements[itemCount] = NULL;
    
    for (auto i = 0; i < itemCount; i++) {
        auto item = ReadKernel64(itemBuffer + (i * sizeof(kptr_t)));
        auto entitlementString = OSString_CopyString(item);
        if (!entitlementString) {
            SafeFreeNULL(entitlements);
            return NULL;
        }
        auto len = strlen(entitlementString) + 1;
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
    auto ret = KPTR_NULL;
    auto const symbol = getoffset(OSBoolean_True);
    if (!KERN_POINTER_VALID(symbol)) goto out;
    auto OSBool = ReadKernel64(symbol);
    if (!KERN_POINTER_VALID(OSBool)) goto out;
    if (!value) OSBool += sizeof(kptr_t);
    ret = OSBool;
out:;
    return ret;
}

bool entitle_process(kptr_t amfi_entitlements, const char *key, kptr_t val) {
    auto ret = false;
    if (!KERN_POINTER_VALID(amfi_entitlements) || key == NULL || !KERN_POINTER_VALID(val)) goto out;
    if (OSDictionary_GetItem(amfi_entitlements, key) == val) ret = true;
    if (!ret) ret = OSDictionary_SetItem(amfi_entitlements, key, val);
out:;
    return ret;
}

bool set_sandbox_exceptions(kptr_t sandbox, const char **exceptions) {
    auto ret = false;
    if (!KERN_POINTER_VALID(sandbox) || exceptions == NULL) goto out;
    for (auto exception = exceptions; *exception; exception++) {
        if (!set_file_extension(sandbox, FILE_EXC_KEY, *exception))
            ret = false;
    }
out:;
    return ret;
}

bool check_for_exception(char **current_exceptions, const char *exception) {
    auto ret = false;
    if (current_exceptions == NULL || exception == NULL) goto out;
    for (auto entitlement_string = current_exceptions; *entitlement_string && !ret; entitlement_string++) {
        auto ent = strdup(*entitlement_string);
        if (ent == NULL) goto out;
        auto lastchar = strlen(ent) - 1;
        if (ent[lastchar] == '/') ent[lastchar] = '\0';
        if (strcmp(ent, exception) == 0) {
            ret = true;
        }
        SafeFreeNULL(ent);
    }
out:;
    return ret;
}

bool set_amfi_exceptions(kptr_t amfi_entitlements, const char **exceptions) {
    auto ret = false;
    auto current_exceptions = (char **)NULL;
    if (!KERN_POINTER_VALID(amfi_entitlements) || exceptions == NULL) goto out;
    auto const present_exception_osarray = OSDictionary_GetItem(amfi_entitlements, FILE_EXC_KEY);
    if (present_exception_osarray == KPTR_NULL) {
        auto osarray = get_exception_osarray(exceptions);
        if (!KERN_POINTER_VALID(osarray)) goto out;
        ret = OSDictionary_SetItem(amfi_entitlements, FILE_EXC_KEY, osarray);
        OSObject_Release(osarray);
        goto out;
    }
    current_exceptions = copy_amfi_entitlements(present_exception_osarray);
    if (current_exceptions == NULL) goto out;
    for (auto exception = exceptions; *exception; exception++) {
        if (check_for_exception(current_exceptions, *exception)) {
            ret = true;
            continue;
        }
        const char *array[] = {*exception, NULL};
        auto osarray = get_exception_osarray(array);
        if (!KERN_POINTER_VALID(osarray)) continue;
        ret = OSArray_Merge(present_exception_osarray, osarray);
        OSObject_Release(osarray);
    }
out:;
    SafeFreeNULL(current_exceptions);
    return ret;
}

bool set_exceptions(kptr_t sandbox, kptr_t amfi_entitlements) {
    auto ret = false;
    if (KERN_POINTER_VALID(sandbox))
        if (!set_sandbox_exceptions(sandbox, abs_path_exceptions))
            goto out;
    if (KERN_POINTER_VALID(amfi_entitlements))
        if (!set_amfi_exceptions(amfi_entitlements, abs_path_exceptions))
            goto out;
    ret = true;
out:;
    return ret;
}

kptr_t get_amfi_entitlements(kptr_t cr_label) {
    auto amfi_entitlements = KPTR_NULL;
    if (!KERN_POINTER_VALID(cr_label)) goto out;
    amfi_entitlements = ReadKernel64(cr_label + 0x8);
    if (!KERN_POINTER_VALID(amfi_entitlements)) goto out;
out:;
    return amfi_entitlements;
}

kptr_t get_sandbox(kptr_t cr_label) {
    auto sandbox = KPTR_NULL;
    if (!KERN_POINTER_VALID(cr_label)) goto out;
    sandbox = ReadKernel64(cr_label + 0x8 + 0x8);
    if (!KERN_POINTER_VALID(sandbox)) goto out;
out:;
    return sandbox;
}

bool entitle_process_with_pid(pid_t pid, const char *key, kptr_t val) {
    auto ret = false;
    auto proc = KPTR_NULL;
    if (pid <= 0 || key == NULL || !KERN_POINTER_VALID(val)) goto out;
    proc = proc_find(pid);
    if (!KERN_POINTER_VALID(proc)) goto out;
    auto const proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    if (!KERN_POINTER_VALID(proc_ucred)) goto out;
    auto const cr_label = ReadKernel64(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
    if (!KERN_POINTER_VALID(cr_label)) goto out;
    auto const amfi_entitlements = get_amfi_entitlements(cr_label);
    if (!KERN_POINTER_VALID(cr_label)) goto out;
    if (!entitle_process(amfi_entitlements, key, val)) goto out;
    ret = true;
out:;
    if (KERN_POINTER_VALID(proc)) proc_rele(proc);
    return ret;
}

bool remove_memory_limit() {
    auto ret = false;
    auto const pid = getpid();
    auto const entitlement_key = "com.apple.private.memorystatus";
    auto const entitlement_val = OSBoolTrue;
    if (!KERN_POINTER_VALID(entitlement_val)) goto out;
    if (!entitle_process_with_pid(pid, entitlement_key, entitlement_val)) goto out;
    if (memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, pid, 0, NULL, 0) != ERR_SUCCESS) goto out;
    ret = true;
out:;
    return ret;
}

bool restore_kernel_task_port(task_t *out_kernel_task_port) {
    auto restored_kernel_task_port = false;
    auto kr = KERN_FAILURE;
    auto kernel_task_port = (task_t *)NULL;
    auto host = HOST_NULL;
    if (out_kernel_task_port == NULL) goto out;
    kernel_task_port = (task_t *)malloc(sizeof(task_t *));
    if (kernel_task_port == NULL) goto out;
    bzero(kernel_task_port, sizeof(task_t));
    host = mach_host_self();
    if (!MACH_PORT_VALID(host)) goto out;
    kr = task_for_pid(mach_task_self(), 0, kernel_task_port);
    if (kr != KERN_SUCCESS) kr = host_get_special_port(host, HOST_LOCAL_NODE, 4, kernel_task_port);
    if (kr != KERN_SUCCESS) goto out;
    if (!MACH_PORT_VALID(*kernel_task_port)) goto out;
    *out_kernel_task_port = *kernel_task_port;
    restored_kernel_task_port = true;
out:;
    SafeFreeNULL(kernel_task_port);
    if (MACH_PORT_VALID(host)) mach_port_deallocate(mach_task_self(), host); host = HOST_NULL;
    return restored_kernel_task_port;
}

bool restore_kernel_base(uint64_t *out_kernel_base, uint64_t *out_kernel_slide) {
    auto restored_kernel_base = false;
    auto kr = KERN_FAILURE;
    auto kernel_task_base = (kptr_t *)NULL;
    auto kernel_task_slide = (uint64_t *)NULL;
    auto task_dyld_info = (struct task_dyld_info *)NULL;
    auto task_dyld_info_count = (mach_msg_type_number_t *)NULL;
    if (out_kernel_base == NULL || out_kernel_slide == NULL) goto out;
    kernel_task_base = (kptr_t *)malloc(sizeof(kptr_t));
    if (kernel_task_base == NULL) goto out;
    bzero(kernel_task_base, sizeof(kptr_t));
    kernel_task_slide = (uint64_t *)malloc(sizeof(uint64_t));
    if (kernel_task_slide == NULL) goto out;
    bzero(kernel_task_slide, sizeof(uint64_t));
    task_dyld_info = (struct task_dyld_info *)malloc(sizeof(struct task_dyld_info));
    if (task_dyld_info == NULL) goto out;
    bzero(task_dyld_info, sizeof(struct task_dyld_info));
    task_dyld_info_count = (mach_msg_type_number_t *)malloc(sizeof(mach_msg_type_number_t));
    if (task_dyld_info_count == NULL) goto out;
    bzero(task_dyld_info_count, sizeof(mach_msg_type_number_t));
    *task_dyld_info_count = TASK_DYLD_INFO_COUNT;
    kr = task_info(tfp0, TASK_DYLD_INFO, (task_info_t)task_dyld_info, task_dyld_info_count);
    if (kr != KERN_SUCCESS) goto out;
    if (task_dyld_info->all_image_info_size > MAX_KASLR_SLIDE) goto out;
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
    auto restored_kernel_offset_cache = false;
    auto kr = KERN_FAILURE;
    auto task_dyld_info = (struct task_dyld_info *)NULL;
    auto task_dyld_info_count = (mach_msg_type_number_t *)NULL;
    auto offset_cache_addr = KPTR_NULL;
    auto offset_cache_size_addr = KPTR_NULL;
    auto offset_cache_size = (size_t *)NULL;
    auto offset_cache_blob = (struct cache_blob *)NULL;
    task_dyld_info = (struct task_dyld_info *)malloc(sizeof(struct task_dyld_info));
    if (task_dyld_info == NULL) goto out;
    bzero(task_dyld_info, sizeof(struct task_dyld_info));
    task_dyld_info_count = (mach_msg_type_number_t *)malloc(sizeof(mach_msg_type_number_t));
    if (task_dyld_info_count == NULL) goto out;
    bzero(task_dyld_info_count, sizeof(mach_msg_type_number_t));
    offset_cache_size = (size_t *)malloc(sizeof(size_t));
    if (offset_cache_size == NULL) goto out;
    bzero(offset_cache_size, sizeof(size_t));
    *task_dyld_info_count = TASK_DYLD_INFO_COUNT;
    kr = task_info(tfp0, TASK_DYLD_INFO, (task_info_t)task_dyld_info, task_dyld_info_count);
    if (kr != KERN_SUCCESS) goto out;
    if (!KERN_POINTER_VALID(task_dyld_info->all_image_info_addr)) goto out;
    offset_cache_addr = task_dyld_info->all_image_info_addr;
    offset_cache_size_addr = offset_cache_addr + offsetof(struct cache_blob, size);
    if (!rkbuffer(offset_cache_size_addr, offset_cache_size, sizeof(*offset_cache_size))) goto out;
    offset_cache_blob = create_cache_blob(*offset_cache_size);
    if (offset_cache_blob == NULL) goto out;
    if (!rkbuffer(offset_cache_addr, offset_cache_blob, *offset_cache_size)) goto out;
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
    auto restored_file_offset_cache = false;
    auto offset_cache_file_name = (CFStringRef)NULL;
    auto offset_cache_file_url = (CFURLRef)NULL;
    auto offset_cache_file_data = (CFDataRef)NULL;
    auto offset_cache_property_list = (CFPropertyListRef)NULL;
    auto status = (Boolean)false;
    auto offset_kernel_base = KPTR_NULL;
    auto offset_kernel_slide = KPTR_NULL;
    if (offset_cache_file_path == NULL || out_kernel_base == NULL || out_kernel_slide == NULL) goto out;
    offset_cache_file_name = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, offset_cache_file_path, kCFStringEncodingUTF8, kCFAllocatorDefault);
    if (offset_cache_file_name == NULL) goto out;
    offset_cache_file_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, offset_cache_file_name, kCFURLPOSIXPathStyle, false);
    if (offset_cache_file_url == NULL) goto out;
    status = CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, offset_cache_file_url, &offset_cache_file_data, NULL, NULL, NULL);
    if (!status) goto out;
    offset_cache_property_list = CFPropertyListCreateWithData(kCFAllocatorDefault, offset_cache_file_data, kCFPropertyListImmutable, NULL, NULL);
    if (offset_cache_property_list == NULL) goto out;
    if (CFGetTypeID(offset_cache_property_list) != CFDictionaryGetTypeID()) goto out;
#define restore_offset(entry_name, out_offset) do { \
    auto value = CFDictionaryGetValue(offset_cache_property_list, CFSTR(entry_name)); \
    if (value == NULL) break; \
    auto string = CFStringGetCStringPtr((CFStringRef)value, kCFStringEncodingUTF8); \
    if (string == NULL) break; \
    auto offset = strtoull(string, NULL, 16); \
    if (!KERN_POINTER_VALID(offset)) break; \
    out_offset = offset; \
} while (false)
#define restore_and_set_offset(entry_name, offset_name) do { \
    auto restored_offset = KPTR_NULL; \
    restore_offset(entry_name, restored_offset); \
    set_offset(offset_name, restored_offset); \
} while (false)
    restore_offset("KernelBase", offset_kernel_base);
    restore_offset("KernelSlide", offset_kernel_slide);
    restore_and_set_offset("TrustChain", "trustcache");
    restore_and_set_offset("OSBooleanTrue", "OSBooleanTrue");
    restore_and_set_offset("OSBooleanFalse", "OSBooleanFalse");
    restore_and_set_offset("OSUnserializeXML", "osunserializexml");
    restore_and_set_offset("Smalloc", "smalloc");
    restore_and_set_offset("AddRetGadget", "add_x0_x0_0x40_ret");
    restore_and_set_offset("ZoneMapOffset", "zone_map_ref");
    restore_and_set_offset("VfsContextCurrent", "vfs_context_current");
    restore_and_set_offset("VnodeLookup", "vnode_lookup");
    restore_and_set_offset("VnodePut", "vnode_put");
    restore_and_set_offset("KernelTask", "kernel_task");
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
    found_offsets = true;
    restored_file_offset_cache = true;
out:;
    CFSafeReleaseNULL(offset_cache_file_url);
    CFSafeReleaseNULL(offset_cache_file_data);
    CFSafeReleaseNULL(offset_cache_property_list);
    return restored_file_offset_cache;
}

bool convert_port_to_task_port(mach_port_t port, kptr_t space, kptr_t task_kaddr) {
    auto ret = false;
    if (!MACH_PORT_VALID(port) || !KERN_POINTER_VALID(space) || !KERN_POINTER_VALID(task_kaddr)) goto out;
    auto const port_kaddr = get_address_of_port(getpid(), port);
    if (!KERN_POINTER_VALID(port_kaddr)) goto out;
    if (!WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_BITS_ACTIVE | IKOT_TASK)) goto out;
    if (!WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d)) goto out;
    if (!WriteKernel32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d)) goto out;
    if (!WriteKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space)) goto out;
    if (!WriteKernel64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr)) goto out;
    auto const task_port_addr = task_self_addr();
    if (!KERN_POINTER_VALID(task_port_addr)) goto out;
    auto const task_addr = ReadKernel64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    if (!KERN_POINTER_VALID(task_addr)) goto out;
    auto const itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    if (!KERN_POINTER_VALID(itk_space)) goto out;
    auto const is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    if (!KERN_POINTER_VALID(is_table)) goto out;
    auto bits = ReadKernel32(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)) + koffset(KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS));
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    if (!WriteKernel32(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)) + koffset(KSTRUCT_OFFSET_IPC_ENTRY_IE_BITS), bits)) goto out;
    ret = true;
out:;
    return ret;
}

kptr_t make_fake_task(kptr_t vm_map) {
    auto ret = KPTR_NULL;
    auto fake_task_size = SIZE_NULL;
    auto fake_task_kaddr = KPTR_NULL;
    auto fake_task = NULL;
    if (!KERN_POINTER_VALID(vm_map)) goto out;
    fake_task_size = 0x1000;
    fake_task_kaddr = kmem_alloc(fake_task_size);
    if (!KERN_POINTER_VALID(fake_task_kaddr)) goto out;
    fake_task = malloc(fake_task_size);
    if (fake_task == NULL) goto out;
    memset(fake_task, 0, fake_task_size);
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d;
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    if (!wkbuffer(fake_task_kaddr, fake_task, fake_task_size)) goto out;
    ret = fake_task_kaddr;
out:;
    if (!KERN_POINTER_VALID(ret) && KERN_POINTER_VALID(fake_task_kaddr)) kmem_free(fake_task_kaddr, fake_task_size); fake_task_kaddr = KPTR_NULL;
    SafeFreeNULL(fake_task);
    return ret;
}

bool make_port_fake_task_port(mach_port_t port, kptr_t task_kaddr) {
    auto ret = false;
    if (!MACH_PORT_VALID(port) || !KERN_POINTER_VALID(task_kaddr)) goto out;
    auto const space = ipc_space_kernel();
    if (!KERN_POINTER_VALID(space)) goto out;
    if (!convert_port_to_task_port(port, space, task_kaddr)) goto out;
    ret = true;
out:;
    return ret;
}

bool set_hsp4(task_t port) {
    auto ret = false;
    auto host = HOST_NULL;
    auto kr = KERN_FAILURE;
    if (!MACH_PORT_VALID(port)) goto out;
    host = mach_host_self();
    if (!MACH_PORT_VALID(host)) goto out;
    auto const sizeof_task = 0x1000;
    auto const kernel_task_offset = getoffset(kernel_task);
    if (!KERN_POINTER_VALID(kernel_task_offset)) goto out;
    auto const kernel_task_addr = ReadKernel64(kernel_task_offset);
    if (!KERN_POINTER_VALID(kernel_task_addr)) goto out;
    auto zm_fake_task_port = TASK_NULL;
    auto km_fake_task_port = TASK_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    if (kr != KERN_SUCCESS) goto out;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    if (kr != KERN_SUCCESS) goto out;
    auto const zone_map_offset = getoffset(zone_map_ref);
    if (!KERN_POINTER_VALID(zone_map_offset)) goto out;
    auto const zone_map = ReadKernel64(zone_map_offset);
    if (!KERN_POINTER_VALID(zone_map)) goto out;
    auto const kernel_map = ReadKernel64(kernel_task_addr + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    if (!KERN_POINTER_VALID(kernel_map)) goto out;
    auto const zm_fake_task_addr = make_fake_task(zone_map);
    if (!KERN_POINTER_VALID(zm_fake_task_addr)) goto out;
    auto const km_fake_task_addr = make_fake_task(kernel_map);
    if (!KERN_POINTER_VALID(km_fake_task_addr)) goto out;
    if (!make_port_fake_task_port(zm_fake_task_port, zm_fake_task_addr)) goto out;
    if (!make_port_fake_task_port(km_fake_task_port, km_fake_task_addr)) goto out;
    km_fake_task_port = zm_fake_task_port;
    auto cur = VM_PROT_NONE, max = VM_PROT_NONE;
    auto remapped_task_addr = KPTR_NULL;
    kr = mach_vm_remap(km_fake_task_port, &remapped_task_addr, sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, zm_fake_task_port, kernel_task_addr, 0, &cur, &max, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) goto out;
    if (remapped_task_addr == kernel_task_addr) goto out;
    kr = mach_vm_wire(host, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) goto out;
    const auto pid = getpid();
    auto const port_addr = get_address_of_port(pid, port);
    if (!KERN_POINTER_VALID(port_addr)) goto out;
    if (!make_port_fake_task_port(port, remapped_task_addr)) goto out;
    if (ReadKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) != remapped_task_addr) goto out;
    auto const host_priv_addr = get_address_of_port(pid, host);
    if (!KERN_POINTER_VALID(host_priv_addr)) goto out;
    auto const realhost_addr = ReadKernel64(host_priv_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    if (!KERN_POINTER_VALID(realhost_addr)) goto out;
    auto const slot = 4;
    if (!WriteKernel64(realhost_addr + koffset(KSTRUCT_OFFSET_HOST_SPECIAL) + slot * sizeof(kptr_t), port_addr)) goto out;
    ret = true;
out:;
    if (MACH_PORT_VALID(host)) mach_port_deallocate(mach_task_self(), host); host = HOST_NULL;
    return ret;
}

kptr_t get_vnode_for_path(const char *path) {
    auto ret = KPTR_NULL;
    auto vpp = (kptr_t *)NULL;
    auto const vfs_context = vfs_context_current();
    if (!KERN_POINTER_VALID(vfs_context)) goto out;
    vpp = (kptr_t *)malloc(sizeof(kptr_t));
    if (vpp == NULL) goto out;
    bzero(vpp, sizeof(kptr_t));
    if (vnode_lookup(path, O_RDONLY, vpp, vfs_context) != 0) goto out;
    auto const vnode = *vpp;
    if (!KERN_POINTER_VALID(vnode)) goto out;
    ret = vnode;
out:;
    SafeFreeNULL(vpp);
    return ret;
}

kptr_t get_vnode_for_snapshot(int fd, char *name) {
    auto ret = KPTR_NULL;
    auto snap_vnode = KPTR_NULL;
    auto rvpp_ptr = KPTR_NULL;
    auto sdvpp_ptr = KPTR_NULL;
    auto ndp_buf = KPTR_NULL;
    auto sdvpp = KPTR_NULL;
    auto snap_meta_ptr = KPTR_NULL;
    auto old_name_ptr = KPTR_NULL;
    auto ndp_old_name = KPTR_NULL;
    rvpp_ptr = kmem_alloc(sizeof(kptr_t));
    if (!KERN_POINTER_VALID(rvpp_ptr)) goto out;
    sdvpp_ptr = kmem_alloc(sizeof(kptr_t));
    if (!KERN_POINTER_VALID(sdvpp_ptr)) goto out;
    ndp_buf = kmem_alloc(816);
    if (!KERN_POINTER_VALID(ndp_buf)) goto out;
    auto const vfs_context = vfs_context_current();
    if (!KERN_POINTER_VALID(vfs_context)) goto out;
    if (kexec(getoffset(vnode_get_snapshot), fd, rvpp_ptr, sdvpp_ptr, (kptr_t)name, ndp_buf, 2, vfs_context) != 0) goto out;
    sdvpp = ReadKernel64(sdvpp_ptr);
    if (!KERN_POINTER_VALID(sdvpp_ptr)) goto out;
    auto const sdvpp_v_mount = ReadKernel64(sdvpp + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
    if (!KERN_POINTER_VALID(sdvpp_v_mount)) goto out;
    auto const sdvpp_v_mount_mnt_data = ReadKernel64(sdvpp_v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_DATA));
    if (!KERN_POINTER_VALID(sdvpp_v_mount_mnt_data)) goto out;
    snap_meta_ptr = kmem_alloc(sizeof(kptr_t));
    if (!KERN_POINTER_VALID(snap_meta_ptr)) goto out;
    old_name_ptr = kmem_alloc(sizeof(kptr_t));
    if (!KERN_POINTER_VALID(old_name_ptr)) goto out;
    ndp_old_name = ReadKernel64(ndp_buf + 336 + 40);
    if (!KERN_POINTER_VALID(ndp_old_name)) goto out;
    auto const ndp_old_name_len = ReadKernel32(ndp_buf + 336 + 48);
    if (kexec(getoffset(fs_lookup_snapshot_metadata_by_name_and_return_name), sdvpp_v_mount_mnt_data, ndp_old_name, ndp_old_name_len, snap_meta_ptr, old_name_ptr, 0, 0) != 0) goto out;
    auto const snap_meta = ReadKernel64(snap_meta_ptr);
    if (!KERN_POINTER_VALID(snap_meta)) goto out;
    snap_vnode = kexec(getoffset(apfs_jhash_getvnode), sdvpp_v_mount_mnt_data, ReadKernel32(sdvpp_v_mount_mnt_data + 440), ReadKernel64(snap_meta + 8), 1, 0, 0, 0);
    if (snap_vnode != KPTR_NULL) snap_vnode = zm_fix_addr(snap_vnode);
    if (!KERN_POINTER_VALID(snap_vnode)) goto out;
    ret = snap_vnode;
out:
    if (KERN_POINTER_VALID(sdvpp)) vnode_put(sdvpp); sdvpp = KPTR_NULL;
    if (KERN_POINTER_VALID(sdvpp_ptr)) kmem_free(sdvpp_ptr, sizeof(kptr_t)); sdvpp_ptr = KPTR_NULL;
    if (KERN_POINTER_VALID(ndp_buf)) kmem_free(ndp_buf, 816); ndp_buf = KPTR_NULL;
    if (KERN_POINTER_VALID(snap_meta_ptr)) kmem_free(snap_meta_ptr, sizeof(kptr_t)); snap_meta_ptr = KPTR_NULL;
    if (KERN_POINTER_VALID(old_name_ptr)) kmem_free(old_name_ptr, sizeof(kptr_t)); old_name_ptr = KPTR_NULL;
    return ret;
}

bool set_kernel_task_info() {
    auto ret = false;
    auto kr = KERN_FAILURE;
    auto task_dyld_info = (struct task_dyld_info *)NULL;
    auto task_dyld_info_count = (mach_msg_type_number_t *)NULL;
    auto cache = (struct cache_blob *)NULL;
    auto cache_size = SIZE_NULL;
    auto kernel_cache_blob = KPTR_NULL;
    task_dyld_info = (struct task_dyld_info *)malloc(sizeof(struct task_dyld_info));
    if (task_dyld_info == NULL) goto out;
    bzero(task_dyld_info, sizeof(struct task_dyld_info));
    task_dyld_info_count = (mach_msg_type_number_t *)malloc(sizeof(mach_msg_type_number_t));
    if (task_dyld_info_count == NULL) goto out;
    bzero(task_dyld_info_count, sizeof(mach_msg_type_number_t));
    *task_dyld_info_count = TASK_DYLD_INFO_COUNT;
    auto const kernel_task_offset = getoffset(kernel_task);
    if (!KERN_POINTER_VALID(kernel_task_offset)) goto out;
    auto const kernel_task_addr = ReadKernel64(kernel_task_offset);
    if (!KERN_POINTER_VALID(kernel_task_addr)) goto out;
    kr = task_info(tfp0, TASK_DYLD_INFO, (task_info_t)task_dyld_info, task_dyld_info_count);
    if (kr != KERN_SUCCESS) goto out;
    if (!KERN_POINTER_VALID(task_dyld_info->all_image_info_addr) && task_dyld_info->all_image_info_addr != kernel_base && task_dyld_info->all_image_info_addr > kernel_base) {
        auto const blob_size = ReadKernel32(task_dyld_info->all_image_info_addr + offsetof(struct cache_blob, size));
        if (blob_size <= 0) goto out;
        auto blob = create_cache_blob(blob_size);
        if (blob == NULL) goto out;
        merge_cache_blob(blob); // Adds any entries that are in kernel but we don't have
        SafeFreeNULL(blob);
        if (!kmem_free(task_dyld_info->all_image_info_addr, blob_size)) goto out; // Free old offset cache - didn't bother comparing because it's faster to just replace it if it's the same
    }
    cache_size = export_cache_blob(&cache);
    kernel_cache_blob = kmem_alloc_wired(cache_size);
    if (!KERN_POINTER_VALID(kernel_cache_blob)) goto out;
    blob_rebase(cache, (kptr_t)cache, kernel_cache_blob);
    if (!wkbuffer(kernel_cache_blob, cache, cache_size)) goto out;
    if (!WriteKernel64(kernel_task_addr + koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_ADDR), kernel_cache_blob)) goto out;
    if (!WriteKernel64(kernel_task_addr + koffset(KSTRUCT_OFFSET_TASK_ALL_IMAGE_INFO_SIZE), kernel_slide)) goto out;
    bzero(task_dyld_info, sizeof(struct task_dyld_info));
    kr = task_info(tfp0, TASK_DYLD_INFO, (task_info_t)task_dyld_info, task_dyld_info_count);
    if (kr != KERN_SUCCESS) goto out;
    if (task_dyld_info->all_image_info_addr != kernel_cache_blob || task_dyld_info->all_image_info_size != kernel_slide) goto out;
    ret = true;
out:;
    if (!ret && KERN_POINTER_VALID(kernel_cache_blob)) kmem_free(kernel_cache_blob, cache_size); kernel_cache_blob = KPTR_NULL;
    SafeFreeNULL(task_dyld_info);
    SafeFreeNULL(task_dyld_info_count);
    SafeFreeNULL(cache);
    return ret;
}

bool analyze_pid(pid_t pid,
                 kptr_t *out_proc,
                 kptr_t *out_proc_ucred,
                 kptr_t *out_cr_label,
                 kptr_t *out_amfi_entitlements,
                 kptr_t *out_sandbox,
                 char **out_path,
                 int *out_file_is_setuid,
                 int *out_file_is_setgid,
                 int *out_file_uid,
                 int *out_file_gid,
                 int *out_csflags,
                 int *out_is_platform_application) {
    bool ret = false;
    auto proc = KPTR_NULL;
    auto proc_ucred = KPTR_NULL;
    auto cr_label = KPTR_NULL;
    auto amfi_entitlements = KPTR_NULL;
    auto sandbox = KPTR_NULL;
    auto path = NULL;
    auto file_is_setuid = false;
    auto file_is_setgid = false;
    auto file_uid = 0;
    auto file_gid = 0;
    auto csflags = 0;
    auto is_platform_application = false;
    auto statbuf = (struct stat *)NULL;
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
                    sandbox = get_sandbox(sandbox);
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
            statbuf = (struct stat *)malloc(sizeof(struct stat));
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
    auto ret = true;
    auto proc = KPTR_NULL;
    auto proc_ucred = KPTR_NULL;
    auto amfi_entitlements = KPTR_NULL;
    auto sandbox = KPTR_NULL;
    auto is_setuid = false;
    auto is_setgid = false;
    auto file_uid = 0;
    auto file_gid = 0;
    auto csflags = 0;
    auto is_platform_application = false;
    if (!analyze_pid(pid,
                    &proc,
                    &proc_ucred,
                    NULL,
                    &amfi_entitlements,
                    &sandbox,
                    NULL,
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
        LOG("Enabling get-task-allow for pid %x", pid);
        if (!entitle_process(amfi_entitlements, "get-task-allow", OSBoolTrue)) {
            LOG("Unable to enable get-task-allow entitlement for pid %d", pid);
            ret = false;
        }
    }
    if (is_platform_application) {
        LOG("Setting task platform binary flag for pid %d", pid);
        if (!set_platform_binary(proc, true)) {
            LOG("Unable to set task platform binary flag for pid %d", pid);
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
    LOG("Setting exceptions for pid %x", pid);
    if (!set_exceptions(sandbox, amfi_entitlements)) {
        LOG("Unable to set exceptions for pid %d", pid);
        ret = false;
    }
out:;
    if (KERN_POINTER_VALID(proc)) proc_rele(proc);
    return ret;
}

bool unrestrict_process_with_task_port(task_t task_port) {
    auto ret = false;
    auto pid = 0;
    if (pid_for_task(task_port, &pid) != KERN_SUCCESS) goto out;
    if (!unrestrict_process(pid)) goto out;
    ret = true;
out:;
    return ret;
}

bool revalidate_process(pid_t pid) {
    auto ret = true;
    auto proc = KPTR_NULL;
    auto csflags = 0;
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
    if (OPT(CS_DEBUGGED)) {
        LOG("Setting codesign dynamic validity flag for pid %d", pid);
        if (!set_csflags(proc, CS_VALID, true)) {
            LOG("Unable to set codesign dynamic validity flag for pid %d", pid);
            ret = false;
        }
    }
out:;
    if (KERN_POINTER_VALID(proc)) proc_rele(proc);
    return ret;
}

bool revalidate_process_with_task_port(task_t task_port) {
    auto ret = false;
    auto pid = 0;
    if (pid_for_task(task_port, &pid) != KERN_SUCCESS) goto out;
    if (!revalidate_process(pid)) goto out;
    ret = true;
out:;
    return ret;
}
