#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>

#include <common.h>
#include <iokit.h>

#include "KernelMemory.h"
#include "KernelStructureOffsets.h"
#include "KernelUtilities.h"
#include "find_port.h"
#include "KernelExecution.h"

#define P_MEMSTAT_INTERNAL 0x00001000 /* Process is a system-critical-not-be-jetsammed process i.e. launchd */

#define CS_PLATFORM_BINARY 0x4000000 /* this is a platform binary */
#define CS_GET_TASK_ALLOW 0x0000004 /* has get-task-allow entitlement */

#define TF_PLATFORM 0x00000400 /* task is a platform binary */

#define IO_ACTIVE 0x80000000

#define IKOT_HOST 3
#define IKOT_HOST_PRIV 4

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
        if (!ISADDR(kernproc)) {
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
        if (!ISADDR(proc_struct_addr)) {
            LOG("failed to get proc_struct_addr!");
            return 0;
        }
    }
    if (task_addr == 0) {
        task_addr = ReadKernel64(proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_TASK));
        LOG("task_addr = " ADDR, task_addr);
        if (!ISADDR(task_addr)) {
            LOG("failed to get task_addr!");
            return 0;
        }
    }
    if (itk_space == 0) {
        itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
        LOG("itk_space = " ADDR, itk_space);
        if (!ISADDR(itk_space)) {
            LOG("failed to get itk_space!");
            return 0;
        }
    }
    if (is_table == 0) {
        is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
        LOG("is_table = " ADDR, is_table);
        if (!ISADDR(is_table)) {
            LOG("failed to get is_table!");
            return 0;
        }
    }
    uint64_t port_addr = ReadKernel64(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)));
    LOG("port_addr = " ADDR, port_addr);
    if (!ISADDR(port_addr)) {
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
        if (!ISADDR(kernel_proc_struct_addr)) {
            LOG("failed to get kernel_proc_struct_addr!");
            return 0;
        }
    }
    if (kernel_ucred_struct_addr == 0) {
        kernel_ucred_struct_addr = ReadKernel64(kernel_proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_UCRED));
        LOG("kernel_ucred_struct_addr = " ADDR, kernel_ucred_struct_addr);
        if (!ISADDR(kernel_ucred_struct_addr)) {
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
    if (!ISADDR(orig_creds)) {
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
    if (!ISADDR(task_struct_addr)) {
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

bool verify_tfp0() {
    size_t test_size = sizeof(uint64_t);
    uint64_t test_kptr = kmem_alloc(test_size);
    if (!ISADDR(test_kptr)) {
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

void vnode_lock(uint64_t vp) {
    kexecute(GETOFFSET(lck_mtx_lock), ReadKernel64(vp + koffset(KSTRUCT_OFFSET_VNODE_V_LOCK)), 0, 0, 0, 0, 0, 0);
}

void vnode_unlock(uint64_t vp) {
    kexecute(GETOFFSET(lck_mtx_unlock), ReadKernel64(vp + koffset(KSTRUCT_OFFSET_VNODE_V_LOCK)), 0, 0, 0, 0, 0, 0);
}

void mount_lock(uint64_t mp) {
    kexecute(GETOFFSET(lck_mtx_lock), ReadKernel64(mp + koffset(KSTRUCT_OFFSET_MOUNT_MNT_MLOCK)), 0, 0, 0, 0, 0, 0);
}

void mount_unlock(uint64_t mp) {
    kexecute(GETOFFSET(lck_mtx_unlock), ReadKernel64(mp + koffset(KSTRUCT_OFFSET_MOUNT_MNT_MLOCK)), 0, 0, 0, 0, 0, 0);
}
