#ifndef kutils_h
#define kutils_h

#include <common.h>
#include <mach/mach.h>

#define SETOFFSET(offset, val) (offs.offset = val)
#define GETOFFSET(offset) offs.offset

typedef struct {
    kptr_t trustcache;
    kptr_t OSBoolean_True;
    kptr_t osunserializexml;
    kptr_t smalloc;
    kptr_t add_x0_x0_0x40_ret;
    kptr_t zone_map_ref;
    kptr_t vfs_context_current;
    kptr_t vnode_lookup;
    kptr_t vnode_put;
    kptr_t kernel_task;
    kptr_t shenanigans;
    kptr_t lck_mtx_lock;
    kptr_t lck_mtx_unlock;
    kptr_t strlen;
} offsets_t;

extern offsets_t offs;
extern uint64_t kernel_base;
extern uint64_t kernel_slide;

extern uint64_t cached_task_self_addr;

uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_kernel_base(void);

uint64_t current_thread(void);

mach_port_t fake_host_priv(void);

int message_size_for_kalloc_size(int kalloc_size);

uint64_t get_proc_struct_for_pid(pid_t pid);
uint64_t get_kernel_cred_addr(void);
uint64_t give_creds_to_process_at_addr(uint64_t proc, uint64_t cred_addr);
void set_platform_binary(uint64_t proc);

#endif /* kutils_h */
