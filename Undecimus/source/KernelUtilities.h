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
    kptr_t apfs_jhash_getvnode;
    kptr_t vnode_get_snapshot;
    kptr_t fs_lookup_snapshot_metadata_by_name_and_return_name;
    kptr_t pmap_load_trust_cache;
    kptr_t paciza_pointer__l2tp_domain_module_start;
    kptr_t paciza_pointer__l2tp_domain_module_stop;
    kptr_t l2tp_domain_inited;
    kptr_t sysctl__net_ppp_l2tp;
    kptr_t sysctl_unregister_oid;
    kptr_t mov_x0_x4__br_x5;
    kptr_t mov_x9_x0__br_x1;
    kptr_t mov_x10_x3__br_x6;
    kptr_t kernel_forge_pacia_gadget;
    kptr_t kernel_forge_pacda_gadget;
    kptr_t IOUserClient__vtable;
    kptr_t IORegistryEntry__getRegistryEntryID;
    kptr_t pmap_loaded_trust_caches;
} offsets_t;

extern offsets_t offs;
extern uint64_t kernel_base;
extern uint64_t kernel_slide;
extern uint64_t trust_chain;

extern uint64_t cached_task_self_addr;
extern bool found_offsets;

uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_kernel_base(void);

uint64_t current_thread(void);

mach_port_t fake_host_priv(void);

int message_size_for_kalloc_size(int kalloc_size);

uint64_t get_proc_struct_for_pid(pid_t pid);
uint64_t get_address_of_port(pid_t pid, mach_port_t port);
uint64_t get_kernel_cred_addr(void);
uint64_t give_creds_to_process_at_addr(uint64_t proc, uint64_t cred_addr);
void set_platform_binary(uint64_t proc, bool set);

uint64_t zm_fix_addr(uint64_t addr);

bool verify_tfp0(void);

int _pmap_load_trust_cache(uint64_t kernel_trust, size_t length);

#endif /* kutils_h */
