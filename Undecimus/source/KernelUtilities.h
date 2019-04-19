#ifndef kutils_h
#define kutils_h

#include <common.h>
#include <mach/mach.h>
#include <offsetcache.h>

#define SETOFFSET(offset, val) set_offset(#offset, val)
#define GETOFFSET(offset) get_offset(#offset)

#define ISADDR(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)

extern uint64_t kernel_base;
extern uint64_t kernel_slide;

extern uint64_t cached_task_self_addr;
extern bool found_offsets;

uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_kernel_base(void);

uint64_t current_thread(void);

mach_port_t fake_host_priv(void);

int message_size_for_kalloc_size(int kalloc_size);

uint64_t get_kernel_proc_struct_addr(void);
void iterate_proc_list(void (^handler)(uint64_t, pid_t, bool *));
uint64_t get_proc_struct_for_pid(pid_t pid);
uint64_t get_address_of_port(pid_t pid, mach_port_t port);
uint64_t get_kernel_cred_addr(void);
uint64_t give_creds_to_process_at_addr(uint64_t proc, uint64_t cred_addr);
void set_platform_binary(uint64_t proc, bool set);

uint64_t zm_fix_addr(uint64_t addr);

bool verify_tfp0(void);

extern int (*pmap_load_trust_cache)(uint64_t kernel_trust, size_t length);
int _pmap_load_trust_cache(uint64_t kernel_trust, size_t length);

void set_host_type(host_t host, uint32_t type);
void export_tfp0(host_t host);
void unexport_tfp0(host_t host);

void set_csflags(uint64_t proc, uint32_t flags, bool value);
void set_cs_platform_binary(uint64_t proc, bool value);

bool execute_with_credentials(uint64_t proc, uint64_t credentials, void (^function)(void));

uint32_t get_proc_memstat_state(uint64_t proc);
void set_proc_memstat_state(uint64_t proc, uint32_t memstat_state);
void set_proc_memstat_internal(uint64_t proc, bool set);
bool get_proc_memstat_internal(uint64_t proc);
void vnode_lock(uint64_t vp);
void vnode_unlock(uint64_t vp);
void mount_lock(uint64_t mp);
void mount_unlock(uint64_t mp);

#endif /* kutils_h */
