#ifndef kutils_h
#define kutils_h

#include <mach/mach.h>

extern uint64_t cached_task_self_addr;

uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_kernel_base(void);

uint64_t current_thread(void);

mach_port_t fake_host_priv(void);

uint64_t get_proc_ipc_table(uint64_t proc);
mach_port_t proc_to_task_port(uint64_t proc, uint64_t our_proc);

#endif /* kutils_h */
