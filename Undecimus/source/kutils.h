#ifndef kutils_h
#define kutils_h

#include <mach/mach.h>

uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_kernel_base(void);

uint64_t current_thread(void);

mach_port_t fake_host_priv(void);

uint64_t get_proc_ipc_table(uint64_t proc);
mach_port_t proc_to_task_port(uint64_t proc, uint64_t our_proc);

int message_size_for_kalloc_size(int kalloc_size);

#endif /* kutils_h */
