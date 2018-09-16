#ifndef remote_memory_h
#define remote_memory_h

#include <stdio.h>
#include <stdint.h>

// allocate a buffer in the remote process
uint64_t
remote_alloc(mach_port_t task_port,
             uint64_t size);

// free a buffer in the remote process
void
remote_free(mach_port_t task_port,
            uint64_t base,
            uint64_t size);

// allocate a buffer in the remote process and fill it with the given contents
uint64_t
alloc_and_fill_remote_buffer(mach_port_t task_port,
                             uint64_t local_address,
                             uint64_t length);

// read from the remote address to the local address
// local address must be the address of a buffer at least length bytes in size
void
remote_read_overwrite(mach_port_t task_port,
                      uint64_t remote_address,
                      uint64_t local_address,
                      uint64_t length);

void
remote_write(mach_port_t remote_task_port,
             uint64_t remote_address,
             uint64_t local_address,
             uint64_t length);

#endif /* remote_memory_h */
