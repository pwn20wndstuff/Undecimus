#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <mach/task.h>

#include "remote_memory.h"

#include <common.h>

// no headers for these in iOS SDK:
extern kern_return_t mach_vm_allocate(
    vm_map_t target,
    mach_vm_address_t* address,
    mach_vm_size_t size,
    int flags);

extern kern_return_t mach_vm_deallocate(
    vm_map_t target,
    mach_vm_address_t address,
    mach_vm_size_t size);

extern kern_return_t mach_vm_read_overwrite(
    vm_map_t target_task,
    mach_vm_address_t address,
    mach_vm_size_t size,
    mach_vm_address_t data,
    mach_vm_size_t* outsize);

extern kern_return_t mach_vm_write(
    vm_map_t target_task,
    mach_vm_address_t address,
    vm_offset_t data,
    mach_msg_type_number_t dataCnt);

uint64_t
remote_alloc(mach_port_t task_port,
    uint64_t size)
{
    kern_return_t err;

    mach_vm_offset_t remote_addr = 0;
    mach_vm_size_t remote_size = (mach_vm_size_t)size;
    err = mach_vm_allocate(task_port, &remote_addr, remote_size, 1); // ANYWHERE
    if (err != KERN_SUCCESS) {
        LOG("unable to allocate buffer in remote process");
        return 0;
    }
    return (uint64_t)remote_addr;
}

void remote_free(mach_port_t task_port,
    uint64_t base,
    uint64_t size)
{
    kern_return_t err;

    err = mach_vm_deallocate(task_port, (mach_vm_address_t)base, (mach_vm_size_t)size);
    if (err != KERN_SUCCESS) {
        LOG("unabble to deallocate remote buffer");
        return;
    }
    return;
}

uint64_t
alloc_and_fill_remote_buffer(mach_port_t task_port,
    uint64_t local_address,
    uint64_t length)
{
    kern_return_t err;

    uint64_t remote_address = remote_alloc(task_port, length);

    err = mach_vm_write(task_port, remote_address, (mach_vm_offset_t)local_address, (mach_msg_type_number_t)length);
    if (err != KERN_SUCCESS) {
        LOG("unable to write to remote memory");
        return 0;
    }

    return remote_address;
}

void remote_read_overwrite(mach_port_t task_port,
    uint64_t remote_address,
    uint64_t local_address,
    uint64_t length)
{
    kern_return_t err;

    mach_vm_size_t outsize = 0;
    err = mach_vm_read_overwrite(task_port, (mach_vm_address_t)remote_address, (mach_vm_size_t)length, (mach_vm_address_t)local_address, &outsize);
    if (err != KERN_SUCCESS) {
        LOG("remote read failed");
        return;
    }

    if (outsize != length) {
        LOG("remote read was short (expected %llx, got %llx", length, outsize);
        return;
    }
}

void remote_write(mach_port_t remote_task_port,
    uint64_t remote_address,
    uint64_t local_address,
    uint64_t length)
{
    kern_return_t err = mach_vm_write(remote_task_port,
        (mach_vm_address_t)remote_address,
        (vm_offset_t)local_address,
        (mach_msg_type_number_t)length);
    if (err != KERN_SUCCESS) {
        LOG("remote write failed: %s %x", mach_error_string(err), err);
        return;
    }
}
