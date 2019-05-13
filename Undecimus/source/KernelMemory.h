#ifndef KernelMemory_h
#define KernelMemory_h

#include <mach/mach.h>
#include <stdbool.h>
#include <common.h>

/***** mach_vm.h *****/
kern_return_t mach_vm_read(
    vm_map_t target_task,
    mach_vm_address_t address,
    mach_vm_size_t size,
    vm_offset_t* data,
    mach_msg_type_number_t* dataCnt);

kern_return_t mach_vm_write(
    vm_map_t target_task,
    mach_vm_address_t address,
    vm_offset_t data,
    mach_msg_type_number_t dataCnt);

kern_return_t mach_vm_read_overwrite(
    vm_map_t target_task,
    mach_vm_address_t address,
    mach_vm_size_t size,
    mach_vm_address_t data,
    mach_vm_size_t* outsize);

kern_return_t mach_vm_allocate(
    vm_map_t target,
    mach_vm_address_t* address,
    mach_vm_size_t size,
    int flags);

kern_return_t mach_vm_deallocate(
    vm_map_t target,
    mach_vm_address_t address,
    mach_vm_size_t size);

kern_return_t mach_vm_protect(
    vm_map_t target_task,
    mach_vm_address_t address,
    mach_vm_size_t size,
    boolean_t set_maximum,
    vm_prot_t new_protection);

kern_return_t mach_vm_remap(
    mach_port_name_t target,
    mach_vm_address_t *address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    mach_port_name_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance);

extern size_t kreads;
extern size_t kwrites;
extern mach_port_t tfp0;

size_t kread(kptr_t where, void* p, size_t size);
size_t kwrite(kptr_t where, const void* p, size_t size);

#define rk32(kaddr) ReadKernel32(kaddr)
#define rk64(kaddr) ReadKernel64(kaddr)
uint32_t ReadKernel32(kptr_t kaddr);
uint64_t ReadKernel64(kptr_t kaddr);

#define wk32(kaddr, val) WriteKernel32(kaddr, val)
#define wk64(kaddr, val) WriteKernel64(kaddr, val)
bool WriteKernel32(kptr_t kaddr, uint32_t val);
bool WriteKernel64(kptr_t kaddr, uint64_t val);

bool wkbuffer(kptr_t kaddr, void* buffer, size_t length);
bool rkbuffer(kptr_t kaddr, void* buffer, size_t length);

void kmemcpy(uint64_t dest, uint64_t src, uint32_t length);

bool kmem_protect(kptr_t kaddr, uint32_t size, vm_prot_t prot);

kptr_t kmem_alloc(uint64_t size);
kptr_t kmem_alloc_wired(uint64_t size);
bool kmem_free(kptr_t kaddr, uint64_t size);

void prepare_rk_via_kmem_read_port(mach_port_t port);
void prepare_rwk_via_tfp0(mach_port_t port);
void prepare_for_rw_with_fake_tfp0(mach_port_t fake_tfp0);

// query whether kmem read or write is present
bool have_kmem_read(void);
bool have_kmem_write(void);

#endif
