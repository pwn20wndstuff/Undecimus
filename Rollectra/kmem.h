#ifndef kmem_h
#define kmem_h

#include <mach/mach.h>

/***** mach_vm.h *****/
kern_return_t mach_vm_read(
                           vm_map_t target_task,
                           mach_vm_address_t address,
                           mach_vm_size_t size,
                           vm_offset_t *data,
                           mach_msg_type_number_t *dataCnt);

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
                                     mach_vm_size_t *outsize);

kern_return_t mach_vm_allocate(
                               vm_map_t target,
                               mach_vm_address_t *address,
                               mach_vm_size_t size,
                               int flags);

kern_return_t mach_vm_deallocate (
                                  vm_map_t target,
                                  mach_vm_address_t address,
                                  mach_vm_size_t size);

kern_return_t mach_vm_protect (
                               vm_map_t target_task,
                               mach_vm_address_t address,
                               mach_vm_size_t size,
                               boolean_t set_maximum,
                               vm_prot_t new_protection);

extern mach_port_t tfp0;

uint32_t rk32(uint64_t kaddr);
uint64_t rk64(uint64_t kaddr);

void wk32(uint64_t kaddr, uint32_t val);
void wk64(uint64_t kaddr, uint64_t val);

void wkbuffer(uint64_t kaddr, void* buffer, uint32_t length);
void rkbuffer(uint64_t kaddr, void* buffer, uint32_t length);

void kmemcpy(uint64_t dest, uint64_t src, uint32_t length);

void kmem_protect(uint64_t kaddr, uint32_t size, int prot);

uint64_t kmem_alloc(uint64_t size);
uint64_t kmem_alloc_wired(uint64_t size);
void kmem_free(uint64_t kaddr, uint64_t size);

void prepare_rk_via_kmem_read_port(mach_port_t port);
void prepare_rwk_via_tfp0(mach_port_t port);
void prepare_for_rw_with_fake_tfp0(mach_port_t fake_tfp0);

// query whether kmem read or write is present
int have_kmem_read(void);
int have_kmem_write(void);

#endif
