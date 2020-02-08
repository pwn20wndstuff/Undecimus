/*
 * kernel_memory.c
 * Brandon Azad
 */
#define OOB_KERNEL_MEMORY_EXTERN
#include "oob_kernel_memory.h"
#include "kernel_memory.h"

#include <assert.h>

#include "log.h"
#include "mach_vm.h"
#include "platform.h"

// ---- Kernel memory functions -------------------------------------------------------------------

uint64_t
kernel_vm_allocate(size_t size) {
    mach_vm_address_t address = 0;
    kern_return_t kr = mach_vm_allocate(kernel_task_port, &address, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        ERROR("%s returned %d: %s", "mach_vm_allocate", kr, mach_error_string(kr));
        address = -1;
    } else {
        // Fault in each page.
        for (size_t offset = 0; offset < size; offset += page_size) {
            oob_kernel_read64(address + offset);
        }
    }
    return address;
}

bool
oob_kernel_read(uint64_t address, void *data, size_t size) {
    mach_vm_size_t size_out;
    kern_return_t kr = mach_vm_read_overwrite(kernel_task_port, address,
            size, (mach_vm_address_t) data, &size_out);
    if (kr != KERN_SUCCESS) {
        ERROR("%s returned %d: %s", "mach_vm_read_overwrite", kr, mach_error_string(kr));
        ERROR("Could not %s address 0x%016llx", "read", address);
        return false;
    }
    if (size_out != size) {
        ERROR("Partial read of address 0x%016llx: %llu of %zu bytes",
                address, size_out, size);
        return false;
    }
    return true;
}

bool
oob_kernel_write(uint64_t address, const void *data, size_t size) {
    const uint8_t *write_data = data;
    while (size > 0) {
        size_t write_size = size;
        if (write_size > page_size) {
            write_size = page_size;
        }
        kern_return_t kr = mach_vm_write(kernel_task_port, address,
                (mach_vm_address_t) write_data, (mach_msg_size_t) write_size);
        if (kr != KERN_SUCCESS) {
            ERROR("%s returned %d: %s", "mach_vm_write", kr, mach_error_string(kr));
            ERROR("Could not %s address 0x%016llx", "write", address);
            return false;
        }
        address += write_size;
        write_data += write_size;
        size -= write_size;
    }
    return true;
}

uint8_t
oob_kernel_read8(uint64_t address) {
    uint8_t value;
    bool ok = oob_kernel_read(address, &value, sizeof(value));
    if (!ok) {
        return -1;
    }
    return value;
}

uint16_t
oob_kernel_read16(uint64_t address) {
    uint16_t value;
    bool ok = oob_kernel_read(address, &value, sizeof(value));
    if (!ok) {
        return -1;
    }
    return value;
}

uint32_t
oob_kernel_read32(uint64_t address) {
    uint32_t value;
    bool ok = oob_kernel_read(address, &value, sizeof(value));
    if (!ok) {
        return -1;
    }
    return value;
}

uint64_t
oob_kernel_read64(uint64_t address) {
    uint64_t value;
    bool ok = oob_kernel_read(address, &value, sizeof(value));
    if (!ok) {
        return -1;
    }
    return value;
}

bool
oob_kernel_write8(uint64_t address, uint8_t value) {
    return oob_kernel_write(address, &value, sizeof(value));
}

bool
oob_kernel_write16(uint64_t address, uint16_t value) {
    return oob_kernel_write(address, &value, sizeof(value));
}

bool
oob_kernel_write32(uint64_t address, uint32_t value) {
    return oob_kernel_write(address, &value, sizeof(value));
}

bool
oob_kernel_write64(uint64_t address, uint64_t value) {
    return oob_kernel_write(address, &value, sizeof(value));
}
