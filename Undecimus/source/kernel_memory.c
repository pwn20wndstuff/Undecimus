/*
 * kernel_memory.c
 * Brandon Azad
 */
#define KERNEL_MEMORY_EXTERN
#include "kernel_memory.h"

#include "log.h"
#include "mach_vm.h"
#include "parameters.h"

// ---- Kernel memory functions -------------------------------------------------------------------

bool
kernel_read(uint64_t address, void *data, size_t size) {
    extern bool rkbuffer(uint64_t kaddr, void* buffer, size_t length);
    return rkbuffer(address, data, size);
}

bool
kernel_write(uint64_t address, const void *data, size_t size) {
    extern bool wkbuffer(uint64_t kaddr, void* buffer, size_t length);
    return wkbuffer(address, (void *)data, size);
}

uint8_t
kernel_read8(uint64_t address) {
	uint8_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

uint16_t
kernel_read16(uint64_t address) {
	uint16_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

uint32_t
kernel_read32(uint64_t address) {
	uint32_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

uint64_t
kernel_read64(uint64_t address) {
	uint64_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

bool
kernel_write8(uint64_t address, uint8_t value) {
	return kernel_write(address, &value, sizeof(value));
}

bool
kernel_write16(uint64_t address, uint16_t value) {
	return kernel_write(address, &value, sizeof(value));
}

bool
kernel_write32(uint64_t address, uint32_t value) {
	return kernel_write(address, &value, sizeof(value));
}

bool
kernel_write64(uint64_t address, uint64_t value) {
	return kernel_write(address, &value, sizeof(value));
}

// ---- Kernel utility functions ------------------------------------------------------------------

bool
kernel_ipc_port_lookup(uint64_t task, mach_port_name_t port_name,
		uint64_t *ipc_port, uint64_t *ipc_entry) {
	// Get the task's ipc_space.
	uint64_t itk_space = kernel_read64(task + OFFSET(task, itk_space));
	// Get the size of the table.
	uint32_t is_table_size = kernel_read32(itk_space + OFFSET(ipc_space, is_table_size));
	// Get the index of the port and check that it is in-bounds.
	uint32_t port_index = MACH_PORT_INDEX(port_name);
	if (port_index >= is_table_size) {
		return false;
	}
	// Get the space's is_table and compute the address of this port's entry.
	uint64_t is_table = kernel_read64(itk_space + OFFSET(ipc_space, is_table));
	uint64_t entry = is_table + port_index * SIZE(ipc_entry);
	if (ipc_entry != NULL) {
		*ipc_entry = entry;
	}
	// Get the address of the port if requested.
	if (ipc_port != NULL) {
		*ipc_port = kernel_read64(entry + OFFSET(ipc_entry, ie_object));
	}
	return true;
}
