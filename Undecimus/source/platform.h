/*
 * platform.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__PLATFORM_H_
#define VOUCHER_SWAP__PLATFORM_H_

#include <stdbool.h>
#include <mach/machine.h>

#ifdef PLATFORM_EXTERN
#define extern PLATFORM_EXTERN
#endif

/*
 * platform
 *
 * Description:
 * 	Basic information about the platform.
 */
struct platform {
	/*
	 * platform.machine
	 *
	 * Description:
	 * 	The name of the platform, e.g. iPhone11,8.
	 */
	const char machine[32];
	/*
	 * platform.osversion
	 *
	 * Description:
	 * 	The version of the OS build, e.g. 16C50.
	 */
	const char osversion[32];
	/*
	 * platform.cpu_type
	 *
	 * Description:
	 * 	The platform CPU type.
	 */
	cpu_type_t cpu_type;
	/*
	 * platform.cpu_subtype
	 *
	 * Description:
	 * 	The platform CPU subtype.
	 */
	cpu_subtype_t cpu_subtype;
	/*
	 * platform.physical_cpu
	 *
	 * Description:
	 * 	The number of physical CPU cores.
	 */
	unsigned physical_cpu;
	/*
	 * platform.logical_cpu
	 *
	 * Description:
	 * 	The number of logical CPU cores.
	 */
	unsigned logical_cpu;
	/*
	 * platform.page_size
	 *
	 * Description:
	 * 	The kernel page size.
	 */
	size_t page_size;
	/*
	 * platform.memory_size
	 *
	 * Description:
	 * 	The size of physical memory on the device.
	 */
	size_t memory_size;
};
extern struct platform platform;

/*
 * page_size
 *
 * Description:
 * 	The kernel page size on this platform, made available globally for convenience.
 */
extern size_t page_size;

/*
 * platform_init
 *
 * Description:
 * 	Initialize the platform.
 */
void platform_init(void);

#undef extern

#endif
