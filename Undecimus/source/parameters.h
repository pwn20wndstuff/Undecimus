/*
 * parameters.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__PARAMETERS_H_
#define VOUCHER_SWAP__PARAMETERS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef PARAMETERS_EXTERN
#define extern PARAMETERS_EXTERN
#endif

// Some helpful units.
#define KB (1024uLL)
#define MB (1024uLL * KB)
#define GB (1024uLL * MB)

// Generate the name for an offset.
#define OFFSET(base_, object_)		_##base_##__##object_##__offset_

// Generate the name for the size of an object.
#define SIZE(object_)			_##object_##__size_

// Generate the name for the size of a zalloc block of objects.
#define BLOCK_SIZE(object_)		_##object_##__block_size_

// Generate the name for the number of elements in a zalloc block.
#define COUNT_PER_BLOCK(object_)	_##object_##__per_block_

// Generate the name for the address of an object.
#define ADDRESS(object_)		_##object_##__address_

// Generate the name for the static (unslid) address of an object.
#define STATIC_ADDRESS(object_)		_##object_##__static_address_

// A convenience macro for accessing a field of a structure.
#define FIELD(object_, struct_, field_, type_)	\
	( *(type_ *) ( ((uint8_t *) object_) + OFFSET(struct_, field_) ) )

// The static base address of the kernel.
extern uint64_t STATIC_ADDRESS(kernel_base);

// The kernel_slide granularity.
extern uint64_t kernel_slide_step;

// Messages up to this size are allocated from the dedicated ipc.kmsgs zone.
extern size_t message_size_for_kmsg_zone;

// The size of elements in ipc.kmsgs.
extern size_t kmsg_zone_size;

// The maximum number of OOL ports in a single message.
extern size_t max_ool_ports_per_message;

// How much to allocate between sleeps while trying to trigger garbage collection.
extern size_t gc_step;

// Parameters for ipc_entry.
extern size_t SIZE(ipc_entry);
extern size_t OFFSET(ipc_entry, ie_object);
extern size_t OFFSET(ipc_entry, ie_bits);
extern size_t OFFSET(ipc_entry, ie_request);

// Parameters for ipc_port.
extern size_t SIZE(ipc_port);
extern size_t BLOCK_SIZE(ipc_port);
extern size_t COUNT_PER_BLOCK(ipc_port);
extern size_t OFFSET(ipc_port, ip_bits);
extern size_t OFFSET(ipc_port, ip_references);
extern size_t OFFSET(ipc_port, waitq_flags);
extern size_t OFFSET(ipc_port, imq_messages);
extern size_t OFFSET(ipc_port, imq_msgcount);
extern size_t OFFSET(ipc_port, imq_qlimit);
extern size_t OFFSET(ipc_port, ip_receiver);
extern size_t OFFSET(ipc_port, ip_kobject);
extern size_t OFFSET(ipc_port, ip_nsrequest);
extern size_t OFFSET(ipc_port, ip_requests);
extern size_t OFFSET(ipc_port, ip_mscount);
extern size_t OFFSET(ipc_port, ip_srights);

// Parameters for ipc_port_request.
extern size_t SIZE(ipc_port_request);
extern size_t OFFSET(ipc_port_request, ipr_soright);

// Parameters for struct ipc_space.
extern size_t OFFSET(ipc_space, is_table_size);
extern size_t OFFSET(ipc_space, is_table);

// Parameters for ipc_voucher.
extern size_t SIZE(ipc_voucher);
extern size_t BLOCK_SIZE(ipc_voucher);
extern size_t COUNT_PER_BLOCK(ipc_voucher);

// Parameters for struct proc.
extern size_t OFFSET(proc, p_pid);
extern size_t OFFSET(proc, p_ucred);

// Parameters for struct sysctl_oid.
extern size_t SIZE(sysctl_oid);
extern size_t OFFSET(sysctl_oid, oid_parent);
extern size_t OFFSET(sysctl_oid, oid_link);
extern size_t OFFSET(sysctl_oid, oid_kind);
extern size_t OFFSET(sysctl_oid, oid_handler);
extern size_t OFFSET(sysctl_oid, oid_version);
extern size_t OFFSET(sysctl_oid, oid_refcnt);

// Parameters for struct task.
extern size_t OFFSET(task, lck_mtx_type);
extern size_t OFFSET(task, ref_count);
extern size_t OFFSET(task, active);
extern size_t OFFSET(task, map);
extern size_t OFFSET(task, itk_space);
extern size_t OFFSET(task, bsd_info);

/*
 * parameters_init
 *
 * Description:
 * 	Initialize the parameters for the system.
 */
bool parameters_init(void);

#undef extern

#endif
