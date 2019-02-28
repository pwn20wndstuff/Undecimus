/*
 * kernel_call.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__KERNEL_CALL_H_
#define VOUCHER_SWAP__KERNEL_CALL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * kernel_call_init
 *
 * Description:
 * 	Initialize kernel_call functions.
 */
bool kernel_call_init(void);

/*
 * kernel_call_deinit
 *
 * Description:
 * 	Deinitialize the kernel call subsystem and restore the kernel to a safe state.
 */
void kernel_call_deinit(void);

/*
 * kernel_call_7
 *
 * Description:
 * 	Call a kernel function with the specified arguments.
 *
 * Restrictions:
 * 	See kernel_call_7v().
 */
uint32_t kernel_call_7(uint64_t function, size_t argument_count, ...);

/*
 * kernel_call_7v
 *
 * Description:
 * 	Call a kernel function with the specified arguments.
 *
 * Restrictions:
 * 	At most 7 arguments can be passed.
 * 	arguments[0] must be nonzero.
 * 	The return value is truncated to 32 bits.
 */
uint32_t kernel_call_7v(uint64_t function, size_t argument_count, const uint64_t arguments[]);

/*
 * kernel_forge_pacia
 *
 * Description:
 * 	Forge a PACIA pointer using the kernel forging gadget.
 */
uint64_t kernel_forge_pacia(uint64_t pointer, uint64_t context);

/*
 * kernel_forge_pacia_with_type
 *
 * Description:
 * 	Forge a PACIA pointer using the specified address, with the upper 16 bits replaced by the
 * 	type code, as context.
 */
uint64_t kernel_forge_pacia_with_type(uint64_t pointer, uint64_t address, uint16_t type);

/*
 * kernel_forge_pacda
 *
 * Description:
 * 	Forge a PACDA pointer using the kernel forging gadget.
 */
uint64_t kernel_forge_pacda(uint64_t pointer, uint64_t context);

/*
 * kernel_xpaci
 *
 * Description:
 * 	Strip a PACIx code from a kernel pointer.
 */
uint64_t kernel_xpaci(uint64_t pointer);

/*
 * kernel_xpacd
 *
 * Description:
 * 	Strip a PACDx code from a kernel pointer.
 */
uint64_t kernel_xpacd(uint64_t pointer);

#endif
