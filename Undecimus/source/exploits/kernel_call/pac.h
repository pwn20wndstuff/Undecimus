/*
 * kernel_call/pac.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__KERNEL_CALL__PAC_H_
#define VOUCHER_SWAP__KERNEL_CALL__PAC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * stage2_kernel_call_init
 *
 * Description:
 * 	Initialize stage 2 of kernel function calling.
 *
 * Initializes:
 * 	stage2_kernel_call_7v()
 * 	kernel_forge_pacia()
 * 	kernel_forge_pacia_with_type()
 * 	kernel_forge_pacda()
 */
bool stage2_kernel_call_init(void);

/*
 * stage2_kernel_call_deinit
 *
 * Description:
 * 	Deinitialize stage 2 of kernel function calling.
 */
void stage2_kernel_call_deinit(void);

/*
 * stage2_kernel_call_7v
 *
 * Description:
 * 	Call a kernel function using our stage 2 execute primitive.
 *
 * Restrictions:
 * 	At most 7 arguments can be passed.
 * 	The return value is truncated to 32 bits.
 * 	At stage 2, only arguments X1 - X6 are controlled.
 */
uint32_t stage2_kernel_call_7v(uint64_t function,
		size_t argument_count, const uint64_t arguments[]);

#endif
