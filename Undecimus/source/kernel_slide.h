/*
 * kernel_slide.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__KERNEL_SLIDE_H_
#define VOUCHER_SWAP__KERNEL_SLIDE_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef KERNEL_SLIDE_EXTERN
#define extern KERNEL_SLIDE_EXTERN
#endif

/*
 * kernel_slide
 *
 * Description:
 * 	The kASLR slide.
 */
extern uint64_t kernel_slide;

/*
 * kernel_slide_init
 *
 * Description:
 * 	Find the value of the kernel slide using kernel_read() and current_task.
 */
bool kernel_slide_init(void);

/*
 * kernel_slide_init_with_kernel_image_address
 *
 * Description:
 * 	Find the value of the kernel slide using kernel_read(), starting with an address that is
 * 	known to reside within the kernel image.
 */
bool kernel_slide_init_with_kernel_image_address(uint64_t address);

#undef extern

#endif
