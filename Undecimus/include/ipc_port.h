/*
 * ipc_port.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__IPC_PORT_H_
#define VOUCHER_SWAP__IPC_PORT_H_

#include <mach/mach.h>
#include <stdint.h>

// ---- osfmk/kern/waitq.h ------------------------------------------------------------------------

#define _EVENT_MASK_BITS   ((sizeof(uint32_t) * 8) - 7)

#define WQT_QUEUE       0x2

union waitq_flags {
	struct {
		uint32_t /* flags */
			waitq_type:2,    /* only public field */
			waitq_fifo:1,    /* fifo wakeup policy? */
			waitq_prepost:1, /* waitq supports prepost? */
			waitq_irq:1,     /* waitq requires interrupts disabled */
			waitq_isvalid:1, /* waitq structure is valid */
			waitq_turnstile_or_port:1, /* waitq is embedded in a turnstile (if irq safe), or port (if not irq safe) */
			waitq_eventmask:_EVENT_MASK_BITS;
	};
	uint32_t flags;
};

// ---- osfmk/kern/ipc_kobject.h ------------------------------------------------------------------

#define	IKOT_NONE				0
#define	IKOT_TASK				2

// ---- osfmk/ipc/ipc_object.h --------------------------------------------------------------------

#define	IO_BITS_KOTYPE		0x00000fff	/* used by the object */
#define	IO_BITS_ACTIVE		0x80000000	/* is object alive? */

#define	io_makebits(active, otype, kotype)	\
	(((active) ? IO_BITS_ACTIVE : 0) | ((otype) << 16) | (kotype))

#define	IOT_PORT		0

// ---- Custom definitions ------------------------------------------------------------------------

#define MACH_HEADER_SIZE_DELTA	(2 * (sizeof(uint64_t) - sizeof(uint32_t)))

// ------------------------------------------------------------------------------------------------

#endif
