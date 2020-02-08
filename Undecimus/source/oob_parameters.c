/*
 * parameters.c
 * Brandon Azad
 */
#define PARAMETERS_EXTERN
#include "oob_parameters.h"

#include "log.h"
#include "platform.h"
#include "platform_match.h"

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
#define ARRAY_COUNT(x)    (sizeof(x) / sizeof((x)[0]))

// ---- Offset initialization ---------------------------------------------------------------------

// Initialization for iPhone12,3 17C54.
static void
offsets__iphone12_3__17C54() {
    OFFSET(oob_host, special) = 0x10;

    SIZE(oob_ipc_entry)              = 0x18;
    OFFSET(oob_ipc_entry, ie_object) =  0x0;
    OFFSET(oob_ipc_entry, ie_bits)   =  0x8;

    OFFSET(oob_ipc_port, ip_bits)       =  0x0;
    OFFSET(oob_ipc_port, ip_references) =  0x4;
    OFFSET(oob_ipc_port, ip_receiver)   = 0x60;
    OFFSET(oob_ipc_port, ip_kobject)    = 0x68;
    OFFSET(oob_ipc_port, ip_mscount)    = 0x9c;
    OFFSET(oob_ipc_port, ip_srights)    = 0xa0;

    OFFSET(oob_ipc_space, is_table_size) = 0x14;
    OFFSET(oob_ipc_space, is_table)      = 0x20;
    OFFSET(oob_ipc_space, is_task)       = 0x28;

    OFFSET(oob_proc, p_list_next) =  0x0;
    OFFSET(oob_proc, task)        = 0x10;
    OFFSET(oob_proc, p_pid)       = 0x68;

    OFFSET(oob_task, lck_mtx_data)        =   0x0;
    OFFSET(oob_task, lck_mtx_type)        =   0xb;
    OFFSET(oob_task, ref_count)           =  0x10;
    OFFSET(oob_task, active)              =  0x14;
    OFFSET(oob_task, map)                 =  0x28;
    OFFSET(oob_task, itk_sself)           = 0x108;
    OFFSET(oob_task, itk_space)           = 0x320;
    OFFSET(oob_task, bsd_info)            = 0x388;
    OFFSET(oob_task, all_image_info_addr) = 0x3d0;

    OFFSET(oob_IOSurface, properties) = 0xe8;

    OFFSET(oob_IOSurfaceClient, surface) = 0x40;

    OFFSET(oob_IOSurfaceRootUserClient, surfaceClients) = 0x118;

    OFFSET(oob_OSArray, count) = 0x14;
    OFFSET(oob_OSArray, array) = 0x20;

    OFFSET(oob_OSData, capacity) = 0x10;
    OFFSET(oob_OSData, data) = 0x18;

    OFFSET(oob_OSDictionary, count) = 0x14;
    OFFSET(oob_OSDictionary, dictionary) = 0x20;

    OFFSET(oob_OSString, string) = 0x10;
}

// A list of offset initializations by platform.
static struct initialization offsets[] = {
    { "iPhone12,3", "17C54", offsets__iphone12_3__17C54 },
    { "iPhone12,1", "17C54", offsets__iphone12_3__17C54 },
};

// The minimum number of offsets that must match in order to declare a platform initialized.
static const size_t min_offsets = 1;

// ---- Public API --------------------------------------------------------------------------------

bool
oob_parameters_init() {
    // Initialize offsets.
    size_t count = run_initializations(offsets, ARRAY_COUNT(offsets));
    if (count < min_offsets) {
        ERROR("No offsets for %s %s", platform.machine, platform.osversion);
        return false;
    }
    return true;
}
