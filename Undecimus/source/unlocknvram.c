// iOS 11 moves OFVariables to const
// https://twitter.com/s1guza/status/908790514178301952
// however, if we:
//  1) Can find IODTNVRAM service
//  2) Have tfp0 / kernel read|write|alloc
//  3) Can leak kernel address of mach port
// then we can fake vtable on IODTNVRAM object
// async_wake satisfies those requirements
// however, I wasn't able to actually set or get ANY nvram variable
// not even userread/userwrite
// Guess sandboxing won't let to access nvram

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <iokit.h>
#include <common.h>
#include "KernelUtilities.h"
#include "KernelStructureOffsets.h"
#include "KernelMemory.h"
#include "find_port.h"

static const size_t max_vtable_size = 0x1000;
static const size_t kernel_buffer_size = 0x4000;
// from vtable start in bytes
unsigned VTB_IODTNVRAM__SEARCHNVRAMPROPERTY = 0x590;
unsigned VTB_IODTNVRAM__GETOFVARIABLEPERM   = 0x558;

// convertPropToObject calls getOFVariableType
// open convertPropToObject, look for first vtable call -- that'd be getOFVariableType
// find xrefs, figure out vtable start from that
// following are offsets of entries in vtable

// get kernel address of IODTNVRAM object
uint64_t get_iodtnvram_obj(void) {
    static uint64_t IODTNVRAMObj = 0;
    
    if (IODTNVRAMObj == 0) {
        io_service_t IODTNVRAMSrv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
        if (!MACH_PORT_VALID(IODTNVRAMSrv)) {
            LOG("Failed to get IODTNVRAM service");
            return 0;
        }
        uint64_t nvram_up = get_address_of_port(getpid(), IODTNVRAMSrv);
        IODTNVRAMObj = ReadKernel64(nvram_up + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));

        LOG("IODTNVRAM obj at 0x%llx", IODTNVRAMObj);
    }

    return IODTNVRAMObj;
}

uint64_t orig_vtable = -1;

int unlocknvram(void) {
    uint64_t obj = get_iodtnvram_obj();
    if (obj == 0) {
        LOG("get_iodtnvram_obj failed!");
        return 1;
    }

    orig_vtable = ReadKernel64(obj);
    
    uint64_t *buf = calloc(1, max_vtable_size);
    kread(orig_vtable, buf, max_vtable_size);
    
    // alter it
    buf[VTB_IODTNVRAM__GETOFVARIABLEPERM / sizeof(uint64_t)] = \
        buf[VTB_IODTNVRAM__SEARCHNVRAMPROPERTY / sizeof(uint64_t)];

    // allocate buffer in kernel and copy it back
    uint64_t fake_vtable = kmem_alloc_wired(kernel_buffer_size);
    wkbuffer(fake_vtable, buf, kernel_buffer_size);

    // replace vtable on IODTNVRAM object
    WriteKernel64(obj, fake_vtable);

    free(buf);
    LOG("Unlocked nvram");
    return 0;
}

int locknvram(void) {
    if (orig_vtable == -1) {
        LOG("Trying to lock nvram, but didnt unlock first");
        return -1;
    }

    uint64_t obj = get_iodtnvram_obj();
    if (obj == 0) { // would never happen but meh
        LOG("get_iodtnvram_obj failed!");
        return 1;
    }
    
    WriteKernel64(obj, orig_vtable);

    LOG("Locked nvram");
    return 0;
}
