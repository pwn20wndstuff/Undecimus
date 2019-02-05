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

    uint64_t vtable_start = ReadKernel64(obj);

    orig_vtable = vtable_start;

    uint64_t vtable_end = vtable_start;
    // Is vtable really guaranteed to end with 0 or was it just a coincidence?..
    // should we just use some max value instead?
    while (ReadKernel64(vtable_end) != 0) vtable_end += sizeof(uint64_t);

    uint32_t vtable_len = (uint32_t) (vtable_end - vtable_start);

    // copy vtable to userspace
    uint64_t *buf = calloc(1, vtable_len);
    rkbuffer(vtable_start, buf, vtable_len);

    LOG("IODTNVRAM vtable: 0x%llx - 0x%llx", vtable_start, vtable_end);

    for (int i = 0; i != vtable_len; i += sizeof(uint64_t)) {
        LOG("\t[0x%03x]: 0x%llx", i, buf[i/sizeof(uint64_t)]);
    }

    // alter it
    buf[VTB_IODTNVRAM__GETOFVARIABLEPERM / sizeof(uint64_t)] = \
        buf[VTB_IODTNVRAM__SEARCHNVRAMPROPERTY / sizeof(uint64_t)];

    // allocate buffer in kernel and copy it back
    uint64_t fake_vtable = kmem_alloc_wired(vtable_len);
    wkbuffer(fake_vtable, buf, vtable_len);

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
