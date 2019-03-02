// iOS 11 moves OFVariables to const
// https://twitter.com/s1guza/status/908790514178301952
// however, if we:
//  1) Can find IODTNVRAM service
//  2) Have tfp0 / kernel read|write|alloc
//  3) Can leak kernel address of mach port
// then we can fake vtable on IODTNVRAM object

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

// it always returns false
static const uint64_t searchNVRAMProperty = 0x590;
// 0 corresponds to root only
static const uint64_t getOFVariablePerm = 0x558;

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

uint64_t orig_vtable = 0;
uint64_t fake_vtable = 0;

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
    buf[getOFVariablePerm / sizeof(uint64_t)] = \
        buf[searchNVRAMProperty / sizeof(uint64_t)];

    // allocate buffer in kernel and copy it back
    fake_vtable = kmem_alloc_wired(kernel_buffer_size);
    wkbuffer(fake_vtable, buf, kernel_buffer_size);

    // replace vtable on IODTNVRAM object
    WriteKernel64(obj, fake_vtable);

    free(buf);
    LOG("Unlocked nvram");
    return 0;
}

int locknvram(void) {
    if (orig_vtable == 0 || fake_vtable == 0) {
        LOG("Trying to lock nvram, but didnt unlock first");
        return -1;
    }

    uint64_t obj = get_iodtnvram_obj();
    if (obj == 0) { // would never happen but meh
        LOG("get_iodtnvram_obj failed!");
        return 1;
    }
    
    WriteKernel64(obj, orig_vtable);
    kmem_free(fake_vtable, kernel_buffer_size);

    LOG("Locked nvram");
    return 0;
}
