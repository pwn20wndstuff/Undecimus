//
//  v1ntex_offsets.mm
//  Undecimus
//
//  Created by Pwn20wnd on 2/7/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#include "v1ntex_offsets.h"
#include <liboffsetfinder64/liboffsetfinder64.hpp>

static v1ntex_offsets v1ntex_offs;

extern "C" v1ntex_offsets* get_v1ntex_offsets(const char* filename)
{
    LOG("Initializing offsetfinder64...");
    tihmstar::offsetfinder64 fi(filename);
    LOG("Successfully initialized offsetfinder64.");
    LOG("Finding offsets for v1ntex with liboffsetfinder64...");
    try {
        v1ntex_offs.offset_zone_map = (kptr_t)fi.find_zone_map();
        v1ntex_offs.offset_kernel_map = (kptr_t)fi.find_kernel_map();
        v1ntex_offs.offset_kernel_task = (kptr_t)fi.find_kernel_task();
        v1ntex_offs.offset_realhost = (kptr_t)fi.find_realhost();
        v1ntex_offs.offset_bzero = (kptr_t)fi.find_bzero();
        v1ntex_offs.offset_bcopy = (kptr_t)fi.find_bcopy();
        v1ntex_offs.offset_copyin = (kptr_t)fi.find_copyin();
        v1ntex_offs.offset_copyout = (kptr_t)fi.find_copyout();
        v1ntex_offs.offset_ipc_port_alloc_special = (kptr_t)fi.find_ipc_port_alloc_special();
        v1ntex_offs.offset_ipc_kobject_set = (kptr_t)fi.find_ipc_kobject_set();
        v1ntex_offs.offset_ipc_port_make_send = (kptr_t)fi.find_ipc_port_make_send();
        v1ntex_offs.offset_rop_ldr_r0_r0_0xc = (kptr_t)fi.find_rop_ldr_x0_x0_0x10();
        v1ntex_offs.offset_chgproccnt = (kptr_t)fi.find_chgproccnt();
        v1ntex_offs.offset_kauth_cred_ref = (kptr_t)fi.find_kauth_cred_ref();
        v1ntex_offs.offset_OSSerializer_serialize = (kptr_t)fi.find_osserializer_serialize();
        LOG("Successfully found offsets for v1ntex with offsetfinder64.");
        return &v1ntex_offs;
    } catch (tihmstar::exception& e) {
        LOG("Failed to find offsets for v1ntex with offsetfinder64 with a non-fatal error. %d (%s).", e.code(), e.what());
        return NULL;
    } catch (std::exception& e) {
        LOG("Failed to find offsets for v1ntex with offsetfinder64 with a fatal error. %s.", e.what());
        return NULL;
    }
}
