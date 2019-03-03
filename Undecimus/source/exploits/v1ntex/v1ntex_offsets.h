//
//  v1ntex_offsets.h
//  Undecimus
//
//  Created by Pwn20wnd on 2/7/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#ifndef v1ntex_offsets_h
#define v1ntex_offsets_h

#include <common.h>
#include <stdint.h>

typedef struct {
    kptr_t offset_zone_map;
    kptr_t offset_kernel_map;
    kptr_t offset_kernel_task;
    kptr_t offset_realhost;
    kptr_t offset_bzero;
    kptr_t offset_bcopy;
    kptr_t offset_copyin;
    kptr_t offset_copyout;
    kptr_t offset_ipc_port_alloc_special;
    kptr_t offset_ipc_kobject_set;
    kptr_t offset_ipc_port_make_send;
    kptr_t offset_rop_ldr_r0_r0_0xc;
    kptr_t offset_chgproccnt;
    kptr_t offset_kauth_cred_ref;
    kptr_t offset_OSSerializer_serialize;
} v1ntex_offsets;

#ifdef __cplusplus
extern "C"
#endif
    v1ntex_offsets*
    get_v1ntex_offsets(const char* filename);

#endif /* v1ntex_offsets_h */
