//
//  offsets.h
//  v1ntex
//
//  Created by tihmstar on 23.01.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef offsets_h
#define offsets_h

#include "stddef.h"
#include "stdint.h"
#include <stdint.h>
typedef uint64_t kptr_t;

typedef struct {
    char build_id[32];
    char machine[255];
} t_device;

typedef struct{
    kptr_t offset_task_bsd_info;
    kptr_t offset_ipc_space_is_task;
    kptr_t offset_task_itk_registered;
    kptr_t offset_vtab_get_external_trap_for_index;
    kptr_t offset_kernel_base;
    kptr_t offset_zone_map;
    kptr_t offset_rop_ldr_x0_x0_0x10;
    kptr_t offset_copyout;
    kptr_t offset_copyin;
    kptr_t offset_kernel_task;
    kptr_t offset_OSSerializer_serialize;
    kptr_t offset_proc_ucred;
    kptr_t offset_kauth_cred_ref;
    kptr_t offset_chgproccnt;
    kptr_t offset_kernel_map;
    kptr_t offset_vm_map_hdr;
    kptr_t offset_ipc_port_alloc_special;
    kptr_t offset_ipc_kobject_set;
    kptr_t offset_sizeof_task;
    kptr_t offset_ipc_port_make_send;
    kptr_t offset_realhost;
    kptr_t offset_realhost_special;
}t_offsets;

// Initializer
t_device get_info(void);
t_offsets *info_to_target_environment(void);
#endif /* offsets_h */
