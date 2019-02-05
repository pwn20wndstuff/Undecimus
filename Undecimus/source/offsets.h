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


/* https://github.com/cheesecakeufo/saigon-v0rtex/blob/master/saigon/vortex/offsets.m */

typedef struct{
    kptr_t offset_task_bsd_info; // osfmk/kern/task.h: task->bsd_info, or you can get via _get_bsdtask_info:  ldr x0, [x0, #0x368]
    kptr_t offset_ipc_space_is_task; // osfmk/ipc/ipc_space.h: ipc_space->is_task
    kptr_t offset_task_itk_registered; // osfmk/kern/task.h: task->itk_registered
    kptr_t offset_vtab_get_external_trap_for_index;
    // ida
    kptr_t offset_kernel_base;
    kptr_t offset_zone_map;
    kptr_t offset_rop_ldr_x0_x0_0x10;
    kptr_t offset_copyout;
    kptr_t offset_copyin;
    kptr_t offset_kernel_task;
    kptr_t offset_OSSerializer_serialize;
    kptr_t offset_proc_ucred;
    kptr_t offset_kauth_cred_ref;
    kptr_t offset_chgproccnt; // contains string chgproccnt
    kptr_t offset_kernel_map;
    //
    kptr_t offset_vm_map_hdr; // osfmk/vm/vm_map.h: vm_map->hdr
    kptr_t offset_ipc_port_alloc_special; // 1 function below "\\\"Over-release of port %p send-once right!\\\""
    kptr_t offset_ipc_kobject_set; // 1 function above _mach_msg_send_from_kernel_proper
    kptr_t offset_sizeof_task; // sizeof(task)
    kptr_t offset_ipc_port_make_send; // third one above _ipc_port_release_send
    kptr_t offset_realhost; // look at _host_get_special_port, below _lck_mtx_lock
    kptr_t offset_realhost_special; // below realhost
}t_offsets;

// Initializer
t_device get_info(void);
t_offsets *info_to_target_environment(void);
#endif /* offsets_h */
