//
//  offsets.c
//  v1ntex
//
//  Created by tihmstar on 23.01.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "offsets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <unistd.h>


/*
#define OFFSET_TASK_BSD_INFO 0x368
#define BSDINFO_PID_OFFSET  0x10
#define OFFSET_IPC_SPACE_IS_TASK 0x28
#define OFFSET_TASK_ITK_REGISTERED 0x2f0
#define OFFSET_VTAB_GET_EXTERNAL_TRAP_FOR_INDEX 183
#define OFFSET_KERNELBASE   0xfffffff007004000
#define OFFSET_ZONE_MAP 0xfffffff0075d5e50
#define OFFSET_ROP_LDR_X0_X0_0X10 0xfffffff00723f47c
#define OFFSET_COPYOUT 0xfffffff007198d44
#define OFFSET_COPYIN 0xfffffff007198b14
#define OFFSET_KERNEL_TASK 0xfffffff007624048
#define OFFSET_OSSERIALIZER_SERIALIZE 0xfffffff0074bda44
#define OFFSET_PROC_UCRED 0x100
#define OFFSET_KAUTH_CRED_REF 0xfffffff0073b017c
#define OFFSET_CHGPROCCNT 0xfffffff0073dafc8
#define OFFSET_KERNEL_MAP 0xfffffff007624050
#define OFFSET_VM_MAP_HDR 0x10
#define OFFSET_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070a8368
#define OFFSET_IPC_KOBJECT_SET 0xfffffff0070bd4b4
#define OFFSET_SIZEOF_TASK 0x568
#define OFFSET_IPC_PORT_MAKE_SEND 0xfffffff0070a7df4
#define OFFSET_REALHOST 0xfffffff0075b8b98
#define OFFSET_REALHOST_SPECIAL 0x10
// hardcoded offsets for iPhone 5S, iOS 11.2.6
*/
t_device get_info() {
    t_device device;
    size_t size = 32;
    char build_id[size];
    memset(build_id, 0, size);
    int err = sysctlbyname("kern.osversion", build_id, &size, NULL, 0);
    if (err == -1) {
        printf("failed to detect version (sysctlbyname failed\n");
    }
    strcpy(device.build_id, build_id);
    struct utsname u = {0};
    uname(&u);
    strcpy(device.machine, u.machine);
    return device;
}

t_offsets *info_to_target_environment() {
    t_device device = get_info();
    printf("build_id = %s\n", device.build_id);
    printf("machine = %s\n", device.machine);
    t_offsets *guoffsets = NULL;
    t_offsets uoffsets;
    int pushing = 0;
#define pushOffset(off) *(((kptr_t*)&uoffsets)+(pushing++)) = (off)
    if (strcmp(device.build_id, "15E302") == 0 && strstr(device.machine, "iPhone7,1")) { // hardcoded offsets for iPhone 6 Plus, iOS 11.3.1
        pushOffset(0x368);
        pushOffset(0x28);
        pushOffset(0x2f0);
        pushOffset(183);
        pushOffset(0xfffffff007004000);
        pushOffset(0xfffffff0075ffe50);
        pushOffset(0xfffffff007254c64);
        pushOffset(0xfffffff0071aaa28);
        pushOffset(0xfffffff0071aa804);
        pushOffset(0xfffffff0075dd048);
        pushOffset(0xfffffff0074e2efc);
        pushOffset(0x100);
        pushOffset(0xfffffff0073cce40);
        pushOffset(0xfffffff0073f869c);
        pushOffset(0xfffffff0075dd050);
        pushOffset(0x10);
        pushOffset(0xfffffff0070b9328);
        pushOffset(0xfffffff0070cf2c8);
        pushOffset(0x568);
        pushOffset(0xfffffff0070b8aa4);
        pushOffset(0xfffffff0075e2b98);
        pushOffset(0x10);
    } else if (strcmp(device.build_id, "15D100") == 0 && strstr(device.machine, "iPhone5,2")) {
        pushOffset(0x368);
        pushOffset(0x28);
        pushOffset(0x2f0);
        pushOffset(183);
        pushOffset(0xfffffff007004000);
        pushOffset(0xfffffff0075d5e50);
        pushOffset(0xfffffff00723f47c);
        pushOffset(0xfffffff007198d44);
        pushOffset(0xfffffff007198b14);
        pushOffset(0xfffffff007624048);
        pushOffset(0xfffffff0074bda44);
        pushOffset(0x100);
        pushOffset(0xfffffff0073b017c);
        pushOffset(0xfffffff0073dafc8);
        pushOffset(0xfffffff007624050);
        pushOffset(0x10);
        pushOffset(0xfffffff0070a8368);
        pushOffset(0xfffffff0070bd4b4);
        pushOffset(0x568);
        pushOffset(0xfffffff0070a7df4);
        pushOffset(0xfffffff0075b8b98);
        pushOffset(0x10);
    }
    else{
        printf("[!] Failed to load offsets\n");
        return NULL;
    }
    usleep(500);
    guoffsets = malloc(sizeof(t_offsets));
    memcpy(guoffsets,&uoffsets,sizeof(t_offsets));
    
    printf("[*] Loaded offsets:\n");
    printf("    0x%016llx -offset_zone_map\n",uoffsets.offset_zone_map);
    printf("    0x%016llx -offset_kernel_map\n",uoffsets.offset_kernel_map);
    printf("    0x%016llx -offset_kernel_task\n",uoffsets.offset_kernel_task);
    printf("    0x%016llx -offset_realhost\n",uoffsets.offset_realhost);
    printf("    0x%016llx -offset_realhost_special\n",uoffsets.offset_realhost_special);
    printf("    0x%016llx -offset_copyin\n",uoffsets.offset_copyin);
    printf("    0x%016llx -offset_copyout\n",uoffsets.offset_copyout);
    printf("    0x%016llx -offset_ipc_port_alloc_special\n",uoffsets.offset_ipc_port_alloc_special);
    printf("    0x%016llx -offset_ipc_kobject_set\n",uoffsets.offset_ipc_kobject_set);
    printf("    0x%016llx -offset_ipc_port_make_send\n",uoffsets.offset_ipc_port_make_send);
    printf("    0x%016llx -offset_rop_ldr_r0_r0_0xc\n",uoffsets.offset_rop_ldr_x0_x0_0x10);
    printf("    0x%016llx -offset_chgproccnt\n",uoffsets.offset_chgproccnt);
    printf("    0x%016llx -offset_kauth_cred_ref\n",uoffsets.offset_kauth_cred_ref);
    printf("    0x%016llx -offset_OSSerializer_serialize\n",uoffsets.offset_OSSerializer_serialize);
    printf("    0x%016llx -offset_ipc_space_is_task\n",uoffsets.offset_ipc_space_is_task);
    printf("    0x%016llx -offset_task_itk_registered\n",uoffsets.offset_task_itk_registered);
    printf("    0x%016llx -offset_vtab_get_external_trap_for_index\n",uoffsets.offset_vtab_get_external_trap_for_index);
    printf("    0x%016llx -offset_proc_ucred\n",uoffsets.offset_proc_ucred);
    printf("    0x%016llx -offset_task_bsd_info\n",uoffsets.offset_task_bsd_info);
    printf("    0x%016llx -offset_sizeof_task\n",uoffsets.offset_sizeof_task);
    
    return guoffsets;
}
