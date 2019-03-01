#include <errno.h>
#include <string.h>             // strcmp, strerror
#include <sys/utsname.h>        // uname

#include "common.h"             // LOG, kptr_t
#include "machswap_offsets.h"

static machswap_offsets_t *machswap_offsets[] =
{
    &(machswap_offsets_t)
    {
        .constant =
        {
            .version = "Darwin Kernel Version 18.2.0: Mon Nov 12 20:32:02 PST 2018; root:xnu-4903.232.2~1/RELEASE_ARM64_S8000",
            .kernel_image_base = 0xfffffff007004000,
        },
        .funcs =
        {
            .copyin = 0xfffffff0071b6068,
            .copyout = 0xfffffff0071b65e0,
            .kalloc_external = 0xfffffff0070d93fc,
            .csblob_get_cdhash = 0xfffffff0073f4d04,
        },
        .data = 
        {
            .zonemap = 0xfffffff007624ec8,
            .kernproc = 0xfffffff0076020d0,
            .realhost = 0xfffffff007607bb8,
            .system_clock = 0xfffffff007078540,
        },
        .struct_offsets =
        {
            .proc_pid = 0x60,
            .proc_task = 0x10,
            .proc_ucred = 0xf8,
            .task_vm_map = 0x20,
            .task_bsd_info = 0x358,
            .task_itk_self = 0xd8,
            .task_itk_registered = 0x2e8,
            .task_all_image_info_addr = 0x398,
            .task_all_image_info_size = 0x3a0,
        },
        .iosurface = 
        {
            .create_outsize = 0xdd0,
            .get_external_trap_for_index = 0xb7,
        },
    },
    &(machswap_offsets_t)
    {
        .constant =
        {
            .version = "Darwin Kernel Version 18.2.0: Mon Nov 12 20:32:02 PST 2018; root:xnu-4903.232.2~1/RELEASE_ARM64_T7001",
            .kernel_image_base = 0xfffffff007004000,
        },
        .funcs =
        {
            .copyin = 0xfffffff0071b90b0,
            .copyout = 0xfffffff0071b94e4,
            .kalloc_external = 0xfffffff0070d9488,
            .csblob_get_cdhash = 0xfffffff0073f983c,
        },
        .data =
        {
            .zonemap = 0xfffffff007628ec8,
            .kernproc = 0xfffffff0076060d0,
            .realhost = 0xfffffff00760bbb8,
            .system_clock = 0xfffffff007078540,
        },
        .struct_offsets =
        {
            .proc_pid = 0x60,
            .proc_task = 0x10,
            .proc_ucred = 0xf8,
            .task_vm_map = 0x20,
            .task_bsd_info = 0x358,
            .task_itk_self = 0xd8,
            .task_itk_registered = 0x2e8,
            .task_all_image_info_addr = 0x398,
            .task_all_image_info_size = 0x3a0,
        },
        .iosurface =
        {
            .create_outsize = 0xdd0,
            .get_external_trap_for_index = 0xb7,
        },
    },
    &(machswap_offsets_t)
    {
        .constant =
        {
            .version = "Darwin Kernel Version 17.7.0: Mon Jun 11 19:06:26 PDT 2018; root:xnu-4570.70.24~3/RELEASE_ARM64_S5L8960X",
            .kernel_image_base = 0xfffffff007004000,
        },
        .funcs =
        {
            .copyin = 0xfffffff00719e88c,
            .copyout = 0xfffffff00719eab0,
            .kalloc_external = 0xfffffff0070c67cc,
            .csblob_get_cdhash = 0xfffffff0073c2ed4,
        },
        .data = 
        {
            .zonemap = 0xfffffff0075f3e50,
            .kernproc = 0xfffffff0075d10a0,
            .realhost = 0xfffffff0075d6b98,
            .system_clock = 0xfffffff00706d898,
        },
        .struct_offsets =
        {
            .proc_pid = 0x10,
            .proc_task = 0x18,
            .proc_ucred = 0x100,
            .task_vm_map = 0x20,
            .task_bsd_info = 0x368,
            .task_itk_self = 0xd8,
            .task_itk_registered = 0x2f0,
            .task_all_image_info_addr = 0x3a8,
            .task_all_image_info_size = 0x3b0,
        },
        .iosurface = 
        {
            .create_outsize = 0xbc8,
            .get_external_trap_for_index = 0xb7,
        },
    },
    NULL,
};

machswap_offsets_t *get_machswap_offsets(void)
{
    struct utsname u;
    if (uname(&u) != 0)
    {
        LOG("uname: %s", strerror(errno));
        return 0;
    }

    for (size_t i = 0; machswap_offsets[i] != 0; ++i)
    {
        if (strcmp(u.version, machswap_offsets[i]->constant.version) == 0)
        {
            return machswap_offsets[i];
        }
    }

    // LOG("Failed to get offsets for kernel version: %s", u.version);
    return NULL;
}
