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
            .release = "18.",
            .kernel_image_base = 0xfffffff007004000,
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
            .release = "17.",
            .kernel_image_base = 0xfffffff007004000,
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
        if (strncmp(machswap_offsets[i]->constant.release, u.release, strlen(machswap_offsets[i]->constant.release)) == 0)
        {
            return machswap_offsets[i];
        }
    }

    LOG("Failed to get offsets for kernel version: %s", u.version);
    return NULL;
}
