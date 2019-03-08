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
            .cpu_subtype = CPU_SUBTYPE_ARM64E,
            .kernel_image_base = 0xfffffff007004000,
        },
        .struct_offsets =
        {
            .proc_pid = 0x60,
            .proc_task = 0x10,
            .proc_ucred = 0xf8,
            .task_vm_map = 0x20,
            .task_bsd_info = 0x368,
            .task_itk_self = 0xd8,
            .task_itk_registered = 0x2e8,
            .task_all_image_info_addr = 0x3a8,
            .task_all_image_info_size = 0x3b0,
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
            .release = "18.",
            .cpu_subtype = CPU_SUBTYPE_ARM64_V8,
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
            .cpu_subtype = CPU_SUBTYPE_ARM_ALL,
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

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/machine.h>

machswap_offsets_t *get_machswap_offsets(void)
{
    size_t size;
    cpu_type_t cpu_type;
    size = sizeof(cpu_type_t);
    if (sysctlbyname("hw.cputype", &cpu_type, &size, NULL, 0) == -1) {
        LOG("hw.cputype: %s", strerror(errno));
        return NULL;
    }

    cpu_subtype_t cpu_subtype;
    size = sizeof(cpu_subtype_t);
    if (sysctlbyname("hw.cpusubtype", &cpu_subtype, &size, NULL, 0) == -1) {
        LOG("hw.cpusubtype: %s", strerror(errno));
        return NULL;
    }

    int ctl[2];
    ctl[0] = CTL_KERN;
    ctl[1] = KERN_OSRELEASE;

    if (sysctl(ctl, 2, NULL, &size, NULL, 0) == -1 && errno != ENOMEM) {
        LOG("kern.osrelease: %s", strerror(errno));
        return NULL;
    }

    char release[size];
    if (sysctl(ctl, 2, release, &size, NULL, 0) == -1) {
        LOG("kern.osrelease: %s", strerror(errno));
        return NULL;
    }


    for (size_t i = 0; machswap_offsets[i] != 0; ++i)
    {
        if (strncmp(machswap_offsets[i]->constant.release, release, strlen(machswap_offsets[i]->constant.release)) == 0)
        {
            if (machswap_offsets[i]->constant.cpu_subtype == cpu_subtype ||
                machswap_offsets[i]->constant.cpu_subtype == CPU_SUBTYPE_ARM_ALL) {
                return machswap_offsets[i];
            }
        }
    }

    ctl[1] = KERN_VERSION;
    
    if (sysctl(ctl, 2, NULL, &size, NULL, 0) == -1 && errno != ENOMEM) {
        LOG("kern.version: %s", strerror(errno));
        return NULL;
    }

    char version[size];
    if (sysctl(ctl, 2, version, &size, NULL, 0) == -1) {
        LOG("kern.version: %s", strerror(errno));
        return NULL;
    }

    LOG("Failed to get offsets for kernel version: %s", version);
    return NULL;
}
