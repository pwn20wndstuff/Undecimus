#ifndef find_port_h
#define find_port_h

#include <mach/mach.h>

extern bool isv1ntex;
uint64_t find_port_address(mach_port_t port, int disposition);

#endif /* find_port_h */
