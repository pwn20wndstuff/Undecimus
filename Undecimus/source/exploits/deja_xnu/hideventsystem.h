#ifndef hideventsystem_h
#define hideventsystem_h

#include <mach/mach.h>

// get a thread port from backboardd
mach_port_t hid_event_queue_exploit(void);

#endif /* hideventsystem_h */
