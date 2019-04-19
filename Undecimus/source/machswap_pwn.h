#ifndef MACHSWAP_PWN_H
#define MACHSWAP_PWN_H

#include <mach/mach.h>

#include "common.h"
#include "machswap_offsets.h"

kern_return_t machswap_exploit(machswap_offsets_t *offsets);

#endif
