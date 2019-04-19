#ifndef MACHSWAP2_PWN_H
#define MACHSWAP2_PWN_H

#include <mach/mach.h>

#include "common.h"
#include "machswap_offsets.h"

kern_return_t machswap2_exploit(machswap_offsets_t *offsets);

#endif
