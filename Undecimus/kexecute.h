#include <mach/mach.h>
#include <inttypes.h>

mach_port_t prepare_user_client(void);
void init_kexecute(uint64_t add_x0_x0_0x40_ret);
void term_kexecute(void);
uint64_t kexecute(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6);
