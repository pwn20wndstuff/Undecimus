#include <common.h>
#include <mach/mach.h>

bool init_kexec(void);
void term_kexec(void);
kptr_t kexec(kptr_t ptr, kptr_t x0, kptr_t x1, kptr_t x2, kptr_t x3, kptr_t x4, kptr_t x5, kptr_t x6);
