#ifndef PATCHFINDER64_H_
#define PATCHFINDER64_H_

int init_kernel(uint64_t base, const char *filename);
void term_kernel(void);

enum { SearchInCore, SearchInPrelink };

uint64_t find_register_value(uint64_t where, int reg);
uint64_t find_reference(uint64_t to, int n, int prelink);
uint64_t find_strref(const char *string, int n, int prelink);
uint64_t find_gPhysBase(void);
uint64_t find_kernel_pmap(void);
uint64_t find_amfiret(void);
uint64_t find_ret_0(void);
uint64_t find_amfi_memcmpstub(void);
uint64_t find_sbops(void);
uint64_t find_lwvm_mapio_patch(void);
uint64_t find_lwvm_mapio_newj(void);

uint64_t find_entry(void);
const unsigned char *find_mh(void);

uint64_t find_cpacr_write(void);
uint64_t find_str(const char *string);
uint64_t find_amfiops(void);
uint64_t find_sysbootnonce(void);
uint64_t find_trustcache(void);
uint64_t find_amficache(void);
uint64_t find_allproc(void);
uint64_t find_add_x0_x0_0x40_ret(void);
uint64_t find_copyout(void);
uint64_t find_bzero(void);
uint64_t find_bcopy(void);
uint64_t find_rootvnode(void);
uint64_t find_realhost(void);
uint64_t find_zone_map_ref(void);
uint64_t find_OSBoolean_True(void);
uint64_t find_OSBoolean_False(void);
uint64_t find_osunserializexml(void);
uint64_t find_smalloc(void);
uint64_t find_vfs_context_current(void);
uint64_t find_vnode_lookup(void);
uint64_t find_vnode_put(void);
uint64_t find_vnode_getfromfd(void);
uint64_t find_vnode_getattr(void);
uint64_t find_SHA1Init(void);
uint64_t find_SHA1Update(void);
uint64_t find_SHA1Final(void);
uint64_t find_csblob_entitlements_dictionary_set(void);
uint64_t find_kernel_task(void);
uint64_t find_kernproc(void);

#endif

