#ifndef kutils_h
#define kutils_h

#include <common.h>
#include <mach/mach.h>
#include <offsetcache.h>
#include <stdbool.h>

#if 0
Credits:
- https://stek29.rocks/2018/01/26/sandbox.html
- https://stek29.rocks/2018/12/11/shenanigans.html
- http://newosxbook.com/QiLin/qilin.pdf
- https://github.com/Siguza/v0rtex/blob/e6d54c97715d6dbcdda8b9a8090484a7a47019d0/src/v0rtex.m#L1623
#endif

#if 0
TODO:
- Patchfind proc_lock (High priority)
- Patchfind proc_unlock (High priority)
- Patchfind proc_ucred_lock (High priority)
- Patchfind proc_ucred_unlock (High priority)
- Patchfind vnode_lock (Low priority)
- Patchfind vnode_unlock (Low priority)
- Patchfind mount_lock (Low priority)
- Patchfind mount_unlock (Low priority)
- Patchfind task_set_platform_binary (High priority)
- Patchfind kauth_cred_ref (Low priority)
- Patchfind kauth_cred_unref (Low priority)
- Patchfind chgproccnt (Low priority)
- Patchfind kauth_cred_ref (Low priority)
- Patchfind kauth_cred_unref (Low priority)
- Patchfind extension_destroy (Low priority)
- Patchfind extension_create_mach (Middle priority)
- Use offsetof with XNU headers to find structure offsets (Low priority)
- Update Unrestrict to implement the kernel calls
#endif

#define SETOFFSET(offset, val) set_offset(#offset, val)
#define GETOFFSET(offset) get_offset(#offset)

#define KERN_POINTER_VALID(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)
#define SIZEOF_STRUCT_EXTENSION 0x60

#define OSBoolTrue getOSBool(true)
#define OSBoolFalse getOSBool(false)

extern uint64_t kernel_base;
extern uint64_t kernel_slide;

extern uint64_t cached_task_self_addr;
extern bool found_offsets;

uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_kernel_base(void);

uint64_t current_thread(void);

mach_port_t fake_host_priv(void);

int message_size_for_kalloc_size(int kalloc_size);

uint64_t get_kernel_proc_struct_addr(void);
void iterate_proc_list(void (^handler)(uint64_t, pid_t, bool *));
uint64_t get_proc_struct_for_pid(pid_t pid);
uint64_t get_address_of_port(pid_t pid, mach_port_t port);
uint64_t get_kernel_cred_addr(void);
uint64_t give_creds_to_process_at_addr(uint64_t proc, uint64_t cred_addr);
void set_platform_binary(uint64_t proc, bool set);

uint64_t zm_fix_addr(uint64_t addr);

bool verify_tfp0(void);

extern int (*pmap_load_trust_cache)(uint64_t kernel_trust, size_t length);
int _pmap_load_trust_cache(uint64_t kernel_trust, size_t length);

void set_host_type(host_t host, uint32_t type);
void export_tfp0(host_t host);
void unexport_tfp0(host_t host);

void set_csflags(uint64_t proc, uint32_t flags, bool value);
void set_cs_platform_binary(uint64_t proc, bool value);

bool execute_with_credentials(uint64_t proc, uint64_t credentials, void (^function)(void));

uint32_t get_proc_memstat_state(uint64_t proc);
void set_proc_memstat_state(uint64_t proc, uint32_t memstat_state);
void set_proc_memstat_internal(uint64_t proc, bool set);
bool get_proc_memstat_internal(uint64_t proc);
size_t kstrlen(uint64_t ptr);
uint64_t kstralloc(const char *str);
void kstrfree(uint64_t ptr);
uint64_t sstrdup(const char *str);
void sfree(uint64_t ptr);
int extension_create_file(uint64_t saveto, uint64_t sb, const char *path, size_t path_len, uint32_t subtype);
int extension_create_mach(uint64_t saveto, uint64_t sb, const char *name, uint32_t subtype);
int extension_add(uint64_t ext, uint64_t sb, const char *desc);
void extension_release(uint64_t ext);
void extension_destroy(uint64_t ext);
bool set_file_extension(uint64_t sandbox, const char *exc_key, const char *path);
bool set_mach_extension(uint64_t sandbox, const char *exc_key, const char *name);
uint64_t proc_find(pid_t pid);
void proc_rele(uint64_t proc);
void proc_lock(uint64_t proc);
void proc_unlock(uint64_t proc);
void proc_ucred_lock(uint64_t proc);
void proc_ucred_unlock(uint64_t proc);
void vnode_lock(uint64_t vp);
void vnode_unlock(uint64_t vp);
void mount_lock(uint64_t mp);
void mount_unlock(uint64_t mp);
void task_set_platform_binary(uint64_t task, boolean_t is_platform);
void kauth_cred_ref(uint64_t cred);
void kauth_cred_unref(uint64_t cred);
int chgproccnt(uid_t uid, int diff);
uint64_t vfs_context_current(void);
int vnode_lookup(const char *path, int flags, uint64_t *vpp, uint64_t ctx);
int vnode_put(uint64_t vp);
bool OSDictionary_SetItem(uint64_t OSDictionary, const char *key, uint64_t val);
uint64_t OSDictionary_GetItem(uint64_t OSDictionary, const char *key);
bool OSDictionary_Merge(uint64_t OSDictionary, uint64_t OSDictionary2);
uint32_t OSDictionary_ItemCount(uint64_t OSDictionary);
uint64_t OSDictionary_ItemBuffer(uint64_t OSDictionary);
uint64_t OSDictionary_ItemKey(uint64_t buffer, uint32_t idx);
uint64_t OSDictionary_ItemValue(uint64_t buffer, uint32_t idx);
uint32_t OSArray_ItemCount(uint64_t OSArray);
bool OSArray_Merge(uint64_t OSArray, uint64_t OSArray2);
uint64_t OSArray_GetObject(uint64_t OSArray, uint32_t idx);
void OSArray_RemoveObject(uint64_t OSArray, uint32_t idx);
uint64_t OSArray_ItemBuffer(uint64_t OSArray);
uint64_t OSObjectFunc(uint64_t OSObject, uint32_t off);
void OSObject_Release(uint64_t OSObject);
void OSObject_Retain(uint64_t OSObject);
uint32_t OSObject_GetRetainCount(uint64_t OSObject);
uint32_t OSString_GetLength(uint64_t OSString);
uint64_t OSString_CStringPtr(uint64_t OSString);
char *OSString_CopyString(uint64_t OSString);
uint64_t OSUnserializeXML(const char *buffer);
uint64_t get_exception_osarray(const char **exceptions);
char **copy_amfi_entitlements(uint64_t present);
uint64_t getOSBool(bool value);
bool entitleProcess(uint64_t amfi_entitlements, const char *key, uint64_t val);
bool unrestrictProcess(pid_t pid);
bool unrestrictProcessWithTaskPort(mach_port_t task_port);
bool revalidateProcess(pid_t pid);
bool revalidateProcessWithTaskPort(mach_port_t task_port);
uint64_t get_amfi_entitlements(uint64_t cr_label);
uint64_t get_sandbox(uint64_t cr_label);
bool entitleProcessWithPid(pid_t pid, const char *key, uint64_t val);
bool removeMemoryLimit(void);

#endif /* kutils_h */
