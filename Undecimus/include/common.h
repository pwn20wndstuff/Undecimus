#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>             // uint*_t
#include <stdbool.h>
#include <mach-o/loader.h>
#include <mach/error.h>
#ifdef __OBJC__
#include <Foundation/Foundation.h>
#define RAWLOG(str, args...) do { NSLog(@str, ##args); } while(false)
#define ADDRSTRING(val) [NSString stringWithFormat:@ADDR, val]
#else
#include <CoreFoundation/CoreFoundation.h>
extern void NSLog(CFStringRef, ...);
#define RAWLOG(str, args...) do { NSLog(CFSTR(str), ##args); } while(false)
#define BOOL bool
#define YES ((BOOL) true)
#define NO ((BOOL) false)
#endif

#define LOG(str, args...) RAWLOG("[*] " str, ##args)

#define SafeFree(x) do { if (x) free(x); } while(false)
#define SafeFreeNULL(x) do { SafeFree(x); (x) = NULL; } while(false)
#define CFSafeRelease(x) do { if (x) CFRelease(x); } while(false)
#define CFSafeReleaseNULL(x) do { CFSafeRelease(x); (x) = NULL; } while(false)
#define SafeSFree(x) do { if (KERN_POINTER_VALID(x)) sfree(x); } while(false)
#define SafeSFreeNULL(x) do { SafeSFree(x); (x) = KPTR_NULL; } while(false)
#define SafeIOFree(x, size) do { if (KERN_POINTER_VALID(x)) IOFree(x, size); } while(false)
#define SafeIOFreeNULL(x, size) do { SafeIOFree(x, size); (x) = KPTR_NULL; } while(false)

#define kCFCoreFoundationVersionNumber_iOS_12_0 1535.12
#define kCFCoreFoundationVersionNumber_iOS_11_3 1452.23
#define kCFCoreFoundationVersionNumber_iOS_11_0 1443.00

#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define ADDR                 "0x%016llx"
#define MACH_HEADER_MAGIC    MH_MAGIC_64
#define MACH_LC_SEGMENT      LC_SEGMENT_64
typedef struct mach_header_64 mach_hdr_t;
typedef struct segment_command_64 mach_seg_t;
typedef struct load_command mach_lc_t;
typedef uint64_t kptr_t;
#define KPTR_NULL ((kptr_t) 0)
#define KERN_POINTER_VALID(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)
#define MAX_KASLR_SLIDE 0x21000000
#define STATIC_KERNEL_BASE_ADDRESS 0xfffffff007004000

extern kptr_t offset_options;
#define OPT(x) (offset_options?((rk64(offset_options) & OPT_ ##x)?true:false):false)
#define SETOPT(x) (offset_options?wk64(offset_options, rk64(offset_options) | OPT_ ##x):0)
#define UNSETOPT(x) (offset_options?wk64(offset_options, rk64(offset_options) & ~OPT_ ##x):0)
#define OPT_GET_TASK_ALLOW (1<<0)
#define OPT_CS_DEBUGGED (1<<1)

#endif

