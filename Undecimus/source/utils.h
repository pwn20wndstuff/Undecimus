//
//  utils.h
//  Undecimus
//
//  Created by Sam Bingner on 11/23/18.
//  Copyright © 2018 - 2019 Sam Bingner. All rights reserved.
//

#ifndef _UTILS_H
#define _UTILS_H
#import <sys/types.h>
#import <sys/stat.h>
#include <mach/machine.h>
#import "ArchiveFile.h"

#define system(x) _system(x)
extern int logfd;
extern bool injectedToTrustCache;
extern NSMutableArray *toInjectToTrustCache;

#define DEFAULT_VERSION_STRING "Hacked"
#define SLIDE_FILE "/var/tmp/slide.txt"

typedef enum {
    empty_list_exploit = 0,
    multi_path_exploit,
    async_wake_exploit,
    voucher_swap_exploit,
    mach_swap_exploit,
    mach_swap_2_exploit,
    deja_xnu_exploit,
    necp_exploit,
    kalloc_crash
} exploit_t;

typedef enum {
    substrate_substitutor = 0,
} substitutor_t;

typedef enum {
    jailbreak_capability = 0,
    respring_capability,
    reboot_capability
} exploit_capability_t;

typedef enum {
    lowest_exploit_reliability = 0,
    low_exploit_reliability,
    middle_exploit_reliability,
    high_exploit_reliability,
    highest_exploit_reliability
} exploit_reliability;

typedef struct {
    const char *min_kernel_version;
    const char *max_kernel_version;
    bool (^handler)(void);
} device_support_info_t;

typedef struct {
    exploit_t exploit;
    const char *name;
    exploit_capability_t exploit_capability;
    exploit_reliability exploit_reliability;
    device_support_info_t device_support_info;
} exploit_info_t;

typedef enum {
    lowest_substitutor_stability = 0,
    low_substitutor_stability,
    middle_substitutor_stability,
    high_substitutor_stability,
    highest_substitutor_stability
} substitutor_stability;

typedef struct {
    substitutor_t substitutor;
    const char *name;
    const char *package_id;
    const char *startup_executable;
    const char *server_executable;
    const char *run_command;
    const char *loader_killswitch;
    const char *bootstrap_tools;
    substitutor_stability substitutor_stability;
    device_support_info_t device_support_info;
    char **resources;
} substitutor_info_t;

extern exploit_info_t *exploit_infos[];
extern substitutor_info_t *substitutor_infos[];

enum hashtype {
    HASHTYPE_MD5 = 0,
    HASHTYPE_SHA1
};
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

@interface LSApplicationWorkspace : NSObject
+ (id) defaultWorkspace;
- (BOOL) registerApplication:(id)application;
- (BOOL) unregisterApplication:(id)application;
- (BOOL) invalidateIconCache:(id)bundle;
- (BOOL) registerApplicationDictionary:(id)application;
- (BOOL) installApplication:(id)application withOptions:(id)options;
- (BOOL) _LSPrivateRebuildApplicationDatabasesForSystemApps:(BOOL)system internal:(BOOL)internal user:(BOOL)user;
- (BOOL) applicationIsInstalled:(id)arg1;
@end

static inline bool create_file_data(const char *file, int owner, mode_t mode, NSData *data) {
    return [[NSFileManager defaultManager] createFileAtPath:@(file) contents:data attributes:@{
               NSFileOwnerAccountID: @(owner),
               NSFileGroupOwnerAccountID: @(owner),
               NSFilePosixPermissions: @(mode)
            }
        ];
}

static inline bool create_file(const char *file, int owner, mode_t mode) {
    return create_file_data(file, owner, mode, nil);
}

static inline bool clean_file(const char *file) {
    NSString *path = @(file);
    if ([[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil]) {
        return [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    }
    return YES;
}

static inline bool init_file(const char *file, int owner, mode_t mode) {
    NSString *path = @(file);
    return ([[NSFileManager defaultManager] fileExistsAtPath:path] &&
            [[NSFileManager defaultManager] setAttributes:@{
                    NSFileOwnerAccountID: @(owner),
                    NSFileGroupOwnerAccountID: @(owner),
                    NSFilePosixPermissions: @(mode)
                } ofItemAtPath:path error:nil]);
}

int sha1_to_str(const unsigned char *hash, size_t hashlen, char *buf, size_t buflen);
NSString *sha1sum(NSString *file);
bool verifySha1Sums(NSString *sumFile);
bool verifySums(NSString *sumFile, enum hashtype hash);
int _system(const char *cmd);
int systemf(const char *cmd, ...);
bool pkgIsInstalled(char *packageID);
bool pkgIsConfigured(char *packageID);
bool pkgIsBy(const char *maintainer, const char *packageID);
bool compareInstalledVersion(const char *packageID, const char *op, const char *version);
bool extractDeb(NSString *debPath, bool doInject);
bool extractDebs(NSArray <NSString *> *debPaths, bool doInject);
bool installDeb(const char *debName, bool forceDeps);
bool installDebs(NSArray <NSString*> *debs, bool forceDeps, bool forceAll);
bool removePkg(char *packageID, bool forceDeps);
bool removePkgs(NSArray <NSString*> *packageIDs, bool forceDeps);
BOOL compareDpkgVersion(NSString *version1, NSString *op, NSString *version2, BOOL *result);
NSString *debForPkg(NSString *pkg);
bool aptUpdate(void);
bool aptInstall(NSArray <NSString*> *pkgs);
bool aptUpgrade(void);
bool aptRepair(void);
bool runApt(NSArray <NSString*> *args);
bool extractAptPkgList(NSString *path, ArchiveFile* listcache, id_t owner);
bool ensureAptPkgLists(void);
bool removeURLFromSources(NSMutableString *sources, NSString *url);
void deduplicateSillySources(void);
bool is_symlink(const char *filename);
bool is_directory(const char *filename);
bool is_mountpoint(const char *filename);
bool ensure_directory(const char *directory, int owner, mode_t mode);
bool ensure_file(const char *file, int owner, mode_t mode);
bool ensure_symlink(const char *to, const char *from);
bool mode_is(const char *filename, mode_t mode);
int runCommandv(const char *cmd, int argc, const char * const* argv, void (^unrestrict)(pid_t));
int runCommand(const char *cmd, ...);
NSString *pathForResource(NSString *resource);
pid_t pidOfProcess(const char *name);
char *getKernelVersion(void);
char *getMachineName(void);
char *getModelName(void);
bool kernelVersionContains(const char *string);
bool machineNameContains(const char *string);
bool multi_path_tcp_enabled(void);
bool jailbreakEnabled(void);
NSString *getKernelBuildVersion(void);
exploit_info_t *get_exploit_info(exploit_t exploit);
substitutor_info_t *get_substitutor_info(substitutor_t substitutor);
bool checkDeviceSupport(device_support_info_t device_support);
bool jailbreakSupported(void);
bool substitutorSupported(void);
bool respringSupported(void);
bool restartSupported(void);
NSInteger recommendedJailbreakSupport(void);
NSInteger recommendedSubstitutorSupport(void);
NSInteger recommendedRestartSupport(void);
NSInteger recommendedRespringSupport(void);
bool daemonIsLoaded(char *daemonID);
NSString *bundledResourcesVersion(void);
NSString *appVersion(void);
bool debuggerEnabled(void);
NSString *getLogFile(void);
void enableLogging(void);
void disableLogging(void);
void cleanLogs(void);
bool modifyPlist(NSString *filename, void (^function)(id));
void list(NSString *directory);
bool canRead(const char *file);
bool restartSpringBoard(void);
bool uninstallRootLessJB(void);
bool verifyECID(NSString *ecid);
bool canOpen(const char *URL);
bool airplaneModeEnabled(void);
bool installApp(const char *bundle);
bool rebuildApplicationDatabases(void);
char *get_path_for_pid(pid_t pid);
NSString *getECID(void);
NSString *getUDID(void);
char *sysctlWithName(const char *name);
char *getOSVersion(void);
char *getOSProductVersion(void);
void printOSDetails(void);
bool isBetaFirmware(void);
double getUptime(void);
vm_size_t get_kernel_page_size(void);
int waitForFile(const char *filename);
NSString *hexFromInt(NSInteger val);
void waitFor(int seconds);
bool blockDomainWithName(const char *name);
bool unblockDomainWithName(const char *name);
bool cydiaIsInstalled(void);
NSString *localize(NSString *str, ...);

extern NSData *lastSystemOutput;

#endif /* _UTILS_H */
