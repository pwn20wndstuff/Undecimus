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
#import "ArchiveFile.h"

#define system(x) _system(x)
extern int logfd;

#define DEFAULT_VERSION_STRING "Hacked"
#define SLIDE_FILE "/var/tmp/slide.txt"

typedef enum {
    empty_list_exploit = 0,
    multi_path_exploit,
    async_wake_exploit,
    voucher_swap_exploit,
    v1ntex_exploit,
    v3ntex_exploit,
    mach_swap_exploit,
    deja_xnu_exploit,
    necp_exploit
} exploit_t;

enum hashtype {
    HASHTYPE_MD5 = 0,
    HASHTYPE_SHA1
};
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

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
bool extractDeb(NSString *debPath);
bool extractDebs(NSArray <NSString *> *debPaths);
bool installDeb(const char *debName, bool forceDeps);
bool installDebs(NSArray <NSString*> *debs, bool forceDeps);
bool removePkg(char *packageID, bool forceDeps);
bool removePkgs(NSArray <NSString*> *packageIDs, bool forceDeps);
BOOL compareDpkgVersion(NSString *version1, NSString *op, NSString *version2, BOOL *result);
NSString *debForPkg(NSString *pkg);
bool aptUpdate(void);
bool aptInstall(NSArray <NSString*> *pkgs);
bool aptUpgrade(void);
bool runApt(NSArray <NSString*> *args);
bool extractAptPkgList(NSString *path, ArchiveFile* listcache, id_t owner);
bool ensureAptPkgLists(void);
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
bool kernelVersionContains(const char *string);
bool machineNameContains(const char *string);
bool multi_path_tcp_enabled(void);
bool jailbreakEnabled(void);
bool supportsExploit(exploit_t exploit);
bool jailbreakSupported(void);
bool respringSupported(void);
bool restartSupported(void);
NSInteger recommendedJailbreakSupport(void);
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

extern NSData *lastSystemOutput;

#endif /* _UTILS_H */
