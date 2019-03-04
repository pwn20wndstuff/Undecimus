//
//  utils.m
//  Undecimus
//
//  Created by Sam Bingner on 11/23/18.
//  Copyright © 2018 - 2019 Sam Bingner. All rights reserved.
//

#import <mach/mach.h>
#import <sys/sysctl.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <magic.h>
#import <spawn.h>
#include <copyfile.h>
#include <common.h>
#include <libproc.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <MobileGestalt.h>
#import <inject.h>
#include <UIKit/UIKit.h>
#include <SystemConfiguration/SystemConfiguration.h>
#import "ArchiveFile.h"
#import "utils.h"
#import "KernelUtilities.h"
#include "machswap_offsets.h"

extern char **environ;
int logfd=-1;

NSData *lastSystemOutput=nil;
void injectDir(NSString *dir) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *toInject = [NSMutableArray new];
    magic_t cookie = magic_open(MAGIC_MIME_TYPE);
    NSString *magicFile = pathForResource(@"macho.mgc");
    if (cookie && magic_load(cookie, magicFile.UTF8String)==0) {
        const char *magic=NULL;
        for (NSString *filename in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            NSString *file = [dir stringByAppendingPathComponent:filename];
            if ((magic = magic_file(cookie, file.UTF8String)))
            {
                if (strcmp(magic, "application/x-mach-binary")==0) {
                    [toInject addObject:file];
                }
            }
        }
    } else {
        LOG("Error opening or loading magic");
    }
    magic_close(cookie);
    LOG("Injecting %lu files for %@", (unsigned long)toInject.count, dir);
    if (toInject.count > 0) {
        injectTrustCache(toInject, GETOFFSET(trustcache));
    }
}

int sha1_to_str(const unsigned char *hash, size_t hashlen, char *buf, size_t buflen)
{
    if (buflen < (hashlen*2+1)) {
        return -1;
    }
    
    int i;
    for (i=0; i<hashlen; i++) {
        sprintf(buf+i*2, "%02X", hash[i]);
    }
    buf[i*2] = 0;
    return ERR_SUCCESS;
}

NSString *sha1sum(NSString *file)
{
    uint8_t buffer[0x1000];
    unsigned char md[CC_SHA1_DIGEST_LENGTH];

    if (![[NSFileManager defaultManager] fileExistsAtPath:file])
        return nil;
    
    NSInputStream *fileStream = [NSInputStream inputStreamWithFileAtPath:file];
    [fileStream open];

    CC_SHA1_CTX c;
    CC_SHA1_Init(&c);
    while ([fileStream hasBytesAvailable]) {
        NSInteger read = [fileStream read:buffer maxLength:0x1000];
        CC_SHA1_Update(&c, buffer, (CC_LONG)read);
    }
    
    CC_SHA1_Final(md, &c);
    
    char checksum[CC_SHA1_DIGEST_LENGTH * 2 + 1];
    if (sha1_to_str(md, CC_SHA1_DIGEST_LENGTH, checksum, sizeof(checksum)) != ERR_SUCCESS)
        return nil;
    return [NSString stringWithUTF8String:checksum];
}

NSString *md5sum(NSString *file)
{
    uint8_t buffer[0x1000];
    unsigned char md[CC_SHA1_DIGEST_LENGTH];
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:file])
        return nil;
    
    NSInputStream *fileStream = [NSInputStream inputStreamWithFileAtPath:file];
    [fileStream open];
    
    CC_MD5_CTX c;
    CC_MD5_Init(&c);
    while ([fileStream hasBytesAvailable]) {
        NSInteger read = [fileStream read:buffer maxLength:0x1000];
        CC_MD5_Update(&c, buffer, (CC_LONG)read);
    }
    
    CC_MD5_Final(md, &c);
    
    char checksum[CC_MD5_DIGEST_LENGTH * 2 + 1];
    if (sha1_to_str(md, CC_MD5_DIGEST_LENGTH, checksum, sizeof(checksum)) != ERR_SUCCESS)
        return nil;
    return [NSString stringWithUTF8String:checksum];
}

bool verifySha1Sums(NSString *sumFile) {
    return verifySums(sumFile, HASHTYPE_SHA1);
}

bool verifySums(NSString *sumFile, enum hashtype hash) {
    if (![[NSFileManager defaultManager] fileExistsAtPath:sumFile])
        return false;
    
    NSString *checksums = [NSString stringWithContentsOfFile:sumFile encoding:NSUTF8StringEncoding error:NULL];
    if (checksums == nil)
        return false;
    
    for (NSString *checksum in [checksums componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        // Ignore blank lines
        if ([checksum isEqualToString:@""])
            continue;

        NSArray<NSString*> *suminfo = [checksum componentsSeparatedByString:@"  "];

        if ([suminfo count] != 2) {
            LOG("Invalid line \"%s\"", checksum.UTF8String);
            return false;
        }
        NSString *fileSum;
        switch (hash) {
            case HASHTYPE_SHA1:
                fileSum = sha1sum(suminfo[1]);
                break;
            case HASHTYPE_MD5:
                fileSum = md5sum(suminfo[1]);
                break;
        }
        if (![fileSum.lowercaseString isEqualToString:suminfo[0]]) {
            LOG("Corrupted \"%s\"", [suminfo[1] UTF8String]);
            return false;
        }
        LOG("Verified \"%s\"", [suminfo[1] UTF8String]);
    }
    LOG("No errors in verifying checksums");
    return true;
}

int _system(const char *cmd) {
    const char *argv[] = {"sh", "-c", (char *)cmd, NULL};
    return runCommandv("/bin/sh", 3, argv, NULL);
}

int systemf(const char *cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    NSString *cmdstr = [[NSString alloc] initWithFormat:@(cmd) arguments:ap];
    va_end(ap);
    return system([cmdstr UTF8String]);
}

bool pkgIsInstalled(char *packageID) {
    int rv = systemf("/usr/bin/dpkg -s \"%s\" 2>/dev/null | grep -i ^Status: | grep -q \"install ok\"", packageID);
    bool isInstalled = !WEXITSTATUS(rv);
    LOG("Deb: \"%s\" is%s installed", packageID, isInstalled?"":" not");
    return isInstalled;
}

bool pkgIsConfigured(char *packageID) {
    int rv = systemf("/usr/bin/dpkg -s \"%s\" 2>/dev/null | grep -i ^Status: | grep -q \"install ok installed\"", packageID);
    bool isConfigured = !WEXITSTATUS(rv);
    LOG("Deb: \"%s\" is%s installed", packageID, isConfigured?"":" not");
    return isConfigured;
}

bool pkgIsBy(const char *maintainer, const char *packageID) {
    int rv = systemf("/usr/bin/dpkg -s \"%s\" 2>/dev/null | grep -i ^Maintainer: | grep -qi \"%s\"", packageID, maintainer);
    bool isBy = !WEXITSTATUS(rv);
    LOG("Deb: \"%s\" is%s by %s", packageID, isBy?"":" not", maintainer);
    return isBy;
}

bool compareInstalledVersion(const char *packageID, const char *op, const char *version) {
    int rv = systemf("/usr/bin/dpkg --compare-versions $(dpkg-query --showformat='${Version}' --show \"%s\") \"%s\" \"%s\"",
                      packageID, op, version);
    rv = !WEXITSTATUS(rv);
    LOG("Deb %s is%s %s %s", packageID, rv?"":" not", op, version);
    return rv;
}

bool runDpkg(NSArray <NSString*> *args, bool forceDeps) {
    if ([args count] < 2) {
        LOG("%s: Nothing to do", __FUNCTION__);
        return false;
    }
    NSMutableArray <NSString*> *command = [NSMutableArray
                arrayWithArray:@[
                        @"/usr/bin/dpkg",
                        @"--force-bad-path",
                        @"--force-configure-any",
                        @"--no-triggers"
                     ]];
    
    if (forceDeps) {
        [command addObjectsFromArray:@[@"--force-depends", @"--force-remove-essential"]];
    }
    for (NSString *arg in args) {
        [command addObject:arg];
    }
    const char *argv[command.count];
    for (int i=0; i<[command count]; i++) {
        argv[i] = [command[i] UTF8String];
    }
    argv[command.count] = NULL;
    int rv = runCommandv("/usr/bin/dpkg", (int)[command count], argv, NULL);
    return !WEXITSTATUS(rv);
}

bool extractDeb(NSString *debPath) {
    if (![debPath hasSuffix:@".deb"]) {
        LOG(@"%@: not a deb", debPath);
        return NO;
    }
    if ([debPath containsString:@"firmware-sbin"]) {
        // No, just no.
        return YES;
    }
    NSPipe *pipe = [NSPipe pipe];
    if (pipe == nil) {
        LOG(@"Unable to make a pipe!");
        return NO;
    }
    ArchiveFile *deb = [ArchiveFile archiveWithFile:debPath];
    if (deb == nil) {
        return NO;
    }
    ArchiveFile *tar = [ArchiveFile archiveWithFd:pipe.fileHandleForReading.fileDescriptor];
    if (tar == nil) {
        return NO;
    }
    LOG("Extracting %@", debPath);
    dispatch_queue_t extractionQueue = dispatch_queue_create(NULL, NULL);
    dispatch_async(extractionQueue, ^{
        [deb extractFileNum:3 toFd:pipe.fileHandleForWriting.fileDescriptor];
    });
    bool result = [tar extractToPath:@"/"];
    if ((kCFCoreFoundationVersionNumber >= 1535.12) && result) {
        chdir("/");
        NSMutableArray *toInject = [NSMutableArray new];
        NSDictionary *files = tar.files;
        magic_t cookie = magic_open(MAGIC_MIME_TYPE);
        LOG("Opened magic");
        NSString *magicFile = pathForResource(@"macho.mgc");
        LOG("MagicFile: %@", magicFile);
        if (cookie && magic_load(cookie, magicFile.UTF8String)==0) {
            LOG("Opened magic");
            const char *magic=NULL;
            for (NSString *file in files.allKeys) {
                mode_t mode = [files[file][@"mode"] integerValue];
                if (!S_ISDIR(mode)) {
                    if ((magic = magic_file(cookie, file.UTF8String)))
                    {
                        LOG("%@: %s", file, magic);
                        if (strcmp(magic, "application/x-mach-binary")==0) {
                            [toInject addObject:file];
                        }
                    }
                }
            }
        } else {
            LOG("Error opening or loading magic");
        }
        magic_close(cookie);
        LOG("Injecting %lu files for %@", (unsigned long)toInject.count, debPath);
        if (toInject.count > 0) {
            injectTrustCache(toInject, GETOFFSET(trustcache));
        }
    }
    return result;
}

bool extractDebs(NSArray <NSString *> *debPaths) {
    if ([debPaths count] < 1) {
        LOG("%s: Nothing to install", __FUNCTION__);
        return false;
    }
    for (NSString *debPath in debPaths) {
        if (!extractDeb(debPath))
            return NO;
    }
    return YES;
}

bool installDeb(const char *debName, bool forceDeps) {
    return runDpkg(@[@"-i", @(debName)], forceDeps);
}

bool installDebs(NSArray <NSString*> *debs, bool forceDeps) {
    if ([debs count] < 1) {
        LOG("%s: Nothing to install", __FUNCTION__);
        return false;
    }
    return runDpkg([@[@"-i"] arrayByAddingObjectsFromArray:debs], forceDeps);
}

bool removePkg(char *packageID, bool forceDeps) {
    return runDpkg(@[@"-r", @(packageID)], forceDeps);
}

bool removePkgs(NSArray <NSString*> *pkgs, bool forceDeps) {
    if ([pkgs count] < 1) {
        LOG("%s: Nothing to remove", __FUNCTION__);
        return false;
    }
    return runDpkg([@[@"-r"] arrayByAddingObjectsFromArray:pkgs], forceDeps);
}

bool runApt(NSArray <NSString*> *args) {
    if ([args count] < 1) {
        LOG("%s: Nothing to do", __FUNCTION__);
        return false;
    }
    NSMutableArray <NSString*> *command = [NSMutableArray arrayWithArray:@[
                        @"/usr/bin/apt-get",
                        @"-o", @"Dir::Etc::sourcelist=undecimus/undecimus.list",
                        @"-o", @"Dir::Etc::sourceparts=-",
                        @"-o", @"APT::Get::List-Cleanup=0"
                        ]];
    [command addObjectsFromArray:args];
    
    const char *argv[command.count];
    for (int i=0; i<[command count]; i++) {
        argv[i] = [command[i] UTF8String];
    }
    argv[command.count] = NULL;
    int rv = runCommandv(argv[0], (int)[command count], argv, NULL);
    return !WEXITSTATUS(rv);
}

bool aptUpdate() {
    return runApt(@[@"update"]);
}

bool aptInstall(NSArray <NSString*> *pkgs) {
    return runApt([@[@"-y", @"--allow-unauthenticated", @"--allow-downgrades", @"install"]
                     arrayByAddingObjectsFromArray:pkgs]);
}

bool aptUpgrade() {
    return runApt(@[@"-y", @"--allow-unauthenticated", @"--allow-downgrades", @"-f", @"dist-upgrade"]);
}

bool extractAptPkgList(NSString *path, ArchiveFile* listcache, id_t owner)
{
    struct stat buf;
    if (stat(path.UTF8String, &buf) != ERR_SUCCESS || !S_ISDIR(buf.st_mode)) {
        if (!ensure_directory(path.UTF8String, owner, 0755)) return false;
        return [listcache extractToPath:path withOwner:owner andGroup:owner];
    }
    return true;
}

bool ensureAptPkgLists() {
    NSString *lists = pathForResource(@"lists.tar.lzma");
    if (!lists) return false;
    ArchiveFile *listsArchive = [ArchiveFile archiveWithFile:lists];
    if (!listsArchive) return false;
    bool success = extractAptPkgList(@"/var/lib/apt/lists", listsArchive, 0);
    return success && extractAptPkgList(@"/var/mobile/Library/Caches/com.saurik.Cydia/lists", listsArchive, 501);
}

bool is_symlink(const char *filename) {
    struct stat buf;
    if (lstat(filename, &buf) != ERR_SUCCESS) {
        return false;
    }
    return S_ISLNK(buf.st_mode);
}

bool is_directory(const char *filename) {
    struct stat buf;
    if (lstat(filename, &buf) != ERR_SUCCESS) {
        return false;
    }
    return S_ISDIR(buf.st_mode);
}

bool is_mountpoint(const char *filename) {
    struct stat buf;
    if (lstat(filename, &buf) != ERR_SUCCESS) {
        return false;
    }

    if (!S_ISDIR(buf.st_mode))
        return false;
    
    char *cwd = getcwd(NULL, 0);
    int rv = chdir(filename);
    assert(rv == ERR_SUCCESS);
    struct stat p_buf;
    rv = lstat("..", &p_buf);
    assert(rv == ERR_SUCCESS);
    if (cwd) {
        chdir(cwd);
        free(cwd);
    }
    return buf.st_dev != p_buf.st_dev || buf.st_ino == p_buf.st_ino;
}

bool ensure_directory(const char *directory, int owner, mode_t mode) {
    NSString *path = @(directory);
    NSFileManager *fm = [NSFileManager defaultManager];
    id attributes = [fm attributesOfItemAtPath:path error:nil];
    if (attributes &&
        [attributes[NSFileType] isEqual:NSFileTypeDirectory] &&
        [attributes[NSFileOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFileGroupOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFilePosixPermissions] isEqual:@(mode)]
        ) {
        // Directory exists and matches arguments
        return true;
    }
    if (attributes) {
        if ([attributes[NSFileType] isEqual:NSFileTypeDirectory]) {
            // Item exists and is a directory
            return [fm setAttributes:@{
                           NSFileOwnerAccountID: @(owner),
                           NSFileGroupOwnerAccountID: @(owner),
                           NSFilePosixPermissions: @(mode)
                           } ofItemAtPath:path error:nil];
        } else if (![fm removeItemAtPath:path error:nil]) {
            // Item exists and is not a directory but could not be removed
            return false;
        }
    }
    // Item does not exist at this point
    return [fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:@{
                   NSFileOwnerAccountID: @(owner),
                   NSFileGroupOwnerAccountID: @(owner),
                   NSFilePosixPermissions: @(mode)
               } error:nil];
}

bool ensure_symlink(const char *to, const char *from) {
    ssize_t wantedLength = strlen(to);
    ssize_t maxLen = wantedLength + 1;
    char link[maxLen];
    ssize_t linkLength = readlink(from, link, sizeof(link));
    if (linkLength != wantedLength ||
        strncmp(link, to, maxLen) != ERR_SUCCESS
        ) {
        if (!clean_file(from)) {
            return false;
        }
        if (symlink(to, from) != ERR_SUCCESS) {
            return false;
        }
    }
    return true;
}

bool ensure_file(const char *file, int owner, mode_t mode) {
    NSString *path = @(file);
    NSFileManager *fm = [NSFileManager defaultManager];
    id attributes = [fm attributesOfItemAtPath:path error:nil];
    if (attributes &&
        [attributes[NSFileType] isEqual:NSFileTypeRegular] &&
        [attributes[NSFileOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFileGroupOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFilePosixPermissions] isEqual:@(mode)]
        ) {
        // File exists and matches arguments
        return true;
    }
    if (attributes) {
        if ([attributes[NSFileType] isEqual:NSFileTypeRegular]) {
            // Item exists and is a file
            return [fm setAttributes:@{
                                       NSFileOwnerAccountID: @(owner),
                                       NSFileGroupOwnerAccountID: @(owner),
                                       NSFilePosixPermissions: @(mode)
                                       } ofItemAtPath:path error:nil];
        } else if (![fm removeItemAtPath:path error:nil]) {
            // Item exists and is not a file but could not be removed
            return false;
        }
    }
    // Item does not exist at this point
    return [fm createFileAtPath:path contents:nil attributes:@{
                               NSFileOwnerAccountID: @(owner),
                               NSFileGroupOwnerAccountID: @(owner),
                               NSFilePosixPermissions: @(mode)
                               }];
}

bool mode_is(const char *filename, mode_t mode) {
    struct stat buf;
    if (lstat(filename, &buf) != ERR_SUCCESS) {
        return false;
    }
    return buf.st_mode == mode;
}

int runCommandv(const char *cmd, int argc, const char * const* argv, void (^unrestrict)(pid_t)) {
    pid_t pid;
    posix_spawn_file_actions_t *actions = NULL;
    posix_spawn_file_actions_t actionsStruct;
    int out_pipe[2];
    bool valid_pipe = false;
    posix_spawnattr_t *attr = NULL;
    posix_spawnattr_t attrStruct;
    
    NSMutableString *cmdstr = [NSMutableString stringWithCString:cmd encoding:NSUTF8StringEncoding];
    for (int i=1; i<argc; i++) {
        [cmdstr appendFormat:@" \"%s\"", argv[i]];
    }

    valid_pipe = pipe(out_pipe) == ERR_SUCCESS;
    if (valid_pipe && posix_spawn_file_actions_init(&actionsStruct) == ERR_SUCCESS) {
        actions = &actionsStruct;
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 2);
        posix_spawn_file_actions_addclose(actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(actions, out_pipe[1]);
    }
    
    if (unrestrict && posix_spawnattr_init(&attrStruct) == ERR_SUCCESS) {
        attr = &attrStruct;
        posix_spawnattr_setflags(attr, POSIX_SPAWN_START_SUSPENDED);
    }
    
    int rv = posix_spawn(&pid, cmd, actions, attr, (char *const *)argv, environ);
    LOG("%s(%d) command: %@", __FUNCTION__, pid, cmdstr);
    
    if (unrestrict) {
        unrestrict(pid);
        kill(pid, SIGCONT);
    }
    
    if (valid_pipe) {
        close(out_pipe[1]);
    }
    
    if (rv == ERR_SUCCESS) {
        if (valid_pipe) {
            NSMutableData *outData = [NSMutableData new];
            char c;
            char s[2] = {0, 0};
            NSMutableString *line = [NSMutableString new];
            while (read(out_pipe[0], &c, 1) == 1) {
                [outData appendBytes:&c length:1];
                if (c == '\n') {
                    LOG("%s(%d): %@", __FUNCTION__, pid, line);
                    [line setString:@""];
                } else {
                    s[0] = c;
                    [line appendString:@(s)];
                }
            }
            if ([line length] > 0) {
                LOG("%s(%d): %@", __FUNCTION__, pid, line);
            }
            lastSystemOutput = [outData copy];
        }
        if (waitpid(pid, &rv, 0) == -1) {
            LOG("ERROR: Waitpid failed");
        } else {
            LOG("%s(%d) completed with exit status %d", __FUNCTION__, pid, WEXITSTATUS(rv));
        }
        
    } else {
        LOG("%s(%d): ERROR posix_spawn failed (%d): %s", __FUNCTION__, pid, rv, strerror(rv));
        rv <<= 8; // Put error into WEXITSTATUS
    }
    if (valid_pipe) {
        close(out_pipe[0]);
    }
    return rv;
}

int runCommand(const char *cmd, ...) {
    va_list ap, ap2;
    int argc = 1;

    va_start(ap, cmd);
    va_copy(ap2, ap);

    while (va_arg(ap, const char *) != NULL) {
        argc++;
    }
    va_end(ap);
    
    const char *argv[argc+1];
    argv[0] = cmd;
    for (int i=1; i<argc; i++) {
        argv[i] = va_arg(ap2, const char *);
    }
    va_end(ap2);
    argv[argc] = NULL;

    int rv = runCommandv(cmd, argc, argv, NULL);
    return WEXITSTATUS(rv);
}

NSString *pathForResource(NSString *resource) {
    static NSString *sourcePath;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sourcePath = [[NSBundle mainBundle] bundlePath];
    });
    
    NSString *path = [[sourcePath stringByAppendingPathComponent:resource] stringByStandardizingPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return nil;
    }
    return path;
}

pid_t pidOfProcess(const char *name) {
    int numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    pid_t pids[numberOfProcesses];
    bzero(pids, sizeof(pids));
    proc_listpids(PROC_ALL_PIDS, 0, pids, (int)sizeof(pids));
    for (int i = 0; i < numberOfProcesses; ++i) {
        if (pids[i] == 0) {
            continue;
        }
        char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
        bzero(pathBuffer, PROC_PIDPATHINFO_MAXSIZE);
        proc_pidpath(pids[i], pathBuffer, sizeof(pathBuffer));
        if (strlen(pathBuffer) > 0 && strcmp(pathBuffer, name) == 0) {
            return pids[i];
        }
    }
    return 0;
}

bool kernelVersionContains(const char *string) {
    static struct utsname u = { 0 };
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uname(&u);
    });
    return (strstr(u.version, string) != NULL);
}

bool machineNameContains(const char *string) {
    static struct utsname u = { 0 };
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uname(&u);
    });
    return (strstr(u.machine, string) != NULL);
}

#define AF_MULTIPATH 39

bool multi_path_tcp_enabled() {
    static bool enabled = false;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        int sock = socket(AF_MULTIPATH, SOCK_STREAM, 0);
        if (sock < 0) {
            return;
        }
        struct sockaddr* sockaddr_src = malloc(sizeof(struct sockaddr));
        memset(sockaddr_src, 'A', sizeof(struct sockaddr));
        sockaddr_src->sa_len = sizeof(struct sockaddr);
        sockaddr_src->sa_family = AF_INET6;
        struct sockaddr* sockaddr_dst = malloc(sizeof(struct sockaddr));
        memset(sockaddr_dst, 'A', sizeof(struct sockaddr));
        sockaddr_dst->sa_len = sizeof(struct sockaddr);
        sockaddr_dst->sa_family = AF_INET;
        sa_endpoints_t eps = {0};
        eps.sae_srcif = 0;
        eps.sae_srcaddr = sockaddr_src;
        eps.sae_srcaddrlen = sizeof(struct sockaddr);
        eps.sae_dstaddr = sockaddr_dst;
        eps.sae_dstaddrlen = sizeof(struct sockaddr);
        connectx(sock, &eps, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL);
        enabled = (errno != EPERM);
        free(sockaddr_src);
        free(sockaddr_dst);
        close(sock);
    });
    return enabled;
}

bool jailbreakEnabled() {
    return kernelVersionContains(DEFAULT_VERSION_STRING) ||
    access(SLIDE_FILE, F_OK) == ERR_SUCCESS;
}

bool supportsExploit(exploit_t exploit) {
#ifdef CAN_HAS_UNSUPPORTED_EXPLOIT
    return true;
#else /* !CAN_HAS_UNSUPPORTED_EXPLOIT */
    static NSArray *list;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        list = @[
                 // Empty List
                 @[@"4397.0.0.2.4~1",
                   @"4481.0.0.2.1~1",
                   @"4532.0.0.0.1~30",
                   @"4556.0.0.2.5~1",
                   @"4570.1.24.2.3~1",
                   @"4570.2.3~8",
                   @"4570.2.5~84",
                   @"4570.2.5~167",
                   @"4570.7.2~3",
                   @"4570.20.55~10",
                   @"4570.20.62~9",
                   @"4570.20.62~4",
                   @"4570.30.79~22",
                   @"4570.30.85~18",
                   @"4570.32.1~2",
                   @"4570.32.1~1",
                   @"4570.40.6~8",
                   @"4570.40.9~7",
                   @"4570.40.9~1",
                   @"4570.50.243~9",
                   @"4570.50.257~6",
                   @"4570.50.279~9",
                   @"4570.50.294~5",
                   @"4570.52.2~3",
                   @"4570.52.2~8",
                   @"4570.60.10.0.1~16",
                   @"4570.60.16~9",
                   @"4570.60.19~25"],
                 
                 // Multi Path
                 @[@"4397.0.0.2.4~1",
                   @"4481.0.0.2.1~1",
                   @"4532.0.0.0.1~30",
                   @"4556.0.0.2.5~1",
                   @"4570.1.24.2.3~1",
                   @"4570.2.3~8",
                   @"4570.2.5~84",
                   @"4570.2.5~167",
                   @"4570.7.2~3",
                   @"4570.20.55~10",
                   @"4570.20.62~9",
                   @"4570.20.62~4",
                   @"4570.30.79~22",
                   @"4570.30.85~18",
                   @"4570.32.1~2",
                   @"4570.32.1~1",
                   @"4570.40.6~8",
                   @"4570.40.9~7",
                   @"4570.40.9~1",
                   @"4570.50.243~9",
                   @"4570.50.257~6",
                   @"4570.50.279~9",
                   @"4570.50.294~5",
                   @"4570.52.2~3",
                   @"4570.52.2~8",],
                 
                 // Async Wake
                 @[@"4397.0.0.2.4~1",
                   @"4481.0.0.2.1~1",
                   @"4532.0.0.0.1~30",
                   @"4556.0.0.2.5~1",
                   @"4570.1.24.2.3~1",
                   @"4570.2.3~8",
                   @"4570.2.5~84",
                   @"4570.2.5~167",
                   @"4570.7.2~3",
                   @"4570.20.55~10",
                   @"4570.20.62~9",
                   @"4570.20.62~4"],
                 
                 // Voucher Swap
                 @[@"4397.0.0.2.4~1",
                   @"4481.0.0.2.1~1",
                   @"4532.0.0.0.1~30",
                   @"4556.0.0.2.5~1",
                   @"4570.1.24.2.3~1",
                   @"4570.2.3~8",
                   @"4570.2.5~84",
                   @"4570.2.5~167",
                   @"4570.7.2~3",
                   @"4570.20.55~10",
                   @"4570.20.62~9",
                   @"4570.20.62~4",
                   @"4570.30.79~22",
                   @"4570.30.85~18",
                   @"4570.32.1~2",
                   @"4570.32.1~1",
                   @"4570.40.6~8",
                   @"4570.40.9~7",
                   @"4570.40.9~1",
                   @"4570.50.243~9",
                   @"4570.50.257~6",
                   @"4570.50.279~9",
                   @"4570.50.294~5",
                   @"4570.52.2~3",
                   @"4570.52.2~8",
                   @"4570.60.10.0.1~16",
                   @"4570.60.16~9",
                   @"4570.60.19~25",
                   @"4570.60.21~7",
                   @"4570.60.21~3",
                   @"4570.70.14~16",
                   @"4570.70.19~13",
                   @"4570.70.24~9",
                   @"4570.70.24~3",
                   @"4903.200.199.12.3~1",
                   @"4903.200.249.22.3~1",
                   @"4903.200.274.32.3~1",
                   @"4903.200.304.42.1~1",
                   @"4903.200.327.52.1~1",
                   @"4903.200.342.62.3~1",
                   @"4903.200.354~11",
                   @"4903.202.1~2",
                   @"4903.202.2~2",
                   @"4903.202.2~1",
                   @"4903.220.42~21",
                   @"4903.220.48~40",
                   @"4903.222.1~7",
                   @"4903.222.4~3",
                   @"4903.222.5~3",
                   @"4903.222.5~1",
                   @"4903.230.15~8",
                   @"4903.232.1~3",
                   @"4903.232.2~2",
                   @"4903.232.2~1",
                   @"4903.240.8~8",
                   @"4903.232.2~1"],
                 
                 // V1ntex
                 @[@"4570.20.55~10",
                   @"4570.20.62~9",
                   @"4570.20.62~4",
                   @"4570.30.79~22",
                   @"4570.30.85~18",
                   @"4570.32.1~2",
                   @"4570.32.1~1",
                   @"4570.40.6~8",
                   @"4570.40.9~7",
                   @"4570.40.9~1",
                   @"4570.50.243~9",
                   @"4570.50.257~6",
                   @"4570.50.279~9",
                   @"4570.50.294~5",
                   @"4570.52.2~3",
                   @"4570.52.2~8",
                   @"4570.60.10.0.1~16",
                   @"4570.60.16~9",
                   @"4570.60.19~25",
                   @"4570.60.21~7",
                   @"4570.60.21~3",
                   @"4570.70.14~16",
                   @"4570.70.19~13",
                   @"4570.70.24~9",
                   @"4570.70.24~3"],
                 
                 // V3ntex
                 @[@"4903.200.199.12.3~1",
                   @"4903.200.249.22.3~1",
                   @"4903.200.274.32.3~1",
                   @"4903.200.304.42.1~1",
                   @"4903.200.327.52.1~1",
                   @"4903.200.342.62.3~1",
                   @"4903.200.354~11",
                   @"4903.202.1~2",
                   @"4903.202.2~2",
                   @"4903.202.2~1",
                   @"4903.220.42~21",
                   @"4903.220.48~40",
                   @"4903.222.1~7",
                   @"4903.222.4~3",
                   @"4903.222.5~3",
                   @"4903.222.5~1",
                   @"4903.230.15~8",
                   @"4903.232.1~3",
                   @"4903.232.2~2",
                   @"4903.232.2~1",
                   @"4903.240.8~8",
                   @"4903.232.2~1"],
                 
                 // Mach Swap
                 @[@"4397.0.0.2.4~1",
                   @"4481.0.0.2.1~1",
                   @"4532.0.0.0.1~30",
                   @"4556.0.0.2.5~1",
                   @"4570.1.24.2.3~1",
                   @"4570.2.3~8",
                   @"4570.2.5~84",
                   @"4570.2.5~167",
                   @"4570.7.2~3",
                   @"4570.20.55~10",
                   @"4570.20.62~9",
                   @"4570.20.62~4",
                   @"4570.30.79~22",
                   @"4570.30.85~18",
                   @"4570.32.1~2",
                   @"4570.32.1~1",
                   @"4570.40.6~8",
                   @"4570.40.9~7",
                   @"4570.40.9~1",
                   @"4570.50.243~9",
                   @"4570.50.257~6",
                   @"4570.50.279~9",
                   @"4570.50.294~5",
                   @"4570.52.2~3",
                   @"4570.52.2~8",
                   @"4570.60.10.0.1~16",
                   @"4570.60.16~9",
                   @"4570.60.19~25",
                   @"4570.60.21~7",
                   @"4570.60.21~3",
                   @"4570.70.14~16",
                   @"4570.70.19~13",
                   @"4570.70.24~9",
                   @"4570.70.24~3",
                   @"4903.200.199.12.3~1",
                   @"4903.200.249.22.3~1",
                   @"4903.200.274.32.3~1",
                   @"4903.200.304.42.1~1",
                   @"4903.200.327.52.1~1",
                   @"4903.200.342.62.3~1",
                   @"4903.200.354~11",
                   @"4903.202.1~2",
                   @"4903.202.2~2",
                   @"4903.202.2~1",
                   @"4903.220.42~21",
                   @"4903.220.48~40",
                   @"4903.222.1~7",
                   @"4903.222.4~3",
                   @"4903.222.5~3",
                   @"4903.222.5~1",
                   @"4903.230.15~8",
                   @"4903.232.1~3",
                   @"4903.232.2~2",
                   @"4903.232.2~1",
                   @"4903.240.8~8",
                   @"4903.232.2~1"],
                 
                 // Deja Xnu
                 @[@"4397.0.0.2.4~1",
                   @"4481.0.0.2.1~1",
                   @"4532.0.0.0.1~30",
                   @"4556.0.0.2.5~1",
                   @"4570.1.24.2.3~1",
                   @"4570.2.3~8",
                   @"4570.2.5~84",
                   @"4570.2.5~167",
                   @"4570.7.2~3",
                   @"4570.20.55~10",
                   @"4570.20.62~9",
                   @"4570.20.62~4",
                   @"4570.30.79~22",
                   @"4570.30.85~18",
                   @"4570.32.1~2",
                   @"4570.32.1~1",
                   @"4570.40.6~8",
                   @"4570.40.9~7",
                   @"4570.40.9~1",
                   @"4570.50.243~9",
                   @"4570.50.257~6",
                   @"4570.50.279~9",
                   @"4570.50.294~5",
                   @"4570.52.2~3",
                   @"4570.52.2~8",
                   @"4570.60.10.0.1~16",
                   @"4570.60.16~9",
                   @"4570.60.19~25",
                   @"4570.60.21~7",
                   @"4570.60.21~3",
                   @"4570.70.14~16",
                   @"4570.70.19~13",
                   @"4570.70.24~9",
                   @"4570.70.24~3"],
                 
                 // Necp
                 @[@"4397.0.0.2.4~1",
                   @"4481.0.0.2.1~1",
                   @"4532.0.0.0.1~30",
                   @"4556.0.0.2.5~1",
                   @"4570.1.24.2.3~1",
                   @"4570.2.3~8",
                   @"4570.2.5~84",
                   @"4570.2.5~167",
                   @"4570.7.2~3",
                   @"4570.20.55~10",
                   @"4570.20.62~9",
                   @"4570.20.62~4",
                   @"4570.30.79~22",
                   @"4570.30.85~18",
                   @"4570.32.1~2",
                   @"4570.32.1~1",
                   @"4570.40.6~8",
                   @"4570.40.9~7",
                   @"4570.40.9~1",
                   @"4570.50.243~9",
                   @"4570.50.257~6",
                   @"4570.50.279~9",
                   @"4570.50.294~5",
                   @"4570.52.2~3",
                   @"4570.52.2~8",
                   @"4570.60.10.0.1~16",
                   @"4570.60.16~9",
                   @"4570.60.19~25",
                   @"4570.60.21~7",
                   @"4570.60.21~3",
                   @"4570.70.14~16",
                   @"4570.70.19~13",
                   @"4570.70.24~9",
                   @"4570.70.24~3"],
                 
                 // Voucher Swap Poc
                 @[@"4397.0.0.2.4~1",
                   @"4481.0.0.2.1~1",
                   @"4532.0.0.0.1~30",
                   @"4556.0.0.2.5~1",
                   @"4570.1.24.2.3~1",
                   @"4570.2.3~8",
                   @"4570.2.5~84",
                   @"4570.2.5~167",
                   @"4570.7.2~3",
                   @"4570.20.55~10",
                   @"4570.20.62~9",
                   @"4570.20.62~4",
                   @"4570.30.79~22",
                   @"4570.30.85~18",
                   @"4570.32.1~2",
                   @"4570.32.1~1",
                   @"4570.40.6~8",
                   @"4570.40.9~7",
                   @"4570.40.9~1",
                   @"4570.50.243~9",
                   @"4570.50.257~6",
                   @"4570.50.279~9",
                   @"4570.50.294~5",
                   @"4570.52.2~3",
                   @"4570.52.2~8",
                   @"4570.60.10.0.1~16",
                   @"4570.60.16~9",
                   @"4570.60.19~25",
                   @"4570.60.21~7",
                   @"4570.60.21~3",
                   @"4570.70.14~16",
                   @"4570.70.19~13",
                   @"4570.70.24~9",
                   @"4570.70.24~3",
                   @"4903.200.199.12.3~1",
                   @"4903.200.249.22.3~1",
                   @"4903.200.274.32.3~1",
                   @"4903.200.304.42.1~1",
                   @"4903.200.327.52.1~1",
                   @"4903.200.342.62.3~1",
                   @"4903.200.354~11",
                   @"4903.202.1~2",
                   @"4903.202.2~2",
                   @"4903.202.2~1",
                   @"4903.220.42~21",
                   @"4903.220.48~40",
                   @"4903.222.1~7",
                   @"4903.222.4~3",
                   @"4903.222.5~3",
                   @"4903.222.5~1",
                   @"4903.230.15~8",
                   @"4903.232.1~3",
                   @"4903.232.2~2",
                   @"4903.232.2~1",
                   @"4903.240.8~8",
                   @"4903.232.2~1"],
                 ];
    });
    
    switch (exploit) {
        case multi_path_exploit: {
            if (!multi_path_tcp_enabled()) {
                return false;
            }
            break;
        }
        case voucher_swap_exploit: {
            if (vm_kernel_page_size != 0x4000) {
                return false;
            }
            if (machineNameContains("iPad5,") && kCFCoreFoundationVersionNumber >= 1535.12) {
                return false;
            }
            if (machineNameContains("iPhone11,") || machineNameContains("iPad8,")) {
                return false;
            }
            break;
        }
        case v1ntex_exploit: {
            if (vm_kernel_page_size != 0x1000) {
                return false;
            }
            break;
        }
        case v3ntex_exploit: {
            if (vm_kernel_page_size != 0x1000 && !machineNameContains("iPad5,")) {
                return false;
            }
            break;
        }
        case mach_swap_exploit: {
            if (vm_kernel_page_size != 0x1000 && !machineNameContains("iPad5,") && !machineNameContains("iPhone8,")) {
                return false;
            }
            if (get_machswap_offsets() == NULL) {
                return false;
            }
            break;
        }
        case deja_xnu_exploit: {
            if (jailbreakEnabled())
                return false;
            break;
        }
        case empty_list_exploit:
            break;
        case async_wake_exploit:
            break;
        case necp_exploit:
            break;
        case voucher_swap_poc_exploit:
            break;
        default:
            return false;
            break;
    }
    
    for (NSString *string in list[exploit]) {
        if (kernelVersionContains(string.UTF8String)) {
            return true;
        }
    }

    return false;
#endif /* !CAN_HAS_UNSUPPORTED_EXPLOIT */
}

bool jailbreakSupported() {
    return supportsExploit(empty_list_exploit) ||
    supportsExploit(multi_path_exploit) ||
    supportsExploit(async_wake_exploit) ||
    supportsExploit(voucher_swap_exploit) ||
    supportsExploit(v1ntex_exploit) ||
    supportsExploit(v3ntex_exploit) ||
    supportsExploit(mach_swap_exploit);
}

bool respringSupported() {
    return supportsExploit(deja_xnu_exploit);
}

bool restartSupported() {
    return supportsExploit(necp_exploit) ||
    supportsExploit(voucher_swap_poc_exploit);
}

NSInteger recommendedJailbreakSupport() {
    if (supportsExploit(mach_swap_exploit))
        return mach_swap_exploit;
    else if (supportsExploit(async_wake_exploit))
        return async_wake_exploit;
    else if (supportsExploit(voucher_swap_exploit))
        return voucher_swap_exploit;
    else if (supportsExploit(multi_path_exploit))
        return multi_path_exploit;
    else if (supportsExploit(v1ntex_exploit))
        return v1ntex_exploit;
    else if (supportsExploit(empty_list_exploit))
        return empty_list_exploit;
    else if (supportsExploit(v3ntex_exploit))
        return v3ntex_exploit;
    else
        return -1;
}

NSInteger recommendedRestartSupport() {
    if (supportsExploit(necp_exploit))
        return necp_exploit;
    else if (supportsExploit(voucher_swap_poc_exploit))
        return voucher_swap_poc_exploit;
    else
        return -1;
}

NSInteger recommendedRespringSupport() {
    if (supportsExploit(deja_xnu_exploit))
        return deja_xnu_exploit;
    else
        return -1;
}

bool daemonIsLoaded(char *daemonID) {
    int rv = systemf("/bin/launchctl list | grep %s", daemonID);
    bool isLoaded = !WEXITSTATUS(rv);
    LOG("Daemon: \"%s\" is%s loaded", daemonID, isLoaded?"":" not");
    return isLoaded;
}

NSString *bundledResourcesVersion() {
    NSBundle *bundle = [NSBundle mainBundle];
    return [bundle objectForInfoDictionaryKey:@"BundledResources"];
}

NSString *appVersion() {
    NSBundle *bundle = [NSBundle mainBundle];
    return [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
}

bool debuggerEnabled() {
    return (getppid() != 1);
}

NSString *getLogFile() {
    static NSString *logfile;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        logfile = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/log_file.txt"];
    });
    return logfile;
}

void enableLogging() {
    if (!debuggerEnabled()) {
        int old_logfd = logfd;
        int newfd = open(getLogFile().UTF8String, O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (newfd < 0) {
            LOG("Error opening logfile: %s", strerror(errno));
        }
        logfd = newfd;
        if (old_logfd > 0)
            close(old_logfd);
    }
}

void disableLogging() {
    if (!debuggerEnabled()) {
        int old_logfd = logfd;
        logfd = -1;
        if (old_logfd > 0)
            close(old_logfd);
    }
}

void cleanLogs() {
    const char *logFile = getLogFile().UTF8String;
    clean_file(logFile);
    enableLogging();
}

bool modifyPlist(NSString *filename, void (^function)(id)) {
    LOG("%s: Will modify plist: %@", __FUNCTION__, filename);
    NSData *data = [NSData dataWithContentsOfFile:filename];
    if (data == nil) {
        LOG("%s: Failed to read file: %@", __FUNCTION__, filename);
        return false;
    }
    NSPropertyListFormat format = 0;
    NSError *error = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves format:&format error:&error];
    if (plist == nil) {
        LOG("%s: Failed to generate plist data: %@", __FUNCTION__, error);
        return false;
    }
    if (function) {
        function(plist);
    }
    NSData *newData = [NSPropertyListSerialization dataWithPropertyList:plist format:format options:0 error:&error];
    if (newData == nil) {
        LOG("%s: Failed to generate new plist data: %@", __FUNCTION__, error);
        return false;
    }
    if (![data isEqual:newData]) {
        LOG("%s: Writing to file: %@", __FUNCTION__, filename);
        if (![newData writeToFile:filename atomically:YES]) {
            LOG("%s: Failed to write to file: %@", __FUNCTION__, filename);
            return false;
        }
    }
    LOG("%s: Success", __FUNCTION__);
    return true;
}

void list(NSString *directory) {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSArray *listArray = [fileManager contentsOfDirectoryAtPath:directory error:nil];
    LOG(@"%s(%@): %@", __FUNCTION__, directory, listArray);
}

bool canRead(const char *file) {
    NSString *path = @(file);
    NSFileManager *fileManager = [NSFileManager defaultManager];
    return ([fileManager attributesOfItemAtPath:path error:nil]);
}

bool restartSpringBoard() {
    pid_t backboardd_pid = pidOfProcess("/usr/libexec/backboardd");
    if (!(backboardd_pid > 1)) {
        LOG("Unable to find backboardd pid.");
        return false;
    }
    if (kill(backboardd_pid, SIGTERM) != ERR_SUCCESS) {
        LOG("Unable to terminate backboardd.");
        return false;
    }
    return true;
}

bool uninstallRootLessJB() {
    BOOL foundRootLessJB = NO;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSString *rootLessJBBootstrapMarkerFile = @"/var/containers/Bundle/.installed_rootlessJB3";
    NSArray *rootLessJBFileList = @[@"/var/LIB", @"/var/ulb", @"/var/bin", @"/var/sbin", @"/var/libexec", @"/var/containers/Bundle/tweaksupport/Applications", @"/var/Apps", @"/var/profile", @"/var/motd", @"/var/dropbear", @"/var/containers/Bundle/tweaksupport", @"/var/containers/Bundle/iosbinpack64", @"/var/log/testbin.log", @"/var/log/jailbreakd-stdout.log", @"/var/log/jailbreakd-stderr.log", @"/var/log/pspawn_payload_xpcproxy.log", @"/var/lib", @"/var/etc", @"/var/usr", rootLessJBBootstrapMarkerFile];
    if ([fileManager fileExistsAtPath:rootLessJBBootstrapMarkerFile]) {
        LOG("Found RootLessJB.");
        foundRootLessJB = YES;
    }
    if (foundRootLessJB) {
        LOG("Uninstalling RootLessJB...");
        for (NSString *file in rootLessJBFileList) {
            if ([fileManager fileExistsAtPath:file] && ![fileManager removeItemAtPath:file error:nil]) {
                LOG("Unable to remove file: %@", file);
                return false;
            }
        }
    }
    return true;
}

bool verifyECID(NSString *ecid) {
    CFStringRef value = MGCopyAnswer(kMGUniqueChipID);
    if (value == nil) {
        LOG("Unable to get ECID.");
        return false;
    }
    if (![ecid isEqualToString:CFBridgingRelease(value)]) {
        LOG("Unable to verify ECID.");
        return false;
    }
    return true;
}

bool canOpen(const char *URL) {
    __block bool canOpenURL = false;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@(URL)]]) {
            canOpenURL = true;
        }
        dispatch_semaphore_signal(semaphore);
    });
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return canOpenURL;
}

bool airplaneModeEnabled() {
    struct sockaddr_in zeroAddress;
    bzero(&zeroAddress, sizeof(zeroAddress));
    zeroAddress.sin_len = sizeof(zeroAddress);
    zeroAddress.sin_family = AF_INET;
    SCNetworkReachabilityRef reachability = SCNetworkReachabilityCreateWithAddress(kCFAllocatorDefault, (const struct sockaddr *)&zeroAddress);
    if (reachability == NULL)
        return false;
    SCNetworkReachabilityFlags flags;
    if (!SCNetworkReachabilityGetFlags(reachability, &flags)) {
        return false;
    }
    if (flags == 0) {
        return true;
    } else {
        return false;
    }
}

