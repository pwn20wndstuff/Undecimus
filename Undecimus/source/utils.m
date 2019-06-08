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

extern char **environ;
int logfd=-1;

bool injectedToTrustCache = false;
NSMutableArray *toInjectToTrustCache = nil;

exploit_info_t *exploit_infos[] = {
    &(exploit_info_t)
    {
        .exploit = empty_list_exploit,
        .name = "Empty List",
        .exploit_capability = jailbreak_capability,
        .exploit_reliability = lowest_exploit_reliability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4570.60.19~25",
        .device_support_info.handler = NULL,
    },
    &(exploit_info_t)
    {
        .exploit = multi_path_exploit,
        .name = "Multi Path",
        .exploit_capability = jailbreak_capability,
        .exploit_reliability = low_exploit_reliability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4570.52.2~8",
        .device_support_info.handler = ^bool (void) {
            if (!multi_path_tcp_enabled())
                return false;
            return true;
        },
    },
    &(exploit_info_t)
    {
        .exploit = async_wake_exploit,
        .name = "Async Wake",
        .exploit_capability = jailbreak_capability,
        .exploit_reliability = highest_exploit_reliability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4570.20.62~4",
        .device_support_info.handler = NULL,
    },
    &(exploit_info_t)
    {
        .exploit = voucher_swap_exploit,
        .name = "Voucher Swap",
        .exploit_capability = jailbreak_capability,
        .exploit_reliability = high_exploit_reliability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4903.240.8~8",
        .device_support_info.handler = ^bool (void) {
            if (get_kernel_page_size() != 0x4000)
                return false;
            else if (machineNameContains("iPad5,") && kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0)
                return false;
            return true;
        },
    },
    &(exploit_info_t)
    {
        .exploit = mach_swap_exploit,
        .name = "Mach Swap",
        .exploit_capability = jailbreak_capability,
        .exploit_reliability = middle_exploit_reliability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4903.240.8~8",
        .device_support_info.handler = ^bool (void) {
            if (get_kernel_page_size() != 0x1000 &&
                !machineNameContains("iPad5,") &&
                !machineNameContains("iPhone8,") &&
                !machineNameContains("iPad6,"))
                return false;
            return true;
        },
    },
    &(exploit_info_t)
    {
        .exploit = mach_swap_2_exploit,
        .name = "Mach Swap 2",
        .exploit_capability = jailbreak_capability,
        .exploit_reliability = middle_exploit_reliability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4903.240.8~8",
        .device_support_info.handler = NULL,
    },
    &(exploit_info_t)
    {
        .exploit = deja_xnu_exploit,
        .name = "Deja XNU",
        .exploit_capability = respring_capability,
        .exploit_reliability = middle_exploit_reliability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4570.70.24~9",
        .device_support_info.handler = ^bool (void) {
            if (jailbreakEnabled())
                return false;
            return true;
        },
    },
    &(exploit_info_t)
    {
        .exploit = necp_exploit,
        .name = "Necp",
        .exploit_capability = reboot_capability,
        .exploit_reliability = highest_exploit_reliability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4570.70.24~9",
        .device_support_info.handler = NULL,
    },
    &(exploit_info_t)
    {
        .exploit = kalloc_crash,
        .name = "Kalloc Crash",
        .exploit_capability = reboot_capability,
        .exploit_reliability = high_exploit_reliability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4903.252.2~2",
        .device_support_info.handler = NULL,
    },
    NULL,
};

substitutor_info_t *substitutor_infos[] = {
    &(substitutor_info_t)
    {
        .substitutor = substrate_substitutor,
        .name = "Substrate",
        .package_id = "mobilesubstrate",
        .startup_executable = "/usr/libexec/substrate",
        .server_executable = "/usr/libexec/substrated",
        .run_command = "/etc/rc.d/substrate",
        .loader_killswitch = "/var/tmp/.substrated_disable_loader",
        .bootstrap_tools = "/usr/lib/substrate",
        .substitutor_stability = highest_substitutor_stability,
        .device_support_info.min_kernel_version = "4397.0.0.2.4~1",
        .device_support_info.max_kernel_version = "4903.240.8~8",
        .device_support_info.handler = ^bool (void) {
            if (machineNameContains("iPhone11,") || machineNameContains("iPad8,"))
                return false;
            return true;
        },
        .resources = (char **)&(const char*[]) {
            "/usr/libexec/substrate",
            "/usr/libexec/substrated",
            NULL,
        },
    },
    NULL,
};

NSData *lastSystemOutput=nil;
void injectDir(NSString *dir) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *toInject = [NSMutableArray new];
    for (NSString *filename in [fm contentsOfDirectoryAtPath:dir error:nil]) {
        NSString *file = [dir stringByAppendingPathComponent:filename];
        if (cdhashFor(file) != nil) {
            [toInject addObject:file];
        }
    }
    LOG("Will inject %lu files for %@", (unsigned long)toInject.count, dir);
    if (toInject.count > 0) {
        if (injectedToTrustCache) {
            LOG("Warning: Trust cache already injected");
        }
        for (NSString *path in toInject) {
            if (![toInjectToTrustCache containsObject:path]) {
                [toInjectToTrustCache addObject:path];
            }
        }
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

bool runDpkg(NSArray <NSString*> *args, bool forceDeps, bool forceAll) {
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
    
    if (forceAll) {
        [command addObject:@"--force-all"];
    } else if (forceDeps) {
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

bool extractDeb(NSString *debPath, bool doInject) {
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
    if (doInject && result) {
        chdir("/");
        NSMutableArray *toInject = [NSMutableArray new];
        NSDictionary *files = tar.files;
        for (NSString *file in files.allKeys) {
            NSString *path = [@"/" stringByAppendingString:[file stringByStandardizingPath]];
            if (cdhashFor(path) != nil) {
                [toInject addObject:path];
            }
        }
        LOG("Will inject %lu files for %@", (unsigned long)toInject.count, debPath);
        if (toInject.count > 0) {
            if (injectedToTrustCache) {
                LOG("Warning: Trust cache already injected");
            }
            for (NSString *path in toInject) {
                if (![toInjectToTrustCache containsObject:path]) {
                    [toInjectToTrustCache addObject:path];
                }
            }
        }
    }
    return result;
}

bool extractDebs(NSArray <NSString *> *debPaths, bool doInject) {
    if ([debPaths count] < 1) {
        LOG("%s: Nothing to install", __FUNCTION__);
        return false;
    }
    for (NSString *debPath in debPaths) {
        if (!extractDeb(debPath, doInject))
            return NO;
    }
    return YES;
}

bool installDeb(const char *debName, bool forceDeps) {
    return runDpkg(@[@"-i", @(debName)], forceDeps, false);
}

bool installDebs(NSArray <NSString*> *debs, bool forceDeps, bool forceAll) {
    if ([debs count] < 1) {
        LOG("%s: Nothing to install", __FUNCTION__);
        return false;
    }
    return runDpkg([@[@"-i"] arrayByAddingObjectsFromArray:debs], forceDeps, forceAll);
}

bool removePkg(char *packageID, bool forceDeps) {
    return runDpkg(@[@"-r", @(packageID)], forceDeps, false);
}

bool removePkgs(NSArray <NSString*> *pkgs, bool forceDeps) {
    if ([pkgs count] < 1) {
        LOG("%s: Nothing to remove", __FUNCTION__);
        return false;
    }
    return runDpkg([@[@"-r"] arrayByAddingObjectsFromArray:pkgs], forceDeps, false);
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
    return WIFEXITED(rv) && !WEXITSTATUS(rv);
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

bool aptRepair() {
    return runApt(@[@"-o", @"Dir::Etc::preferences=undecimus/preferences", @"-o", @"Dir::Etc::preferencesparts=''", @"-y", @"--allow-unauthenticated", @"--allow-remove-essential", @"--allow-downgrades", @"-f", @"dist-upgrade"]);
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

bool removeURLFromSources(NSMutableString *sources, NSString *url)
{
    bool removed=false;
    NSString *pattern = [NSString stringWithFormat:@"[^\\n](?:(?!\\n\\n).)*%@(?:(?!\\n\\n).)*\\n\\n",
                         [url stringByReplacingOccurrencesOfString:@"." withString:@"\\."]
                         ];
    NSRegularExpression *sourceexp = [NSRegularExpression
                                      regularExpressionWithPattern:pattern
                                      options:NSRegularExpressionDotMatchesLineSeparators
                                      error:nil];
    
    for (NSTextCheckingResult *source in [sourceexp matchesInString:sources options:0 range:NSMakeRange(0, sources.length)])
    {
        removed = true;
        [sources deleteCharactersInRange:[source rangeAtIndex:0]];
    }
    return removed;
}

void deduplicateSillySources(void)
{
    NSString *cydia_list = [NSString stringWithContentsOfFile:@"/etc/apt/sources.list.d/cydia.list" encoding:NSUTF8StringEncoding error:nil];
    NSMutableString *sileo_sources = [NSMutableString stringWithContentsOfFile:@"/etc/apt/sources.list.d/sileo.sources" encoding:NSUTF8StringEncoding error:nil];
    if (cydia_list && sileo_sources) {
        NSFileManager *fm = [NSFileManager defaultManager];
        if (pkgIsInstalled("org.coolstar.sileo")) {
            NSString *orig_sileo_sources = [sileo_sources copy];
            NSRegularExpression *urlexp = [NSRegularExpression regularExpressionWithPattern:@"https?://(\\S+[^/\\s]|\\S+)/?\\s" options:0 error:nil];
            
            for (NSTextCheckingResult *match in [urlexp matchesInString:cydia_list options:0 range:NSMakeRange(0, cydia_list.length)])
            {
                NSString *url = [cydia_list substringWithRange:[match rangeAtIndex:1]];
                if ([url hasPrefix:@"apt.thebigboss.org"] && removeURLFromSources(sileo_sources, @"repounclutter.coolstar.org")) {
                    LOG("Removing duplicated source repounclutter from sileo.sources");
                }
                if (removeURLFromSources(sileo_sources, url)) {
                    LOG("Removing duplicated source %@ from sileo.sources", url);
                }
            }
            if (![sileo_sources isEqual:orig_sileo_sources]) {
                [fm createFileAtPath:@"/etc/apt/sources.list.d/sileo.sources"
                            contents:[sileo_sources dataUsingEncoding:NSUTF8StringEncoding]
                          attributes:@{ NSFileOwnerAccountID:@(0), NSFileGroupOwnerAccountID:@(0), NSFilePosixPermissions:@(0644) }
                 ];
            }
        } else {
            [fm removeItemAtPath:@"/etc/apt/sources.list.d/sileo.sources" error:nil];
        }
    }
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
        SafeFreeNULL(cwd);
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
    bool foundProcess = false;
    pid_t processPid = 0;
    for (int i = 0; i < numberOfProcesses && !foundProcess; ++i) {
        if (pids[i] == 0) {
            continue;
        }
        char *path = get_path_for_pid(pids[i]);
        if (path != NULL) {
            if (strlen(path) > 0 && strcmp(path, name) == 0) {
                processPid = pids[i];
                foundProcess = true;
            }
            SafeFreeNULL(path);
        }
    }
    return processPid;
}

char *getKernelVersion() {
    return sysctlWithName("kern.version");
}

char *getMachineName() {
    return sysctlWithName("hw.machine");
}
char *getModelName() {
    return sysctlWithName("hw.model");
}

bool kernelVersionContains(const char *string) {
    char *kernelVersion = getKernelVersion();
    if (kernelVersion == NULL) return false;
    bool ret = strstr(kernelVersion, string) != NULL;
    SafeFreeNULL(kernelVersion);
    return ret;
}

bool machineNameContains(const char *string) {
    char *machineName = getMachineName();
    if (machineName == NULL) return false;
    bool ret = strstr(machineName, string) != NULL;
    SafeFreeNULL(machineName);
    return ret;
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
        SafeFreeNULL(sockaddr_src);
        SafeFreeNULL(sockaddr_dst);
        close(sock);
    });
    return enabled;
}

bool jailbreakEnabled() {
    return kernelVersionContains(DEFAULT_VERSION_STRING) ||
    access(SLIDE_FILE, F_OK) == ERR_SUCCESS;
}

NSString *getKernelBuildVersion() {
    NSString *kernelBuild = nil;
    NSString *cleanString = nil;
    char *kernelVersion = NULL;
    kernelVersion = getKernelVersion();
    if (kernelVersion == NULL) return nil;
    cleanString = [NSString stringWithUTF8String:kernelVersion];
    SafeFreeNULL(kernelVersion);
    cleanString = [[cleanString componentsSeparatedByString:@"; "] objectAtIndex:1];
    cleanString = [[cleanString componentsSeparatedByString:@"-"] objectAtIndex:1];
    cleanString = [[cleanString componentsSeparatedByString:@"/"] objectAtIndex:0];
    kernelBuild = [cleanString copy];
    return kernelBuild;
}

bool checkDeviceSupport(device_support_info_t device_support) {
#ifdef CAN_HAS_UNSUPPORTED_DEVICE
    return true;
#else /* !CAN_HAS_UNSUPPORTED_DEVICE */
    if (device_support.min_kernel_version != NULL && device_support.max_kernel_version != NULL) {
        NSString *kernelBuildVersion = getKernelBuildVersion();
        if (kernelBuildVersion == nil) {
            return false;
        }
        if ([kernelBuildVersion compare:@(device_support.min_kernel_version) options:NSNumericSearch] == NSOrderedAscending || [kernelBuildVersion compare:@(device_support.max_kernel_version) options:NSNumericSearch] == NSOrderedDescending) {
            return false;
        }
    }
    if (device_support.handler != NULL) {
        if (!device_support.handler()) {
            return false;
        }
    }
    return true;
#endif /* !CAN_HAS_UNSUPPORTED_DEVICE */
}

bool jailbreakSupported() {
    for (size_t i = 0; exploit_infos[i]; i++) {
        if (exploit_infos[i]->exploit_capability != jailbreak_capability) {
            continue;
        }
        if (!checkDeviceSupport(exploit_infos[i]->device_support_info)) {
            continue;
        }
        return true;
    }
    return false;
}

bool substitutorSupported() {
    for (size_t i = 0; substitutor_infos[i]; i++) {
        if (!checkDeviceSupport(substitutor_infos[i]->device_support_info)) {
            continue;
        }
        return true;
    }
    return false;
}

bool respringSupported() {
    for (size_t i = 0; exploit_infos[i]; i++) {
        if (exploit_infos[i]->exploit_capability != respring_capability) {
            continue;
        }
        if (!checkDeviceSupport(exploit_infos[i]->device_support_info)) {
            continue;
        }
        return true;
    }
    return false;
}

bool restartSupported() {
    for (size_t i = 0; exploit_infos[i]; i++) {
        if (exploit_infos[i]->exploit_capability != reboot_capability) {
            continue;
        }
        if (!checkDeviceSupport(exploit_infos[i]->device_support_info)) {
            continue;
        }
        return true;
    }
    return false;
}

NSInteger recommendedJailbreakSupport() {
    NSInteger exploit = -1;
    exploit_info_t *exploit_info = NULL;
    for (size_t i = 0; exploit_infos[i]; i++) {
        if (exploit_infos[i]->exploit_capability != jailbreak_capability
            ) {
            continue;
        }
        if (!checkDeviceSupport(exploit_infos[i]->device_support_info)) {
            continue;
        }
        if (exploit_info == NULL) {
            exploit_info = exploit_infos[i];
            continue;
        }
        if (exploit_infos[i]->exploit_reliability > exploit_info->exploit_reliability) {
            exploit_info = exploit_infos[i];
        }
    }
    if (exploit_info != NULL) {
        exploit = (NSInteger)exploit_info->exploit;
    }
    return exploit;
}

NSInteger recommendedSubstitutorSupport() {
    NSInteger substitutor = -1;
    substitutor_info_t *substitutor_info = NULL;
    for (size_t i = 0; substitutor_infos[i]; i++) {
        if (!checkDeviceSupport(substitutor_infos[i]->device_support_info)) {
            continue;
        }
        if (substitutor_info == NULL) {
            substitutor_info = substitutor_infos[i];
            continue;
        }
        if (substitutor_infos[i]->substitutor_stability > substitutor_info->substitutor_stability) {
            substitutor_info = substitutor_infos[i];
        }
    }
    if (substitutor_info != NULL) {
        substitutor = (NSInteger)substitutor_info->substitutor;
    }
    return substitutor;
}

NSInteger recommendedRestartSupport() {
    NSInteger exploit = -1;
    exploit_info_t *exploit_info = NULL;
    for (size_t i = 0; exploit_infos[i]; i++) {
        if (exploit_infos[i]->exploit_capability != reboot_capability
            ) {
            continue;
        }
        if (!checkDeviceSupport(exploit_infos[i]->device_support_info)) {
            continue;
        }
        if (exploit_info == NULL) {
            exploit_info = exploit_infos[i];
            continue;
        }
        if (exploit_infos[i]->exploit_reliability > exploit_info->exploit_reliability) {
            exploit_info = exploit_infos[i];
        }
    }
    if (exploit_info != NULL) {
        exploit = (NSInteger)exploit_info->exploit;
    }
    return exploit;
}

NSInteger recommendedRespringSupport() {
    NSInteger exploit = -1;
    exploit_info_t *exploit_info = NULL;
    for (size_t i = 0; exploit_infos[i]; i++) {
        if (exploit_infos[i]->exploit_capability != respring_capability
            ) {
            continue;
        }
        if (!checkDeviceSupport(exploit_infos[i]->device_support_info)) {
            continue;
        }
        if (exploit_info == NULL) {
            exploit_info = exploit_infos[i];
            continue;
        }
        if (exploit_infos[i]->exploit_reliability > exploit_info->exploit_reliability) {
            exploit_info = exploit_infos[i];
        }
    }
    if (exploit_info != NULL) {
        exploit = (NSInteger)exploit_info->exploit;
    }
    return exploit;
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
    dispatch_block_t block = ^{
        if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@(URL)]]) {
            canOpenURL = true;
        }
        dispatch_semaphore_signal(semaphore);
    };
    if ([[NSThread currentThread] isMainThread]) {
        block();
    } else {
        dispatch_async(dispatch_get_main_queue(), block);
    }
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

bool installApp(const char *bundle) {
    NSString *bundle_path = @(bundle);
    NSURL *URL = [NSURL URLWithString:bundle_path];
    NSString *info_plist_path = [bundle_path stringByAppendingPathComponent:@"Info.plist"];
    NSMutableDictionary *info_plist = [NSMutableDictionary dictionaryWithContentsOfFile:info_plist_path];
    NSString *bundle_identifier = info_plist[@"CFBundleIdentifier"];
    NSMutableDictionary *options = [NSMutableDictionary new];
    options[@"CFBundleIdentifier"] = bundle_identifier;
    LSApplicationWorkspace *applicationWorkspace = [LSApplicationWorkspace defaultWorkspace];
    if ([applicationWorkspace installApplication:URL withOptions:options]) {
        return true;
    } else {
        LOG("Failed to install application");
        return false;
    }
}

bool rebuildApplicationDatabases() {
    LSApplicationWorkspace *applicationWorkspace = [LSApplicationWorkspace defaultWorkspace];
    if ([applicationWorkspace _LSPrivateRebuildApplicationDatabasesForSystemApps:YES internal:YES user:NO]) {
        return true;
    } else {
        LOG("Failed to rebuild application databases");
        return false;
    }
}

char *get_path_for_pid(pid_t pid) {
    char *ret = NULL;
    uint32_t path_size = PROC_PIDPATHINFO_MAXSIZE;
    char *path = malloc(path_size);
    if (path != NULL) {
        if (proc_pidpath(pid, path, path_size) >= 0) {
            ret = strdup(path);
        }
        SafeFreeNULL(path);
    }
    return ret;
}

NSString *getECID() {
    NSString *ECID = nil;
    CFStringRef value = MGCopyAnswer(kMGUniqueChipID);
    if (value != nil) {
        ECID = [NSString stringWithFormat:@"%@", value];
        CFRelease(value);
    }
    return ECID;
}

NSString *getUDID() {
    NSString *UDID = nil;
    CFStringRef value = MGCopyAnswer(kMGUniqueDeviceID);
    if (value != nil) {
        UDID = [NSString stringWithFormat:@"%@", value];
        CFRelease(value);
    }
    return UDID;
}

char *sysctlWithName(const char *name) {
    kern_return_t kr = KERN_FAILURE;
    char *ret = NULL;
    size_t *size = NULL;
    size = (size_t *)malloc(sizeof(size_t));
    if (size == NULL) goto out;
    bzero(size, sizeof(size_t));
    if (sysctlbyname(name, NULL, size, NULL, 0) != ERR_SUCCESS) goto out;
    ret = (char *)malloc(*size);
    if (ret == NULL) goto out;
    bzero(ret, *size);
    if (sysctlbyname(name, ret, size, NULL, 0) != ERR_SUCCESS) goto out;
    kr = KERN_SUCCESS;
out:
    if (kr == KERN_FAILURE) SafeFreeNULL(ret);
    SafeFreeNULL(size);
    return ret;
}

char *getOSVersion() {
    return sysctlWithName("kern.osversion");
}

char *getOSProductVersion() {
    return sysctlWithName("kern.osproductversion");
}

void printOSDetails() {
    char *machineName = NULL;
    char *modelName = NULL;
    char *kernelVersion = NULL;
    char *OSProductVersion = NULL;
    char *OSVersion = NULL;
    machineName = getMachineName();
    if (machineName == NULL) goto out;
    modelName = getModelName();
    if (modelName == NULL) goto out;
    kernelVersion = getKernelVersion();
    if (kernelVersion == NULL) goto out;
    OSProductVersion = getOSProductVersion();
    if (OSProductVersion == NULL) goto out;
    OSVersion = getOSVersion();
    if (OSVersion == NULL) goto out;
    LOG("Machine Name: %s", machineName);
    LOG("Model Name: %s", modelName);
    LOG("Kernel Version: %s", kernelVersion);
    LOG("Kernel Page Size: 0x%lx", get_kernel_page_size());
    LOG("System Version: iOS %s (%s) (Build: %s)", OSProductVersion, isBetaFirmware() ? "Beta" : "Stable", OSVersion);
out:
    SafeFreeNULL(machineName);
    SafeFreeNULL(modelName);
    SafeFreeNULL(kernelVersion);
    SafeFreeNULL(OSProductVersion);
    SafeFreeNULL(OSVersion);
}

bool isBetaFirmware() {
    bool ret = false;
    char *OSVersion = getOSVersion();
    if (OSVersion == NULL) return false;
    if (strlen(OSVersion) > 6) ret = true;
    SafeFreeNULL(OSVersion);
    return ret;
}

double getUptime() {
    double uptime = 0;
    size_t *size = NULL;
    struct timeval *boottime = NULL;
    size = (size_t *)malloc(sizeof(size_t));
    if (size == NULL) goto out;
    bzero(size, sizeof(size_t));
    *size = sizeof(struct timeval);
    boottime = (struct timeval *)malloc(*size);
    if (boottime == NULL) goto out;
    bzero(boottime, *size);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if (sysctl(mib, 2, boottime, size, NULL, 0) != ERR_SUCCESS) goto out;
    time_t bsec = boottime->tv_sec, csec = time(NULL);
    uptime = difftime(csec, bsec);
out:
    SafeFreeNULL(size);
    SafeFreeNULL(boottime);
    return uptime;
}

vm_size_t get_kernel_page_size() {
    vm_size_t kernel_page_size = 0;
    vm_size_t *out_page_size = NULL;
    host_t host = mach_host_self();
    if (!MACH_PORT_VALID(host)) goto out;
    out_page_size = (vm_size_t *)malloc(sizeof(vm_size_t));
    if (out_page_size == NULL) goto out;
    bzero(out_page_size, sizeof(vm_size_t));
    if (_host_page_size(host, out_page_size) != KERN_SUCCESS) goto out;
    kernel_page_size = *out_page_size;
out:
    if (MACH_PORT_VALID(host)) mach_port_deallocate(mach_task_self(), host); host = HOST_NULL;
    SafeFreeNULL(out_page_size);
    return kernel_page_size;
}

int waitForFile(const char *filename) {
    int rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == ERR_SUCCESS); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}

NSString *hexFromInt(NSInteger val) {
    return [NSString stringWithFormat:@"0x%lX", (long)val];
}

void waitFor(int seconds) {
    for (int i = 1; i <= seconds; i++) {
        LOG("Waiting (%d/%d)", i, seconds);
        sleep(1);
    }
}

bool blockDomainWithName(const char *name) {
    if (!unblockDomainWithName(name)) {
        LOG("%s: Unable to clean hosts file", __FUNCTION__);
        return false;
    }
    NSString *domain = @(name);
    NSString *hosts_file = @"/etc/hosts";
    NSString *hosts = [NSString stringWithContentsOfFile:hosts_file encoding:NSUTF8StringEncoding error:nil];
    if (hosts == nil) {
        LOG("%s: Unable to read hosts file", __FUNCTION__);
        return false;
    }
    NSArray *redirects = @[@"127.0.0.1", @"n::1"];
    for (NSString *redirect in redirects) {
        NSString *line = [NSString stringWithFormat:@"\n%@\t%@\n", redirect, domain];
        hosts = [hosts stringByAppendingString:line];
    }
    if (![hosts writeToFile:hosts_file atomically:YES encoding:NSUTF8StringEncoding error:nil]) {
        LOG("%s: Unable to update hosts file", __FUNCTION__);
        return false;
    }
    return true;
}

bool unblockDomainWithName(const char *name) {
    NSString *domain = @(name);
    NSString *hosts_file = @"/etc/hosts";
    NSString *hosts = [NSString stringWithContentsOfFile:hosts_file encoding:NSUTF8StringEncoding error:nil];
    if (hosts == nil) {
        LOG("%s: Unable to read hosts file", __FUNCTION__);
        return false;
    }
    for (NSString *line in [hosts componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        for (NSString *string in [line componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]) {
            if ([string isEqualToString:domain]) {
                hosts = [hosts stringByReplacingOccurrencesOfString:line withString:@""];
            }
        }
    }
    if (![hosts writeToFile:hosts_file atomically:YES encoding:NSUTF8StringEncoding error:nil]) {
        LOG("%s: Unable to update hosts file", __FUNCTION__);
        return false;
    }
    return true;
}

bool cydiaIsInstalled() {
    if (access("/Applications/Cydia.app", F_OK) != ERR_SUCCESS) {
        return false;
    }
    if (!canOpen("cydia://")) {
        return false;
    }
    return true;
}

NSString *localize(NSString *str, ...) {
    va_list ap;
    va_start(ap, str);
    NSString *str_to_localize = [[NSString alloc] initWithFormat:str arguments:ap];
    va_end(ap);
    return NSLocalizedString(str_to_localize, @"");
}

exploit_info_t *get_exploit_info(exploit_t exploit) {
    for (size_t i = 0; exploit_infos[i]; ++i) {
        if (exploit_infos[i]->exploit == exploit) {
            return exploit_infos[i];
        }
    }
    return NULL;
}

substitutor_info_t *get_substitutor_info(substitutor_t substitutor) {
    for (size_t i = 0; substitutor_infos[i]; ++i) {
        if (substitutor_infos[i]->substitutor == substitutor) {
            return substitutor_infos[i];
        }
    }
    return NULL;
}

__attribute__((constructor))
static void ctor() {
    toInjectToTrustCache = [NSMutableArray new];
}
