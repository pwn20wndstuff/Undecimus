//
//  utils.m
//  Undecimus
//
//  Created by Sam Bingner on 11/23/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#import <mach/error.h>
#import <sys/sysctl.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <spawn.h>
#import <QiLin.h>
#include <copyfile.h>
#include <common.h>
#include <libproc.h>
#import "utils.h"

extern char **environ;

NSData *lastSystemOutput=nil;

int sha1_to_str(const unsigned char *hash, int hashlen, char *buf, size_t buflen)
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

bool verifySha1Sums(NSString *sumFile) {
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
        NSString *fileSum = sha1sum(suminfo[1]);
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
    posix_spawn_file_actions_t *actions = NULL;
    posix_spawn_file_actions_t actionsStruct;
    pid_t Pid = 0;
    int Status = 0;
    int out_pipe[2];
    bool valid_pipe = false;
    char *myenviron[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11:/usr/games",
        "PS1=\\h:\\w \\u\\$ ",
        NULL
    };
    char *argv[] = {"sh", "-c", (char *)cmd, NULL};
    valid_pipe = pipe(out_pipe) == ERR_SUCCESS;
    if (valid_pipe && posix_spawn_file_actions_init(&actionsStruct) == ERR_SUCCESS) {
        actions = &actionsStruct;
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 2);
        posix_spawn_file_actions_addclose(actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(actions, out_pipe[1]);
    }
    Status = posix_spawn(&Pid, "/bin/sh", actions, NULL, argv, myenviron);
    if (valid_pipe) {
        close(out_pipe[1]);
    }
    if (Status == ERR_SUCCESS) {
        waitpid(Pid, &Status, 0);
        if (valid_pipe) {
            NSData *outData = [[[NSFileHandle alloc] initWithFileDescriptor:out_pipe[0]] availableData];
            LOG("system(\"%s\") [%d]: %s", cmd, WEXITSTATUS(Status), [outData bytes]);
            lastSystemOutput = outData;
        }
    }
    if (valid_pipe) {
        close(out_pipe[0]);
    }
    return Status;
}

int systemf(const char *cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    NSString *cmdstr = [[NSString alloc] initWithFormat:@(cmd) arguments:ap];
    va_end(ap);
    return system([cmdstr UTF8String]);
}

bool debIsInstalled(char *packageID) {
    int rv = systemf("/usr/bin/dpkg -s \"%s\" | grep Status: | grep -q \"install ok\"", packageID);
    bool isInstalled = !WEXITSTATUS(rv);
    LOG("Deb: \"%s\" is%s installed", packageID, isInstalled?"":" not");
    return isInstalled;
}

bool debIsConfigured(char *packageID) {
    int rv = systemf("/usr/bin/dpkg -s \"%s\" | grep Status: | grep -q \"install ok installed\"", packageID);
    bool isConfigured = !WEXITSTATUS(rv);
    LOG("Deb: \"%s\" is%s installed", packageID, isConfigured?"":" not");
    return isConfigured;
}

bool compareInstalledVersion(const char *packageID, const char *op, const char *version) {
    int rv = systemf("dpkg --compare-versions $(dpkg-query --showformat='${Version}' --show \"%s\") \"%s\" \"%s\"",
                      packageID, op, version);
    rv = !WEXITSTATUS(rv);
    LOG("Deb %s is%s %s %s", packageID, rv?"":" not", op, version);
    return rv;
}

bool installDeb(char *debName, bool forceDeps) {
    NSString *destPathStr = [NSString stringWithFormat:@"/jb/%s", debName];
    const char *destPath = [destPathStr UTF8String];
    if (!clean_file(destPath)) {
        return false;
    }
    if (!copyResourceFromBundle(@(debName), @(destPath))) {
        return false;
    }
    int rv = systemf("/usr/bin/dpkg %s --force-bad-path --force-configure-any -i \"%s\"", (forceDeps?"--force-depends":""), destPath);
    clean_file(destPath);
    return !WEXITSTATUS(rv);
}

bool pidFileIsValid(NSString *pidfile) {
    NSString *jbdpid = [NSString stringWithContentsOfFile:pidfile encoding:NSUTF8StringEncoding error:NULL];
    if (jbdpid != nil && pidOfProcess("/usr/libexec/jailbreakd") == jbdpid.integerValue) {
        return true;
    }
    return false;
}

bool pspawnHookLoaded() {
    static int request[2] = { CTL_KERN, KERN_BOOTTIME };
    struct timeval result;
    size_t result_len = sizeof result;

    if (access("/var/run/pspawn_hook.ts", F_OK) == ERR_SUCCESS) {
        NSString *stamp = [NSString stringWithContentsOfFile:@"/var/run/pspawn_hook.ts" encoding:NSUTF8StringEncoding error:NULL];
        if (stamp != nil && sysctl(request, 2, &result, &result_len, NULL, 0) >= 0) {
            if ([stamp integerValue] > result.tv_sec) {
                return true;
            }
        }
    }
    return false;
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

bool mode_is(const char *filename, mode_t mode) {
    struct stat buf;
    if (lstat(filename, &buf) != ERR_SUCCESS) {
        return false;
    }
    return buf.st_mode == mode;
}

int runCommand(const char *cmd, ...) {
    posix_spawn_file_actions_t *actions = NULL;
    posix_spawn_file_actions_t actionsStruct;
    va_list ap, ap2;
    pid_t pid;
    int argc = 1;
    int out_pipe[2];
    bool valid_pipe = false;

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
    
    valid_pipe = pipe(out_pipe) == ERR_SUCCESS;
    if (valid_pipe && posix_spawn_file_actions_init(&actionsStruct) == ERR_SUCCESS) {
        actions = &actionsStruct;
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 2);
        posix_spawn_file_actions_addclose(actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(actions, out_pipe[1]);
    }

    int rv = posix_spawn(&pid, cmd, actions, NULL, (char *const *)argv, environ);

    if (valid_pipe) {
        close(out_pipe[1]);
    }

    if (rv == ERR_SUCCESS) {
        if (waitpid(pid, &rv, 0) == -1) {
            LOG("ERROR: Waitpid failed");
        } else {
            rv = WEXITSTATUS(rv);
            if (valid_pipe) {
                NSData *outData = [[[NSFileHandle alloc] initWithFileDescriptor:out_pipe[0]] availableData];
                LOG("runCommand(\"%s\") [%d]: %s", cmd, rv, [outData bytes]);
                lastSystemOutput = outData;
            }
        }
    } else {
        LOG("ERROR: posix_spawn failed (%d): %s", rv, strerror(rv));
    }
    if (valid_pipe) {
        close(out_pipe[0]);
    }

    return rv;
}

bool copyResourceFromBundle(NSString *resource, NSString *to) {
    NSBundle *bundle = [NSBundle mainBundle];
    NSString *bundlePath = [bundle bundlePath];
    NSString *pathForResource = [bundlePath stringByAppendingPathComponent:resource];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:pathForResource]) {
        LOG(@"Unable to find \"%@\" in bundle at path \"%@\"", resource, pathForResource);
        return false;
    }
    if (![fileManager copyItemAtPath:pathForResource toPath:to error:nil]) {
        LOG(@"Unable to copy \"%@\" in bundle at path \"%@\" to \"%@\"", resource, pathForResource, to);
        return false;
    }
    return true;
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
        if (strlen(pathBuffer) > 0 && strcmp(pathBuffer, name) == ERR_SUCCESS) {
            return pids[i];
        }
    }
    return 0;
}
