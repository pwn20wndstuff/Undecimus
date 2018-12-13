//
//  utils.h
//  Undecimus
//
//  Created by Sam Bingner on 11/23/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#ifndef utils_h
#define utils_h
#import <sys/types.h>
#import <sys/stat.h>

int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

static inline bool clean_file(const char *file) {
    return (access(file, F_OK) != ERR_SUCCESS ||
            unlink(file) == ERR_SUCCESS);
}

static inline bool init_file(const char *file, int owner, mode_t mode) {
    return (access(file, F_OK) == ERR_SUCCESS &&
            chmod(file, mode) == ERR_SUCCESS &&
            chown(file, owner, owner) == ERR_SUCCESS);
}

int sha1_to_str(const unsigned char *hash, int hashlen, char *buf, size_t buflen);
NSString *sha1sum(NSString *file);
bool verifySha1Sums(NSString *sumFile);
int _system(const char *cmd);
int _systemf(const char *cmd, ...);
bool debIsInstalled(char *packageID);
bool debIsConfigured(char *packageID);
bool installDeb(char *debName);
bool pidFileIsValid(NSString *pidfile);
bool pspawnHookLoaded(void);
bool is_symlink(const char *filename);
bool is_directory(const char *filename);
int runCommand(const char *cmd, ...);

extern NSData *lastSystemOutput;

#endif /* utils_h */
