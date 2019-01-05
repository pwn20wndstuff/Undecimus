//
//  unar.m
//  Undecimus
//
//  Created by Sam Bingner on 1/4/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#import "unar.h"

struct arHeader {
    char name[16];
    char modification[12];
    char uid[6];
    char gid[6];
    char mode[8];
    char size[10];
    char footer[2];
};

static const char arSignature[] = {0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e, 0x0a};

NSString *copyString(char *string, int len)
{
    return [[NSString alloc] initWithBytes:string length:len encoding:NSUTF8StringEncoding];
}

NSString *copyNormalizedName(NSString *name)
{
    NSUInteger len = [name lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    char buf[len+1];
    if (![name getCString:buf maxLength:len+1 encoding:NSUTF8StringEncoding]) {
        NSLog(@"couldn't get buf");
        return nil;
    }
    NSUInteger i;
    for (i=len-1; i>=0 && (buf[i] == ' ' || buf[i] == '\n'); i--) {
        buf[i] = '\0';
    }
    if (i>0 && buf[i] == '/')
        buf[i] = '\0';
    
    return @(buf);
}

@implementation ARFile
int fd;
NSMutableDictionary *files;
NSDictionary *lfnFile;

+(ARFile*)arFileWithFile:(NSString *)filename
{
#if __has_feature(objc_arc)
    return [[ARFile alloc] initWithFile:filename];
#else
    return [[[ARFile alloc] initWithFile:filename] autorelease];
#endif
}

-(ARFile*)initWithFile:(NSString*)filename
{
    self = [self init];
    struct arHeader fileHdr;

    fd = open(filename.UTF8String, O_RDONLY);
    if (fd < 0) {
        perror("Open file");
        return nil;
    }
    char signature[8];
    if (read(fd, signature, 8) != 8 ||
        memcmp(signature, arSignature, 8) != 0
        ) {
        close(fd);
        return nil;
    }
    files = [NSMutableDictionary new];
    NSNumberFormatter *number = [NSNumberFormatter new];
    number.numberStyle = NSNumberFormatterDecimalStyle;

    while (read(fd, &fileHdr, sizeof(fileHdr)) == sizeof(fileHdr)) {
        int longFileNameLen=0;
        NSString *name = copyString(fileHdr.name, 16);
        if ([name hasPrefix:@"#1/"]) {
            longFileNameLen = [[name substringFromIndex:3] intValue];
            char newName[longFileNameLen];
            if (read(fd, newName, longFileNameLen) != longFileNameLen) {
                NSLog(@"Unable to read long filename");
                return nil;
            }
            name = copyString(newName, longFileNameLen);
        } else if ([name hasPrefix:@"/"] && ![name hasPrefix:@"//"]) {
            // GNU Long Filename
            int lfnOff = [[name substringFromIndex:1] intValue];
            off_t here = lseek(fd, 0, SEEK_CUR);
            if (lfnFile == nil) {
                NSLog(@"Unable to read long filename: no lfnFile");
                return nil;
            }
            off_t lfnBase = [lfnFile[@"offset"] longLongValue];
            int lfnSize = [lfnFile[@"size"] intValue];
            char newName[lfnSize];
            if (lseek(fd, lfnBase + lfnOff, SEEK_SET) != lfnBase + lfnOff) {
                NSLog(@"Unable to seek to lfn");
                return nil;
            }
            if (read(fd, newName, lfnSize) != lfnSize) {
                NSLog(@"Unable to read long filename: short read");
                return nil;
            }
            name = copyString(newName, lfnSize);
            if (lseek(fd, here, SEEK_SET) != here) {
                NSLog(@"Unable to seek back!!?!");
                return nil;
            }
        }
        name = copyNormalizedName(name);
        files[name] = [NSMutableDictionary new];
        files[name][@"offset"] = @(lseek(fd, 0, SEEK_CUR));

        unsigned long long ts = [copyString(fileHdr.modification, 12) longLongValue];
        files[name][@"modification"] = ts?[NSDate dateWithTimeIntervalSince1970:ts]:[NSDate date];

        NSInteger uid = [copyString(fileHdr.uid, 6) integerValue];
        files[name][@"uid"] = @(uid);

        NSInteger gid = [copyString(fileHdr.gid, 6) integerValue];
        files[name][@"gid"] = @(gid);

        mode_t mode = 0;
        for (int i=0; i<6 && fileHdr.mode[i] != ' '; i++) {
            mode = (mode << 3) + (fileHdr.mode[i] - '0');
        }
        files[name][@"mode"] = @(mode);

        NSInteger size = [copyString(fileHdr.size, 10) integerValue];
        size -= longFileNameLen;
        files[name][@"size"] = @(size);

        NSInteger skip = size;
        // Always an even number of bytes for member
        if (skip % 2)
            skip++;
        lseek(fd, skip, SEEK_CUR);
        if ([name isEqualToString:@"/"]) {
            lfnFile = [files[name] copy];
            [files removeObjectForKey:@"/"];
        }
    }
    return self;
}

-(NSArray <NSString*>*)files
{
    return [files allKeys];
}

-(BOOL)extract:(NSString*)file toPath:(NSString*)path
{
    NSFileManager *fm = [NSFileManager defaultManager];
    if (files[file] == nil) {
        NSLog(@"ARFile: no such file \"%@\"", file);
        return NO;
    }
    BOOL isDirectory;
    NSString *target=nil;
    if ([fm fileExistsAtPath:path isDirectory:&isDirectory]) {
        target = path;
        if (!isDirectory) {
            [fm removeItemAtPath:path error:nil];
        } else {
            target = [target stringByAppendingPathComponent:file];
            if ([fm fileExistsAtPath:target isDirectory:&isDirectory]) {
                if (isDirectory) {
                    NSLog(@"error: target \"%@\" is a Directory containing a directory by that name", path);
                    return NO;
                } else {
                    [fm removeItemAtPath:target error:nil];
                }
            }
        }
    } else if ([[NSFileManager defaultManager] fileExistsAtPath:[path stringByDeletingLastPathComponent] isDirectory:&isDirectory]) {
        if (!isDirectory) {
            NSLog(@"ARFile: Path component is not a directory");
            return NO;
        }
        target = path;
    }
    int output = open([target UTF8String], O_WRONLY | O_CREAT | O_TRUNC);
    lseek(fd, [files[file][@"offset"] integerValue], SEEK_SET);
    NSInteger size = [files[file][@"size"] integerValue];
    char buf[2048];
    while (size > 0) {
        ssize_t wantlen = size<2048?size:2048;
        ssize_t rlen = read(fd, buf, wantlen);

        if (rlen < 1 || write(output, buf, rlen) != rlen) {
            close(output);
            NSLog(@"%@ short read; output fail", file);
            return NO;  
        }
        size -= rlen;
    }
    close(output);
    [fm setAttributes:@{
                        NSFileOwnerAccountID: files[file][@"uid"],
                        NSFileGroupOwnerAccountID: files[file][@"gid"],
                        NSFilePosixPermissions: files[file][@"mode"],
                        NSFileModificationDate: files[file][@"modification"]
                        } ofItemAtPath:target error:nil];
    return YES;
}
-(BOOL)contains:(NSString*)file {
    return (files[file] != nil);
}

-(void)dealloc {
    close(fd);
}
@end
