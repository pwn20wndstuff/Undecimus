//
//  Archive.m
//
//  Created by Sam Bingner on 1/4/19.
//  Copyright © 2019 Sam Bingner. All rights reserved.
//

#import "ArchiveFile.h"
#import <archive.h>
#import <archive_entry.h>

static int
copy_data(struct archive *ar, struct archive *aw)
{
    int r;
    const void *buff;
    size_t size;
    off_t offset;
    
    for (;;) {
        r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF)
            return (ARCHIVE_OK);
        if (r < ARCHIVE_OK)
            return (r);
        if (archive_write_data_block(aw, buff, size, offset) < ARCHIVE_OK) {
            NSLog(@"Archive: %s", archive_error_string(aw));
            return (r);
        }
    }
}

@implementation ArchiveFile {
    NSMutableDictionary *_files;
    int _fd;
}

+(ArchiveFile*)archiveWithFile:(NSString *)filename
{
#if __has_feature(objc_arc)
    return [[ArchiveFile alloc] initWithFile:filename];
#else
    return [[[ArchiveFile alloc] initWithFile:filename] autorelease];
#endif
}

-(ArchiveFile*)initWithFile:(NSString*)filename
{
    self = [self init];

    _fd = open(filename.UTF8String, O_RDONLY);
    if (_fd < 0) {
        perror("Open file");
        return nil;
    }
    
    struct archive *a = archive_read_new();
    archive_read_support_compression_all(a);
    archive_read_support_format_all(a);
    if (archive_read_open_fd(a, _fd, 16384) != ARCHIVE_OK)
        return nil;

    struct archive_entry *entry;
    _files = [NSMutableDictionary new];
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        NSString *path = @(archive_entry_pathname(entry));
        _files[path] = [NSMutableDictionary new];
        _files[path][@"mode"] = @(archive_entry_mode(entry));
        _files[path][@"uid"] = @(archive_entry_uid(entry));
        _files[path][@"gid"] = @(archive_entry_gid(entry));
        time_t mtime = archive_entry_mtime(entry);
        if (mtime) {
            _files[path][@"mtime"] = [NSDate dateWithTimeIntervalSince1970:mtime];
        }
    }
    archive_read_close(a);
    lseek(_fd, 0, SEEK_SET);
    return self;
}

-(NSArray*)files {
    return [_files.allKeys copy];
}

-(BOOL)extract:(NSString*)file toPath:(NSString*)path
{
    BOOL result = NO;
    /* Select which attributes we want to restore. */
    int flags = ARCHIVE_EXTRACT_TIME;
    flags |= ARCHIVE_EXTRACT_PERM;
    flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;
    flags |= ARCHIVE_EXTRACT_OWNER;
    
    if (_files[file] == nil) {
        NSLog(@"Archive: no such file \"%@\"", file);
        return NO;
    }

    int fd = dup(_fd);
    if (fd == -1) {
        NSLog(@"Archive: unable to dupe fd");
        return NO;
    }

    struct archive *a = archive_read_new();
    archive_read_support_compression_all(a);
    archive_read_support_format_all(a);
    
    if (archive_read_open_fd(a, _fd, 16384) != ARCHIVE_OK) {
        NSLog(@"Archive: unable to archive_read_open_fd: %s", archive_error_string(a));
        close(fd);
        return result;
    }

    struct archive *ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    
    // Seek to entry
    struct archive_entry *entry = NULL;
    int rv;
    while ((rv = archive_read_next_header(a, &entry)) == ARCHIVE_OK &&
           strcmp(archive_entry_pathname(entry), file.UTF8String) != 0
           );

    if (rv < ARCHIVE_OK) {
        NSLog(@"Archive: %s", archive_error_string(a));
        if (rv < ARCHIVE_WARN)
            goto out;
    }
    
    if (entry && (strcmp(archive_entry_pathname(entry), file.UTF8String) != 0) ) {
        NSLog(@"Archive: Unable to find entry for %@", file);
        goto out;
    }
    
    archive_entry_set_pathname(entry, path.UTF8String);
    rv = archive_write_header(ext, entry);
    if (rv < ARCHIVE_OK) {
        NSLog(@"Archive: Unable to write header for %@: %s", path, archive_error_string(ext));
        if (rv < ARCHIVE_WARN)
            goto out;
    }
    if (archive_entry_size(entry) > 0)
        copy_data(a, ext);
    rv = archive_write_finish_entry(ext);
    if (rv < ARCHIVE_OK) {
        NSLog(@"Archive: %s", archive_error_string(ext));
        if (rv < ARCHIVE_WARN)
            goto out;
    }
    result = YES;
out:
    archive_write_close(ext);
    archive_read_close(a);
    close(fd);
    return result;
}

-(BOOL)extractToPath:(NSString*)path
{
    /* Select which attributes we want to restore. */
    int flags = ARCHIVE_EXTRACT_TIME;
    flags |= ARCHIVE_EXTRACT_PERM;
    flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;
    flags |= ARCHIVE_EXTRACT_OWNER;
    flags |= ARCHIVE_EXTRACT_UNLINK;
    
    return [self extractToPath:path withFlags:flags];
}

-(BOOL)extractToPath:(NSString*)path withFlags:(int)flags
{
    BOOL result = NO;

    int fd = dup(_fd);
    if (fd == -1) {
        NSLog(@"Archive: unable to dupe fd");
        return NO;
    }
    
    struct archive *a = archive_read_new();
    archive_read_support_compression_all(a);
    archive_read_support_format_all(a);
    
    if (archive_read_open_fd(a, _fd, 16384) != ARCHIVE_OK) {
        NSLog(@"Archive: unable to archive_read_open_fd: %s", archive_error_string(a));
        close(fd);
        return result;
    }
    
    struct archive *ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    
    // Seek to entry
    struct archive_entry *entry = NULL;
    int rv;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *cwd = [fm currentDirectoryPath];
    if (![fm changeCurrentDirectoryPath:path]) {
        NSLog(@"Archive: unable to change cwd to %@", path);
        goto out;
    }
    while ((rv = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        if (rv < ARCHIVE_OK) {
            NSLog(@"Archive \"%s\": %s", archive_entry_pathname(entry), archive_error_string(ext));
            if (rv < ARCHIVE_WARN)
                goto out;
        }
        
        rv = archive_write_header(ext, entry);
        if (rv < ARCHIVE_OK) {
            NSLog(@"Archive \"%s\": %s", archive_entry_pathname(entry), archive_error_string(ext));
            if (rv < ARCHIVE_WARN) {
                // Make already exists not a fatal error
                if (strcmp(archive_error_string(ext), "Already exists")==0)
                    continue;
                goto out;
            }
        }
        if (archive_entry_size(entry) > 0)
            copy_data(a, ext);
        rv = archive_write_finish_entry(ext);
        if (rv < ARCHIVE_OK) {
            NSLog(@"Archive \"%s\": %s", archive_entry_pathname(entry), archive_error_string(ext));
            if (rv < ARCHIVE_WARN)
                goto out;
        }
        NSLog(@"%s: OK", archive_entry_pathname(entry));
    }
    result = YES;
    out:
    [fm changeCurrentDirectoryPath:cwd];
    archive_write_close(ext);
    archive_read_close(a);
    close(fd);
    return result;
}

-(BOOL)contains:(NSString*)file {
    return (_files[file] != nil);
}

-(void)dealloc {
    close(_fd);
}

@end
