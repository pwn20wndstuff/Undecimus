//
//  Archive.h
//
//  Created by Sam Bingner on 1/4/19.
//  Copyright © 2019 Sam Bingner. All rights reserved.
//

#ifndef _ARCHIVE_FILE_H
#define _ARCHIVE_FILE_H
#import <Foundation/Foundation.h>
#import <archive.h>

@interface ArchiveFile : NSObject
@property (strong,readonly) NSDictionary *files;

+(ArchiveFile*)archiveWithFile:(NSString*)filename;
+(ArchiveFile*)archiveWithFd:(int)fd;
-(ArchiveFile*)initWithFile:(NSString*)filename;
-(ArchiveFile*)initWithFd:(int)fd;
-(BOOL)contains:(NSString*)file;
-(NSDictionary *)files;
-(BOOL)extract;
-(BOOL)extractFileNum:(int)fileNum toFd:(int)fd;
-(BOOL)extract:(NSString*)file toPath:(NSString*)path;
-(BOOL)extractWithFlags:(int)flags;
-(BOOL)extractToPath:(NSString*)path;
-(BOOL)extractToPath:(NSString*)path withOwner:(id_t)owner andGroup:(id_t)group;
-(BOOL)extractToPath:(NSString*)path overWriteDirectories:(BOOL)overwrite_dirs;
-(BOOL)extractToPath:(NSString*)path withFlags:(int)flags;
-(BOOL)extractToPath:(NSString*)path withFlags:(int)flags overWriteDirectories:(BOOL)overwrite_dirs;
-(BOOL)extractToPath:(NSString*)path withFlags:(int)flags overWriteDirectories:(BOOL)overwrite_dirs owner:(id_t)owner andGroup:(id_t)group;
@end

#endif /* _ARCHIVE_FILE_H */
