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
@property (strong,readonly) NSArray <NSString*> *files;

+(ArchiveFile*)archiveWithFile:(NSString*)filename;
-(ArchiveFile*)initWithFile:(NSString*)filename;
-(BOOL)contains:(NSString*)file;
-(NSArray <NSString*> *)files;
-(BOOL)extract:(NSString*)file toPath:(NSString*)path;
-(BOOL)extractToPath:(NSString*)path;
-(BOOL)extractToPath:(NSString*)path withFlags:(int)flags;
@end

#endif /* _ARCHIVE_FILE_H */
