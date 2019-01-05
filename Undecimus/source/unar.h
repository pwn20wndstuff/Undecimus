//
//  unar.h
//  Undecimus
//
//  Created by Sam Bingner on 1/4/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#ifndef unar_h
#define unar_h
#import <Foundation/Foundation.h>

@interface ARFile : NSObject
@property (strong,readonly) NSArray <NSString*> *files;
+(ARFile*)arFileWithFile:(NSString*)filename;
-(ARFile*)initWithFile:(NSString*)filename;
-(BOOL)contains:(NSString*)file;
-(NSArray <NSString*> *)files;
-(BOOL)extract:(NSString*)file toPath:(NSString*)path;
@end

#endif /* unar_h */
