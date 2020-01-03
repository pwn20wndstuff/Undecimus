//
//  FakeApt.m
//  This is far from a complete implementation.
//
//  Created by Sam Bingner on 1/24/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "utils.h"
#import "common.h"
#import "FakeApt.h"

static int valueForNonDigit(char nd) {
    if (nd == '~')
        return 0;
    else if (nd == '\0')
        return 1;
    else if (nd >= 'A' && nd <= 'Z')
        return 2 + nd - 'A';
    else if (nd >= 'a' && nd <= 'z')
        return 2 + ('Z' - 'A') + nd - 'a';
    else
        return 2 + ('Z' - 'A') * 2 + nd;
}

int versioncomp(NSString *v1, NSString *v2) {
    NSRegularExpression *nonDigitsR = [NSRegularExpression regularExpressionWithPattern:@"^([^\\d]+)" options:0 error:nil];
    NSRegularExpression *digitsR = [NSRegularExpression regularExpressionWithPattern:@"^([\\d]+)" options:0 error:nil];
    int result = 0;
    do {
        NSTextCheckingResult *nonDigits1 = [nonDigitsR firstMatchInString:v1 options:0 range:NSMakeRange(0, v1.length)];
        NSTextCheckingResult *nonDigits2 = [nonDigitsR firstMatchInString:v2 options:0 range:NSMakeRange(0, v2.length)];
        const char *nd1="", *nd2="";
        if (nonDigits1) {
            nd1 = [v1 substringWithRange:nonDigits1.range].UTF8String;
            v1 = [v1 substringFromIndex:nonDigits1.range.length];
        }
        if (nonDigits2) {
            nd2 = [v2 substringWithRange:nonDigits1.range].UTF8String;
            v2 = [v2 substringFromIndex:nonDigits1.range.length];
        }
        size_t maxLen = MIN(nonDigits1.range.length, nonDigits2.range.length) + 1; // Also compare NULL
        int compared;
        for (compared=0; compared < maxLen && *nd1 == *nd2; compared++, nd1++, nd2++);
        if (compared < maxLen) {
            int cv1 = valueForNonDigit(*nd1);
            int cv2 = valueForNonDigit(*nd2);
            result = cv1 - cv2;
        }
        
        if (result == 0) {
            // Compare digits
            NSTextCheckingResult *digits1 = [digitsR firstMatchInString:v1 options:0 range:NSMakeRange(0, v1.length)];
            NSTextCheckingResult *digits2 = [digitsR firstMatchInString:v2 options:0 range:NSMakeRange(0, v2.length)];
            
            int dv1=0, dv2=0;
            if (digits1) {
                dv1 = [[v1 substringWithRange:digits1.range] intValue];
                v1 = [v1 substringFromIndex:digits1.range.length];
            }
            if (digits2) {
                dv2 = [[v2 substringWithRange:digits2.range] intValue];
                v2 = [v2 substringFromIndex:digits2.range.length];
            }
            result = dv1 - dv2;
        }
    } while (result == 0 && (v1.length > 0 || v2.length > 0));
    return result;
}

NSDictionary *parseDependsOrProvides(NSString *string) {
    NSRegularExpression *version = [NSRegularExpression regularExpressionWithPattern:@"^\\s*(\\S+)\\s+\\((<<|<=|=|>=|>>)\\s*((?:\\d:|)[A-Za-z0-9\\.\\+\\-\\~]+)\\)" options:0 error:nil];
    
    NSTextCheckingResult *verMatch = [version firstMatchInString:string options:0 range:NSMakeRange(0, string.length)];
    if (verMatch) {
        return @{
                 @"name": [string substringWithRange:[verMatch rangeAtIndex:1]],
                 @"op": [string substringWithRange:[verMatch rangeAtIndex:2]],
                 @"ver": [string substringWithRange:[verMatch rangeAtIndex:3]]
                 };
    }
    return @{@"name": string};
}

enum dpkgComparisonResult {
    resError = -1,
    resNotSatisfied = 0,
    resSatisfied = 1,
    resPending = 2
};

static enum dpkgComparisonResult testComp(int compRes, NSString *op, bool last) {
    static NSDictionary *compDict;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        compDict = @{
                     @"<<" : @-2,
                     @"<=" : @-1,
                     @"="  : @0,
                     @">=" : @1,
                     @">>" : @2
                     };
    });
    NSNumber *compOp = compDict[op];
    if (!compOp)
        return resError;
    
    switch (compOp.intValue) {
        case -2:
            if (compRes < 0)
                return resSatisfied;
            return last?resNotSatisfied:resPending;
            break;
        case -1:
            if (compRes < 0)
                return resSatisfied;
        case 0:
            if (compRes == 0)
                return last?resSatisfied:resPending;
            return resNotSatisfied;
            break;
        case 1:
            if (compRes == 0)
                return last?resSatisfied:resPending;
        case 2:
            if (compRes > 0)
                return resSatisfied;
            return last?resNotSatisfied:resPending;
            break;
        default:
            return resError;
    }
}

BOOL compareDpkgVersion(NSString *version1, NSString *op, NSString *version2, BOOL *result) {
    if (version1 == nil || op == nil || version2 == nil || result == NULL)
        return NO;
    
    NSRegularExpression *mainVersionPartsRegex = [NSRegularExpression regularExpressionWithPattern:
                                                  @"^(?:(\\d):|)(?:([A-Za-z0-9\\.\\+\\-~]+)-([A-Za-z0-9\\.\\+~]+)|([A-Za-z0-9\\.\\+~]+))$"
                                                                                           options:0 error:nil];
    NSRegularExpression *opRegex = [NSRegularExpression regularExpressionWithPattern:@"^<<|<=|=|>=|>>$" options:0 error:nil];
    
    if ([opRegex numberOfMatchesInString:op options:0 range:NSMakeRange(0, op.length)] != 1) {
        LOG("couldn't parse op");
        return NO;
    }
    
    NSTextCheckingResult *mainVersion1Parts = [mainVersionPartsRegex firstMatchInString:version1 options:0 range:NSMakeRange(0, version1.length)];
    NSTextCheckingResult *mainVersion2Parts = [mainVersionPartsRegex firstMatchInString:version2 options:0 range:NSMakeRange(0, version2.length)];
    
    if (!mainVersion1Parts || !mainVersion2Parts) {
        LOG("couldn't parse version %@ or %@", version1, version2);
        return NO;
    }
    
    NSString *epoch1;
    if (NSEqualRanges([mainVersion1Parts rangeAtIndex:1], NSMakeRange(NSNotFound, 0))) {
        epoch1 = @"0";
    } else {
        epoch1 = [version1 substringWithRange:[mainVersion1Parts rangeAtIndex:1]];
    }
    NSString *epoch2;
    if (NSEqualRanges([mainVersion2Parts rangeAtIndex:1], NSMakeRange(NSNotFound, 0))) {
        epoch2 = @"0";
    } else {
        epoch2 = [version2 substringWithRange:[mainVersion2Parts rangeAtIndex:1]];
    }
    
    NSString *upstream1;
    if (NSEqualRanges([mainVersion1Parts rangeAtIndex:2], NSMakeRange(NSNotFound, 0))) {
        if (NSEqualRanges([mainVersion1Parts rangeAtIndex:4], NSMakeRange(NSNotFound, 0))) {
            LOG("Unable to parse version1 upstream version: %@", version1);
            return NO;
        }
        upstream1 = [version1 substringWithRange:[mainVersion1Parts rangeAtIndex:4]];
    } else {
        upstream1 = [version1 substringWithRange:[mainVersion1Parts rangeAtIndex:2]];
    }
    
    NSString *upstream2;
    if (NSEqualRanges([mainVersion2Parts rangeAtIndex:2], NSMakeRange(NSNotFound, 0))) {
        if (NSEqualRanges([mainVersion2Parts rangeAtIndex:4], NSMakeRange(NSNotFound, 0))) {
            LOG("Unable to parse version2 upstream version: %@", version2);
            return NO;
        }
        upstream2 = [version2 substringWithRange:[mainVersion2Parts rangeAtIndex:4]];
    } else {
        upstream2 = [version2 substringWithRange:[mainVersion2Parts rangeAtIndex:2]];
    }
    
    NSString *deb1;
    if (NSEqualRanges([mainVersion1Parts rangeAtIndex:3], NSMakeRange(NSNotFound, 0))) {
        deb1 = @"0";
    } else {
        deb1 = [version1 substringWithRange:[mainVersion1Parts rangeAtIndex:3]];
    }
    
    NSString *deb2;
    if (NSEqualRanges([mainVersion2Parts rangeAtIndex:3], NSMakeRange(NSNotFound, 0))) {
        deb2 = @"0";
    } else {
        deb2 = [version2 substringWithRange:[mainVersion2Parts rangeAtIndex:3]];
    }
    
    enum dpkgComparisonResult res = testComp(versioncomp(epoch1, epoch2), op, false);
    if (res == resPending)
        res = testComp(versioncomp(upstream1, upstream2), op, false);
    if (res == resPending)
        res = testComp(versioncomp(deb1, deb2), op, true);
    
    *result = res == resSatisfied;
    return YES;
}

NSArray *getDepsForPkg(NSString *pkg) {
    NSDictionary *pkgs = getPkgs();
    
    return pkgs[pkg][@"Depends"];
}

NSArray *getPreDepsForPkg(NSString *pkg) {
    NSDictionary *pkgs = getPkgs();
    
    return pkgs[pkg][@"Pre-Depends"];
}

NSArray *allDepsForPkg(NSString *pkg) {
    NSArray *deps = getDepsForPkg(pkg);
    NSArray *predeps = getPreDepsForPkg(pkg);
    if (deps) {
        return [deps arrayByAddingObjectsFromArray:predeps];
    }
    return predeps;
}

NSArray *resolveDepsForPkgWithQueue(NSString *pkg, NSMutableArray *queue, BOOL preDeps) {
    if (pkg == nil) {
        LOG("I can't resolve deps for no pkg. WTF.");
        return nil;
    }

    NSArray *deps = preDeps?allDepsForPkg(pkg):getDepsForPkg(pkg);
    NSDictionary *pkgs = getPkgs();
    
    if (queue == nil) {
        queue = [NSMutableArray new];
    }
    
    NSRegularExpression *or = [NSRegularExpression regularExpressionWithPattern:@"\\s*([^\\|]+)\\s*\\|?" options:0 error:nil];
    for (NSString *dep in deps) {
        BOOL __block resolved = NO;
        [or enumerateMatchesInString:dep options:0 range:NSMakeRange(0, dep.length) usingBlock:^(NSTextCheckingResult * _Nullable result, NSMatchingFlags flags, BOOL * _Nonnull stop) {
            NSString *match = [dep substringWithRange:[result rangeAtIndex:1]];
            NSDictionary *ver = parseDependsOrProvides(match);
            //            LOG("Match: %@ op: %@ ver: %@", ver[@"name"], ver[@"op"], ver[@"ver"]);
            match = ver[@"name"];
            if (pkgs[match] != nil) {
                if (ver[@"op"]) {
                    compareDpkgVersion(pkgs[match][@"Version"], ver[@"op"], ver[@"ver"], &resolved);
                } else {
                    resolved = YES;
                }
                if (resolved && ![queue containsObject:match]) {
                    [queue addObject:match];
                    if (resolveDepsForPkgWithQueue(match, queue, preDeps) == nil) {
                        LOG("Unmarking %@ as resolved because deps could not be satisified", match);
                        resolved = NO;
                        [queue removeObject:match];
                    } else {
                        // Move to the end of the queue so deps are installed first
                        [queue removeObject:match];
                        [queue addObject:match];
                    }
                }
            }
            if (!resolved) {
//                LOG("Unable to resolve dep: %@ for %@ - trying provides", dep, pkg);
                for (NSString *pkg in pkgs.allKeys) {
                    for (NSString *provide in pkgs[pkg][@"Provides"]) {
                        NSDictionary *provided = parseDependsOrProvides(provide);
                        if ([provided[@"name"] isEqualToString:match]) {
                            if (ver[@"op"]) {
                                if (provided[@"op"] && [provided[@"op"] isEqualToString:@"="]) {
                                    compareDpkgVersion(provided[@"ver"], ver[@"op"], ver[@"ver"], &resolved);
                                }
                            } else {
                                resolved = YES;
                            }
                        }
                        if (resolved && ![queue containsObject:pkg]) {
                            [queue addObject:pkg];
                            if (resolveDepsForPkgWithQueue(pkg, queue, preDeps) == nil) {
                                LOG("Unmarking %@ as resolved because deps could not be satisified", match);
                                resolved = NO;
                                [queue removeObject:pkg];
                            } else {
                                [queue removeObject:pkg];
                                [queue addObject:pkg];
                            }
                            break;
                        }
                    }
                    if (resolved)
                        break;
                }
            }
            
            *stop = resolved;
        }];
        if (!resolved) {
            LOG("Unable to resolve dep: %@ for %@", dep, pkg);
            return nil;
        }
    }
    if (![queue containsObject:pkg])
        [queue addObject:pkg];
    return queue;
}

NSArray *resolveDepsForPkg(NSString *pkg, BOOL preDeps) {
    return resolveDepsForPkgWithQueue(pkg, nil, preDeps);
}

BOOL extractDebsForPkg(NSString *pkg, NSMutableArray *installed, BOOL preDeps, bool doInject) {
    NSArray *pkgsForPkg = resolveDepsForPkg(pkg, preDeps);
    if (pkgsForPkg == nil || pkgsForPkg.count < 1) {
        LOG("Found no pkgs to install for \"%@\"", pkg);
        return NO;
    }
    NSMutableArray *debsForPkg = [debsForPkgs(pkgsForPkg) mutableCopy];
    if (debsForPkg == nil) {
        LOG("Found no debs to install for \"%@\"", pkg);
        return NO;
    }
    if (installed != nil) {
        [debsForPkg removeObjectsInArray:installed];
    }
    if (debsForPkg.count < 1) {
        // Already installed all these
        return YES;
    }
    if (!extractDebs(debsForPkg, doInject)) {
        LOG("Failed to extract debs for \"%@\"", pkg);
        return NO;
    }
    [installed addObjectsFromArray:debsForPkg];
    return YES;
}

NSDictionary *getPkgs(void) {
    static NSDictionary *pkgs = nil;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        NSMutableDictionary *mpkgs = [NSMutableDictionary new];
        NSString *pkgs_path = pathForResource(@"apt/Packages");
        if (pkgs_path == nil) {
            return;
        }
        
        FILE *pkgs_file = fopen(pkgs_path.UTF8String, "r");
        if (pkgs_file == NULL) {
            return;
        }
        char *line = NULL;
        size_t linelen = 0;
        NSString *pkg_id = nil;
        while (getline(&line, &linelen, pkgs_file) != -1) {
            char *newline = strchr(line, '\n');
            if (newline) {
                *newline = '\0';
            }
            char *val = strchr(line, ':');
            if (val == NULL) {
                pkg_id = nil;
                continue;
            }
            char *field = line;
            field[val - line] = '\0';
            do {
                val++;
            } while (*val == ' ');
            if (strcmp(field, "Package") == 0) {
                pkg_id = @(val);
                mpkgs[pkg_id] = [NSMutableDictionary new];
            } else {
                if (![mpkgs[pkg_id] isKindOfClass:[NSMutableDictionary class]]) {
                    LOG("Error reading Packages, Package: must come before values");
                    fclose(pkgs_file);
                    return;
                }
//                LOG(@"pkgs[%@][%s] = %s\n", pkg_id, field, val);
                if (strcmp(field, "Depends") == 0 ||
                    strcmp(field, "Pre-Depends") == 0 ||
                    strcmp(field, "Conflicts") == 0 ||
                    strcmp(field, "Provides") == 0
                    ) {
                    mpkgs[pkg_id][@(field)] = [@(val) componentsSeparatedByString:@", "];
                } else {
                    mpkgs[pkg_id][@(field)] = @(val);
                }
            }
        }
        SafeFreeNULL(line);
        fclose(pkgs_file);
        
        mpkgs[@"firmware"] = @{
                               @"Version": [[UIDevice currentDevice] systemVersion],
                               @"Filename": @"virtual"
                               };
        mpkgs[@"firmware-sbin"] = @{
                                    @"Version": @"0-1",
                                    @"Filename": @"virtual"
                                    };
        
        pkgs = [mpkgs copy];
    });
    return pkgs;
}

NSString *debForPkg(NSString *pkg) {
    NSDictionary *pkgs = getPkgs();
    NSString *file = pkgs[pkg][@"Filename"];
    if (file == nil) {
        LOG(@"file == nil");
        return nil;
    }
    if ([file isEqualToString:@"virtual"]) {
        return @"virtual";
    }
    
    return pathForResource([@"apt" stringByAppendingPathComponent:file]);
}

NSString *versionOfPkg(NSString *pkg) {
    NSDictionary *pkgs = getPkgs();
    
    if (pkgs[pkg])
        return pkgs[pkg][@"Version"];
    
    return nil;
}

NSArray <NSString*> *debsForPkgs(NSArray <NSString*> *pkgs) {
    NSMutableArray *paths = [NSMutableArray new];
    for (NSString* pkg in pkgs) {
        NSString *path = debForPkg(pkg);
        if (!path) {
            LOG("Unable to resolve %@ to a deb", pkg);
            return nil;
        }
        if (![path isEqualToString:@"virtual"])
            [paths addObject:path];
    }
    return [paths copy];
}
