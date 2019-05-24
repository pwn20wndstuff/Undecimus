//
//  FakeApt.h
//  This is far from a complete implementation
//
//  Created by Sam Bingner on 1/24/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#ifndef FakeApt_h
#define FakeApt_h

int versioncomp(NSString *v1, NSString *v2);
NSDictionary *parseDependsOrProvides(NSString *string);
BOOL compareDpkgVersion(NSString *version1, NSString *op, NSString *version2, BOOL *result);
NSString *versionOfPkg(NSString *pkg);
NSArray *resolveDepsForPkg(NSString * _Nonnull pkg, BOOL noPreDeps);
BOOL extractDebsForPkg(NSString *pkg, NSMutableArray *installed, BOOL preDeps, bool doInject);
NSDictionary *getPkgs(void);
NSString *debForPkg(NSString *pkg);
NSArray <NSString*> *debsForPkgs(NSArray <NSString*> *pkgs);

#endif /* FakeApt_h */
