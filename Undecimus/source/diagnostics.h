//
//  diagnostics.h
//  Undecimus
//
//  Created by Pwn20wnd on 5/3/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#ifndef diagnostics_h
#define diagnostics_h

#include <Foundation/Foundation.h>

#define STATUS_FILE @"/var/lib/dpkg/status"
#define CYDIA_LIST @"/etc/apt/sources.list.d/cydia.list"

NSArray *dependencyArrayFromString(NSString *depends);
NSArray *parsedPackageArray(void);
NSString *domainFromRepoObject(NSString *repoObject);
NSArray *sourcesFromFile(NSString *theSourceFile);
NSDictionary *getDiagnostics(void);

#endif /* diagnostics_h */
