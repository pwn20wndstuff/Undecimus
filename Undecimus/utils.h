//
//  utils.h
//  Undecimus
//
//  Created by Sam Bingner on 11/23/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#ifndef utils_h
#define utils_h

int sha1_to_str(const unsigned char *hash, int hashlen, char *buf, size_t buflen);
NSString *sha1sum(NSString *file);
bool verifySha1Sums(NSString *sumFile);

#endif /* utils_h */
