//
//  libfragmentzip.h
//  libfragmentzip
//
//  Created by tihmstar on 24.12.16.
//  Copyright © 2016 tihmstar. All rights reserved.
//

#ifndef libfragmentzip_h
#define libfragmentzip_h

#include <curl/curl.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef _WIN32
#define STATIC_INLINE static __inline
#define ATTRIBUTE_PACKED
#pragma pack(push)
#pragma pack(1)
#else
#define STATIC_INLINE static inline
#define ATTRIBUTE_PACKED __attribute__ ((packed))
#endif

#define makeBE32(a) makeEndian((char *)(&(a)), 4, 1)
#define makeLE32(a) makeEndian((char *)(&(a)), 4, 0)
#define makeBE16(a) makeEndian((char *)(&(a)), 2, 1)
#define makeLE16(a) makeEndian((char *)(&(a)), 2, 0)

#define fragmentzip_nextCD(cd) ((fragmentzip_cd *)(cd->filename+cd->len_filename+cd->len_extra_field+cd->len_file_comment))

#ifdef __cplusplus
extern "C"
{
#else
typedef enum{
    false = 0,
    true = 1
}bool;
#endif

typedef struct{
    uint32_t signature;
    uint16_t version;
    uint16_t flags;
    uint16_t compression;
    uint16_t modtime;
    uint16_t moddate;
    uint32_t crc32;
    uint32_t size_compressed;
    uint32_t size_uncompressed;
    uint16_t len_filename;
    uint16_t len_extra_field;
    char filename[1]; //variable length
//    char extra_field[]; //variable length
} ATTRIBUTE_PACKED fragentzip_local_file;

typedef struct{
    uint32_t crc32;
    uint32_t size_compressed;
    uint32_t size_uncompressed;
} ATTRIBUTE_PACKED fragmentzip_data_descriptor;

typedef struct{
    uint32_t signature;
    uint16_t disk_cur_number;
    uint16_t disk_cd_start_number;
    uint16_t cd_disk_number;
    uint16_t cd_entries;
    uint32_t cd_size;
    uint32_t cd_start_offset;
    uint16_t comment_len;
} ATTRIBUTE_PACKED fragmentzip_end_of_cd;

typedef struct{
    uint32_t signature;
    uint16_t version;
    uint16_t pkzip_version_needed;
    uint16_t flags;
    uint16_t compression;
    uint16_t modtime;
    uint16_t moddate;
    uint32_t crc32;
    uint32_t size_compressed;
    uint32_t size_uncompressed;
    uint16_t len_filename;
    uint16_t len_extra_field;
    uint16_t len_file_comment;
    uint16_t disk_num;
    uint16_t internal_attribute;
    uint32_t external_attribute;
    uint32_t local_header_offset;
    char filename[1]; //variable length
//    char extra_field[]; //variable length
//    char file_comment[]; //variable length
} ATTRIBUTE_PACKED fragmentzip_cd;


typedef struct fragmentzip_info{
    char *url;
    CURL *mcurl;
    FILE *localFile;
    uint64_t length;
    fragmentzip_cd *cd;
    fragmentzip_end_of_cd *cd_end;
} fragmentzip_t;


STATIC_INLINE bool isBigEndian(){
    static const uint32_t tst = 0x41424344;
    return (bool)__builtin_expect(((char*)&tst)[0] == 0x41,0);
}

STATIC_INLINE void makeEndian(char * buf, unsigned int size, bool big){
    if (isBigEndian() != big){
        switch (size) {
            case 2:
                buf[0] ^= buf[1];
                buf[1] ^= buf[0];
                buf[0] ^= buf[1];
                break;
            case 4:
                buf[0] ^= buf[3];
                buf[3] ^= buf[0];
                buf[0] ^= buf[3];
                
                buf[2] ^= buf[1];
                buf[1] ^= buf[2];
                buf[2] ^= buf[1];
                break;
                
            default:
                printf("[FATAL] operation not supported\n");
                exit(1);
                break;
        }
    }
}

typedef void (*fragmentzip_process_callback_t)(unsigned int progress);

fragmentzip_t *fragmentzip_open(const char *url);
fragmentzip_t *fragmentzip_open_extended(const char *url, CURL *mcurl); //pass custom CURL with web auth by basic/digest or cookies

int fragmentzip_download_file(fragmentzip_t *info, const char *remotepath, const char *savepath, fragmentzip_process_callback_t callback);
void fragmentzip_close(fragmentzip_t *info);

fragmentzip_cd *fragmentzip_getCDForPath(fragmentzip_t *info, const char *path);
fragmentzip_cd *fragmentzip_getNextCD(fragmentzip_cd *cd);

const char* fragmentzip_version();

#ifdef __cplusplus
}
#endif

#endif /* libfragmentzip_h */
