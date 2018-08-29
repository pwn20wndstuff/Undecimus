#ifndef libjb_h_included
#define libjb_h_included

/* entitlements *************************************************************/

int entitle(uint64_t proc, const char *ent, int verbose);

/* hdik *********************************************************************/

int attach(const char *path, char buf[], size_t sz);

/* mount ********************************************************************/

struct hfs_mount_args {
	char	*fspec;			/* block special device to mount */
	uid_t	hfs_uid;		/* uid that owns hfs files (standard HFS only) */
	gid_t	hfs_gid;		/* gid that owns hfs files (standard HFS only) */
	mode_t	hfs_mask;		/* mask to be applied for hfs perms  (standard HFS only) */
	u_int32_t hfs_encoding;	/* encoding for this volume (standard HFS only) */
	struct	timezone hfs_timezone;	/* user time zone info (standard HFS only) */
	int		flags;			/* mounting flags, see below */
	int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
	int		journal_flags;          /* flags to pass to journal_open/create */
	int		journal_disable;        /* don't use journaling (potentially dangerous) */
} args;

/* hashes *******************************************************************/

struct trust_dsk {
    unsigned int version;
    unsigned char uuid[16];
    unsigned int count;
    //unsigned char data[];
} __attribute__((packed));

struct trust_mem {
    uint64_t next; //struct trust_mem *next;
    unsigned char uuid[16];
    unsigned int count;
    //unsigned char data[];
} __attribute__((packed));

struct hash_entry_t {
    uint16_t num;
    uint16_t start;
} __attribute__((packed));

typedef uint8_t hash_t[20];

extern hash_t *allhash;
extern unsigned numhash;
extern struct hash_entry_t *amfitab;
extern hash_t *allkern;

/* can be called multiple times. kernel read func & amfi/top trust chain block are optional */
int grab_hashes(const char *root, size_t (*kread)(uint64_t, void *, size_t), uint64_t amfi, uint64_t top);

#endif

