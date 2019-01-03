/*
 * "untar" is an extremely simple tar extractor:
 *  * A single C source file, so it should be easy to compile
 *    and run on any system with a C compiler.
 *  * Extremely portable standard C.  The only non-ANSI function
 *    used is mkdir().
 *  * Reads basic ustar tar archives.
 *  * Does not require libarchive or any other special library.
 *
 * To compile: cc -o untar untar.c
 *
 * Usage:  untar <archive>
 *
 * In particular, this program should be sufficient to extract the
 * distribution for libarchive, allowing people to bootstrap
 * libarchive on systems that do not already have a tar program.
 *
 * To unpack libarchive-x.y.z.tar.gz:
 *    * gunzip libarchive-x.y.z.tar.gz
 *    * untar libarchive-x.y.z.tar
 *
 * Written by Tim Kientzle, March 2009.
 * Modified by xerub, sometime in 2017.
 *
 * Released into the public domain.
 */

/* These are all highly standard and portable headers. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* This is for mkdir(); this may need to be changed for some platforms. */
#include <sys/stat.h>  /* For mkdir() */

#include <common.h>

/* Parse an octal number, ignoring leading and trailing nonsense. */
static int
parseoct(const char *p, size_t n)
{
	int i = 0;

	while (*p < '0' || *p > '7') {
		++p;
		--n;
	}
	while (*p >= '0' && *p <= '7' && n > 0) {
		i *= 8;
		i += *p - '0';
		++p;
		--n;
	}
	return (i);
}

/* Returns true if this is 512 zero bytes. */
static int
is_end_of_archive(const char *p)
{
	int n;
	for (n = 511; n >= 0; --n)
		if (p[n] != '\0')
			return (0);
	return (1);
}

/* Create a directory, including parent directories as necessary. */
static void
create_dir(char *pathname, int mode, int owner, int group)
{
	char *p;
	int r;

	struct stat st;
	r = stat(pathname, &st);
	if (r == 0) {
		return;
	}

	/* Strip trailing '/' */
	if (pathname[strlen(pathname) - 1] == '/')
		pathname[strlen(pathname) - 1] = '\0';

	/* Try creating the directory. */
	r = mkdir(pathname, mode);

	if (r != 0) {
		/* On failure, try creating parent directory. */
		p = strrchr(pathname, '/');
		if (p != NULL) {
			*p = '\0';
			create_dir(pathname, 0755, -1, -1);
			*p = '/';
			r = mkdir(pathname, mode);
		}
	}
	if (r != 0)
		LOG("Could not create directory %s\n", pathname);
	else if (owner >= 0 && group >= 0)
		chown(pathname, owner, group);
}

/* Create a file, including parent directory as necessary. */
static int
create_file(char *pathname, int mode, int owner, int group)
{
	int f;
	if (unlink(pathname) && errno != ENOENT) {
	LOG("untar unable to remove file %s: %s", pathname, strerror(errno));
		return -1;
	}
	f = creat(pathname, mode);
	if (f < 0) {
		/* Try creating parent dir and then creating file. */
		char *p = strrchr(pathname, '/');
		if (p != NULL) {
			*p = '\0';
			create_dir(pathname, 0755, -1, -1);
			*p = '/';
			f = creat(pathname, mode);
		}
	}
	fchown(f, owner, group);
	return (f);
}

/* Verify the tar checksum. */
static int
verify_checksum(const char *p)
{
	int n, u = 0;
	for (n = 0; n < 512; ++n) {
		if (n < 148 || n > 155)
			/* Standard tar checksum adds unsigned bytes. */
			u += ((unsigned char *)p)[n];
		else
			u += 0x20;

	}
	return (u == parseoct(p + 148, 8));
}

/* Extract a tar archive. */
bool untar(const char *file)
{
	bool status = false;
	char buff[512];
	int f = -1;
	size_t bytes_read;
	int filesize;

	FILE *a = fopen(file, "rb");
	if (a == NULL) {
		LOG("untar unable to open \"%s\" for reading: %s", file, strerror(errno));
		return status;
	}

	LOG("Extracting from %s\n", file);
	for (;;) {
		bytes_read = fread(buff, 1, 512, a);
		if (bytes_read < 512) {
			LOG("Short read on %s: expected 512, got %zd\n",
				file, bytes_read);
			goto end;
		}
		if (is_end_of_archive(buff)) {
			LOG("End of %s\n", file);
			status = true;
			goto end;
		}
		if (!verify_checksum(buff)) {
			LOG("Checksum failure\n");
			goto end;
		}
		filesize = parseoct(buff + 124, 12);
		switch (buff[156]) {
		case '1':
			LOG(" Ignoring hardlink %s\n", buff);
			break;
		case '2':
			LOG(" Extracting symlink %s -> %s\n", buff, buff + 157);
			if (unlink(buff) && errno != ENOENT) {
				break;
			}
			symlink(buff + 157, buff);
			break;
		case '3':
			LOG(" Ignoring character device %s\n", buff);
				break;
		case '4':
			LOG(" Ignoring block device %s\n", buff);
			break;
		case '5':
			LOG(" Extracting dir %s\n", buff);
			create_dir(buff, parseoct(buff + 100, 8), parseoct(buff + 108, 8), parseoct(buff + 116, 8));
			filesize = 0;
			break;
		case '6':
			LOG(" Ignoring FIFO %s\n", buff);
			break;
		default:
			LOG(" Extracting file %s\n", buff);
			f = create_file(buff, parseoct(buff + 100, 8), parseoct(buff + 108, 8), parseoct(buff + 116, 8));
			if (f<0) {
				goto end;
			}
			break;
		}
		while (filesize > 0) {
			bytes_read = fread(buff, 1, 512, a);
			if (bytes_read < 512) {
				LOG("Short read on %s: Expected 512, got %zd\n",
					file, bytes_read);
				goto end;
			}
			if (filesize < 512)
				bytes_read = filesize;
			if (f >= 0) {
				if (write(f, buff, bytes_read) != bytes_read)
				{
					LOG("Failed write\n");
					close(f);
					f = -1;
				}
			}
			filesize -= bytes_read;
		}
		if (f >= 0) {
			close(f);
			f = -1;
		}
	}
end:
	fclose(a);
	return status;
}

#ifdef HAVE_MAIN
int
main(int argc, char **argv)
{
	FILE *a;

	++argv; /* Skip program name */
	for ( ;*argv != NULL; ++argv) {
	untar(argv);
	}
	return (0);
}
#endif
