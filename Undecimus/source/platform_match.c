/*
 * platform_match.c
 * Brandon Azad
 */
#include "platform_match.h"

#include <assert.h>
#include <string.h>

#include "log.h"
#include "platform.h"

// ---- Matching helper functions -----------------------------------------------------------------

// Advance past any spaces in a string.
static void
skip_spaces(const char **p) {
	const char *pch = *p;
	while (*pch == ' ') {
		pch++;
	}
	*p = pch;
}

// ---- Device matching ---------------------------------------------------------------------------

// A wildcard device version number.
#define ANY ((unsigned)(-1))

// Parse the version part of a device string.
static bool
parse_device_version_internal(const char *device_version, unsigned *major, unsigned *minor,
		bool allow_wildcard, const char **end) {
	const char *p = device_version;
	// Parse the major version, which might be a wildcard.
	unsigned maj = 0;
	if (allow_wildcard && *p == '*') {
		maj = ANY;
		p++;
	} else {
		for (;;) {
			char ch = *p;
			if (ch < '0' || '9' < ch) {
				break;
			}
			maj = maj * 10 + (ch - '0');
			p++;
		}
	}
	// Make sure we got the comma.
	if (*p != ',') {
		return false;
	}
	p++;
	// Parse the minor version, which might be a wildcard.
	unsigned min = 0;
	if (allow_wildcard && *p == '*') {
		min = ANY;
		p++;
	} else {
		for (;;) {
			char ch = *p;
			if (ch < '0' || '9' < ch) {
				break;
			}
			min = min * 10 + (ch - '0');
			p++;
		}
	}
	// If end is NULL, then require that we're at the end of the string. Else, return the end
	// of what we parsed.
	if (end == NULL) {
		if (*p != 0) {
			return false;
		}
	} else {
		*end = p;
	}
	// Return the values.
	*major = maj;
	*minor = min;
	return true;
}

// Parse a device name.
static bool
parse_device_internal(const char *device, char *device_type, unsigned *major, unsigned *minor,
		bool allow_wildcard, const char **end) {
	// "iPhone11,8" -> "iPhone", 11, 8; "iPad7,*" -> "iPad", 7, ANY
	// If this device name doesn't have a comma then we don't know how to parse it. Just set
	// the whole thing as the device type.
	const char *comma = strchr(device, ',');
	if (comma == NULL) {
unknown:
		strcpy(device_type, device);
		*major = 0;
		*minor = 0;
		return false;
	}
	// Walk backwards from the comma to the start of the major version.
	if (comma == device) {
		goto unknown;
	}
	const char *p = comma;
	for (;;) {
		char ch = *(p - 1);
		if (!(('0' <= ch && ch <= '9') || (allow_wildcard && ch == '*'))) {
			break;
		}
		p--;
		if (p == device) {
			goto unknown;
		}
	}
	if (p == comma) {
		goto unknown;
	}
	size_t device_type_length = p - device;
	// Parse the version numbers.
	bool ok = parse_device_version_internal(p, major, minor, allow_wildcard, end);
	if (!ok) {
		goto unknown;
	}
	// Return the device_type string. This is last in case it's shared with the device string.
	strncpy(device_type, device, device_type_length);
	device_type[device_type_length] = 0;
	return true;
}

// Parse a device name.
static bool
parse_device(const char *device, char *device_type, unsigned *major, unsigned *minor) {
	return parse_device_internal(device, device_type, major, minor, false, NULL);
}

// Parse a device range string.
static bool
parse_device_range(const char *device, char *device_type,
		unsigned *min_major, unsigned *min_minor,
		unsigned *max_major, unsigned *max_minor,
		const char **end) {
	char dev_type[32];
	const char *next = device;
	// First parse a full device.
	bool ok = parse_device_internal(next, dev_type, min_major, min_minor, true, &next);
	if (!ok) {
unknown:
		strcpy(device_type, device);
		*min_major = 0;
		*min_minor = 0;
		*max_major = 0;
		*max_minor = 0;
		return false;
	}
	// Optionally parse a separator and more versions.
	if (*next == 0) {
		*max_major = *min_major;
		*max_minor = *min_minor;
	} else if (*next == '-') {
		next++;
		ok = parse_device_version_internal(next, max_major, max_minor, true, &next);
		if (!ok) {
			goto unknown;
		}
	}
	*end = next;
	// Return the device_type.
	strcpy(device_type, dev_type);
	return true;
}

// Check if the given device number is numerically within range.
static bool
numerical_device_match(unsigned major, unsigned minor,
		unsigned min_major, unsigned min_minor, unsigned max_major, unsigned max_minor) {
	if (major < min_major && min_major != ANY) {
		return false;
	}
	if ((major == min_major || min_major == ANY)
			&& minor < min_minor && min_minor != ANY) {
		return false;
	}
	if (major > max_major && max_major != ANY) {
		return false;
	}
	if ((major == max_major || max_major == ANY)
			&& minor > max_minor && max_minor != ANY) {
		return false;
	}
	return true;
}

// Match a specific device against a device match list.
static bool
match_device(const char *device, const char *devices) {
	if (devices == NULL || strcmp(devices, "*") == 0) {
		return true;
	}
	// Parse this device.
	char device_type[32];
	unsigned major, minor;
	parse_device(device, device_type, &major, &minor);
	// Parse the match list.
	const char *next = devices;
	while (*next != 0) {
		// Parse the next device range.
		char match_device_type[32];
		unsigned min_major, min_minor, max_major, max_minor;
		parse_device_range(next, match_device_type, &min_major, &min_minor,
				&max_major, &max_minor, &next);
		if (*next != 0) {
			skip_spaces(&next);
			assert(*next == '|');
			next++;
			skip_spaces(&next);
			assert(*next != 0);
		}
		// Check if this is a match.
		if (strcmp(device_type, match_device_type) == 0
				&& numerical_device_match(major, minor,
					min_major, min_minor, max_major, max_minor)) {
			return true;
		}
	}
	return false;
}

// ---- Build matching ----------------------------------------------------------------------------

// Parse a build version string into a uint64_t. Maintains comparison order.
static uint64_t
parse_build_version(const char *build, const char **end) {
	// 16A5288q -> [2 bytes][1 byte][3 bytes][1 byte]
	const char *p = build;
	// Parse out the major number.
	uint64_t major = 0;
	for (;;) {
		char ch = *p;
		if (ch < '0' || '9' < ch) {
			break;
		}
		major = major * 10 + (ch - '0');
		p++;
	}
	// Parse out the minor.
	uint64_t minor = 0;
	for (;;) {
		char ch = *p;
		if (ch < 'A' || 'Z' < ch) {
			break;
		}
		minor = (minor << 8) + ch;
		p++;
	}
	// Parse out the patch.
	uint64_t patch = 0;
	for (;;) {
		char ch = *p;
		if (ch < '0' || '9' < ch) {
			break;
		}
		patch = patch * 10 + (ch - '0');
		p++;
	}
	// Parse out the alpha.
	uint64_t alpha = 0;
	for (;;) {
		char ch = *p;
		if (ch < 'a' || 'z' < ch) {
			break;
		}
		alpha = (alpha << 8) + ch;
		p++;
	}
	// Construct the full build version.
	if (end != NULL) {
		*end = p;
	}
	return ((major << (8 * 5))
			| (minor << (8 * 4))
			| (patch << (8 * 1))
			| (alpha << (8 * 0)));
}

// Parse a build version range string.
static void
parse_build_version_range(const char *builds, uint64_t *version_min, uint64_t *version_max) {
	const char *next = builds;
	uint64_t min, max;
	// Parse the lower range.
	if (*next == '*') {
		min = 0;
		next++;
	} else {
		min = parse_build_version(next, &next);
	}
	// Parse the upper range (if it exists).
	if (*next == 0) {
		assert(min != 0);
		max = min;
	} else {
		skip_spaces(&next);
		assert(*next == '-');
		next++;
		skip_spaces(&next);
		if (*next == '*') {
			max = (uint64_t)(-1);
			next++;
		} else {
			max = parse_build_version(next, &next);
		}
		assert(*next == 0);
	}
	*version_min = min;
	*version_max = max;
}

// Check if the given build version string matches the build range.
static bool
match_build(const char *build, const char *builds) {
	if (builds == NULL || strcmp(builds, "*") == 0) {
		return true;
	}
	uint64_t version = parse_build_version(build, NULL);
	uint64_t version_min, version_max;
	parse_build_version_range(builds, &version_min, &version_max);
	return (version_min <= version && version <= version_max);
}

// ---- Public API --------------------------------------------------------------------------------

bool
platform_matches_device(const char *device_range) {
	return match_device(platform.machine, device_range);
}

bool
platform_matches_build(const char *build_range) {
	return match_build(platform.osversion, build_range);
}

bool
platform_matches(const char *device_range, const char *build_range) {
	return platform_matches_device(device_range)
		&& platform_matches_build(build_range);
}
