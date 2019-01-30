/*
 * log.c
 * Brandon Azad
 */
#include "log.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void
log_internal(char type, const char *format, ...) {
	if (log_implementation != NULL) {
		va_list ap;
		va_start(ap, format);
		log_implementation(type, format, ap);
		va_end(ap);
	}
}

// The default logging implementation prints to stderr with a nice hacker prefix.
static void
log_stderr(char type, const char *format, va_list ap) {
	char *message = NULL;
	vasprintf(&message, format, ap);
	assert(message != NULL);
	switch (type) {
		case 'D': type = 'D'; break;
		case 'I': type = '+'; break;
		case 'W': type = '!'; break;
		case 'E': type = '-'; break;
	}
	fprintf(stderr, "[%c] %s\n", type, message);
	free(message);
}

void (*log_implementation)(char type, const char *format, va_list ap) = log_stderr;
