/*
 * log.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__LOG_H_
#define VOUCHER_SWAP__LOG_H_

#include <stdarg.h>
#include <stdio.h>

/*
 * log_implementation
 *
 * Description:
 * 	This is the log handler that will be executed when code wants to log a message. The default
 * 	implementation logs the message to stderr. Setting this value to NULL will disable all
 * 	logging. Specify a custom log handler to process log messages in another way.
 *
 * Parameters:
 * 	type				A character representing the type of message that is being
 * 					logged.
 * 	format				A printf-style format string describing the error message.
 * 	ap				The variadic argument list for the format string.
 *
 * Log Type:
 * 	The type parameter is one of:
 * 	- D: Debug:     Used for debugging messages. Set the DEBUG build variable to control debug
 * 	                verbosity.
 * 	- I: Info:      Used to convey general information about the exploit or its progress.
 * 	- W: Warning:   Used to indicate that an unusual but possibly recoverable condition was
 * 	                encountered.
 * 	- E: Error:     Used to indicate that an unrecoverable error was encountered. The code
 * 	                might continue running after an error was encountered, but it probably will
 * 	                not succeed.
 */
extern void (*log_implementation)(char type, const char *format, va_list ap);

#define DEBUG_LEVEL(level)	(DEBUG && level <= DEBUG)

#if DEBUG
#define DEBUG_TRACE(level, fmt, ...)						\
	do {									\
		if (DEBUG_LEVEL(level)) {					\
			log_internal('D', fmt, ##__VA_ARGS__);			\
		}								\
	} while (0)
#else
#define DEBUG_TRACE(level, fmt, ...)	do {} while (0)
#endif
#define INFO(fmt, ...)		log_internal('I', fmt, ##__VA_ARGS__)
#define WARNING(fmt, ...)	log_internal('W', fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...)		log_internal('E', fmt, ##__VA_ARGS__)

// A function to call the logging implementation.
void log_internal(char type, const char *format, ...) __printflike(2, 3);

#endif
