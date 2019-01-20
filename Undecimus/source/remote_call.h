#ifndef remote_call_h
#define remote_call_h

#include <stdarg.h>
#include <stdint.h>

enum arg_type {
    ARG_LITERAL,
    ARG_BUFFER,
    ARG_BUFFER_PERSISTENT, // don't free the buffer after the call
    ARG_OUT_BUFFER
};

typedef struct _arg_desc {
    uint64_t type;
    uint64_t value;
    uint64_t length;
} arg_desc;

#define REMOTE_LITERAL(val) \
    &(arg_desc) { ARG_LITERAL, (uint64_t)val, (uint64_t)0 }
#define REMOTE_BUFFER(ptr, size) \
    &(arg_desc) { ARG_BUFFER, (uint64_t)ptr, (uint64_t)size }
#define REMOTE_CSTRING(str) \
    &(arg_desc) { ARG_BUFFER, (uint64_t)str, (uint64_t)(strlen(str) + 1) }
#define REMOTE_BUFFER_PERSISTENT(ptr, size) \
    &(arg_desc) { ARG_BUFFER_PERSISTENT, (uint64_t)ptr, (uint64_t)size }
#define REMOTE_CSTRING_PERSISTENT(str) \
    &(arg_desc) { ARG_BUFFER_PERSISTENT, (uint64_t)str, (uint64_t)(strlen(str) + 1) }

// allocate a remote buffer and pass the address of that to the remote function
// when the function call is complete return the contents of that buffer to this process
// and deallocate the buffer in the remote process
// ptr should be a pointer to buffer capable of holding size bytes
//
// eg:
//    mach_port_t port = MACH_PORT_NULL;
//    call_remote(task_port, bootstrap_look_up, 3, REMOTE_LITERAL(remote_bootstrap_port), REMOTE_CSTRING("com.foo.bar"), REMOTE_OUT_BUFFER(&port, sizeof(port))
//    // port set to value of looked up port in remote process
//    // note that this doesn't actually transfer the port! use other helpers for that
#define REMOTE_OUT_BUFFER(ptr, size) \
    &(arg_desc) { ARG_OUT_BUFFER, (uint64_t)ptr, (uint64_t)size }

uint64_t call_remote(mach_port_t task_port, void* fptr, int n_params, ...);
uint64_t thread_call_remote(mach_port_t thread_port, void* fptr, int n_params, ...);

#endif
