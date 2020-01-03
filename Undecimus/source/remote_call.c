#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <mach/task.h>

#include "remote_call.h"
#include "remote_memory.h"

#include <common.h>

#if !__arm64e__
static uint64_t find_gadget_candidate(char **alternatives, size_t gadget_length) {
    void *const haystack_start = (void *)atoi; // will do...
    size_t haystack_size = 100*1024*1024; // likewise...
    
    for (char *candidate = *alternatives; candidate != NULL; alternatives++) {
        void *found_at = memmem(haystack_start, haystack_size, candidate, gadget_length);
        if (found_at != NULL){
            LOG("found at: %llx", (uint64_t)found_at);
            return (uint64_t)found_at;
        }
    }
    return 0;
}

static uint64_t blr_x19_addr = 0;
static uint64_t find_blr_x19_gadget()
{
    if (blr_x19_addr != 0){
        return blr_x19_addr;
    }
    char *const blr_x19 = "\x60\x02\x3f\xd6";
    char* candidates[] = {blr_x19, NULL};
    blr_x19_addr = find_gadget_candidate(candidates, 4);
    return blr_x19_addr;
}

#endif

// no support for non-register args
#define MAX_REMOTE_ARGS 8

// not in iOS SDK headers:
extern void
_pthread_set_self(
    pthread_t p);

uint64_t call_remote(mach_port_t task_port, void* fptr, int n_params, ...)
{
#if __arm64e__
    return 0;
#else
    if (n_params > MAX_REMOTE_ARGS || n_params < 0) {
        LOG("unsupported number of arguments to remote function (%d)", n_params);
        return 0;
    }

    kern_return_t err;

    uint64_t remote_stack_base = 0;
    uint64_t remote_stack_size = 4 * 1024 * 1024;

    remote_stack_base = remote_alloc(task_port, remote_stack_size);

    uint64_t remote_stack_middle = remote_stack_base + (remote_stack_size / 2);

    // create a new thread in the target
    // just using the mach thread API doesn't initialize the pthread thread-local-storage
    // which means that stuff which relies on that will crash
    // we can sort-of make that work by calling _pthread_set_self(NULL) in the target process
    // which will give the newly created thread the same TLS region as the main thread

    _STRUCT_ARM_THREAD_STATE64 thread_state = { 0 };
    mach_msg_type_number_t thread_stateCnt = sizeof(thread_state) / 4;

    // we'll start the thread running and call _pthread_set_self first:
    thread_state.__sp = remote_stack_middle;
    thread_state.__pc = (uint64_t)_pthread_set_self;

    // set these up to put us into a predictable state we can monitor for:
    uint64_t loop_lr = find_blr_x19_gadget();
    thread_state.__x[19] = loop_lr;
    thread_state.__lr = loop_lr;

    // set the argument to NULL:
    thread_state.__x[0] = 0;

    mach_port_t thread_port = MACH_PORT_NULL;

    err = thread_create_running(task_port, ARM_THREAD_STATE64, (thread_state_t)&thread_state, thread_stateCnt, &thread_port);
    if (err != KERN_SUCCESS) {
        LOG("error creating thread in child: %s", mach_error_string(err));
        return 0;
    }
    LOG("new thread running in child: %x", thread_port);

    // wait for it to hit the loop:
    while (1) {
        // monitor the thread until we see it's in the infinite loop indicating it's done:
        err = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&thread_state, &thread_stateCnt);
        if (err != KERN_SUCCESS) {
            LOG("error getting thread state: %s", mach_error_string(err));
            return 0;
        }

        if (thread_state.__pc == loop_lr && thread_state.__x[19] == loop_lr) {
            // thread has returned from the target function
            break;
        }
    }

    // the thread should now have pthread local storage
    // pause it:

    err = thread_suspend(thread_port);
    if (err != KERN_SUCCESS) {
        LOG("unable to suspend target thread");
        return 0;
    }

    /*
   err = thread_abort(thread_port);
   if (err != KERN_SUCCESS){
   LOG("unable to get thread out of any traps");
   return 0;
   }
   */

    // set up for the actual target call:
    thread_state.__sp = remote_stack_middle;
    thread_state.__pc = (uint64_t)fptr;

    // set these up to put us into a predictable state we can monitor for:
    thread_state.__x[19] = loop_lr;
    thread_state.__lr = loop_lr;

    va_list ap;
    va_start(ap, n_params);

    arg_desc* args[MAX_REMOTE_ARGS] = { 0 };

    uint64_t remote_buffers[MAX_REMOTE_ARGS] = { 0 };
    //uint64_t remote_buffer_sizes[MAX_REMOTE_ARGS] = {0};

    for (int i = 0; i < n_params; i++) {
        arg_desc* arg = va_arg(ap, arg_desc*);

        args[i] = arg;

        switch (arg->type) {
        case ARG_LITERAL: {
            thread_state.__x[i] = arg->value;
            break;
        }

        case ARG_BUFFER:
        case ARG_BUFFER_PERSISTENT: {
            uint64_t remote_buffer = alloc_and_fill_remote_buffer(task_port, arg->value, arg->length);
            remote_buffers[i] = remote_buffer;
            thread_state.__x[i] = remote_buffer;
            break;
        }

        case ARG_OUT_BUFFER: {
            uint64_t remote_buffer = remote_alloc(task_port, arg->length);
            LOG("allocated a remote out buffer: %llx", remote_buffer);
            remote_buffers[i] = remote_buffer;
            thread_state.__x[i] = remote_buffer;
            break;
        }

        default: {
            LOG("invalid argument type!");
        }
        }
    }

    va_end(ap);

    err = thread_set_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&thread_state, thread_stateCnt);
    if (err != KERN_SUCCESS) {
        LOG("error setting new thread state: %s", mach_error_string(err));
        return 0;
    }
    LOG("thread state updated in target: %x", thread_port);

    err = thread_resume(thread_port);
    if (err != KERN_SUCCESS) {
        LOG("unable to resume target thread");
        return 0;
    }

    while (1) {
        // monitor the thread until we see it's in the infinite loop indicating it's done:
        err = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&thread_state, &thread_stateCnt);
        if (err != KERN_SUCCESS) {
            LOG("error getting thread state: %s", mach_error_string(err));
            return 0;
        }

        if (thread_state.__pc == loop_lr /*&& thread_state.__x[19] == loop_lr*/) {
            // thread has returned from the target function
            break;
        }

        // thread isn't in the infinite loop yet, let it continue
    }

    // deallocate the remote thread
    err = thread_terminate(thread_port);
    if (err != KERN_SUCCESS) {
        LOG("failed to terminate thread");
        return 0;
    }
    mach_port_deallocate(mach_task_self(), thread_port);

    // handle post-call argument cleanup/copying:
    for (int i = 0; i < MAX_REMOTE_ARGS; i++) {
        arg_desc* arg = args[i];
        if (arg == NULL) {
            break;
        }
        switch (arg->type) {
        case ARG_BUFFER: {
            remote_free(task_port, remote_buffers[i], arg->length);
            break;
        }

        case ARG_OUT_BUFFER: {
            // copy the contents back:
            remote_read_overwrite(task_port, remote_buffers[i], arg->value, arg->length);
            remote_free(task_port, remote_buffers[i], arg->length);
            break;
        }
        }
    }

    uint64_t ret_val = thread_state.__x[0];

    LOG("remote function call return value: %llx", ret_val);

    // deallocate the stack in the target:
    remote_free(task_port, remote_stack_base, remote_stack_size);

    return ret_val;
#endif
}

// thread should be suspended already; will return suspended
uint64_t thread_call_remote(mach_port_t thread_port, void* fptr, int n_params, ...)
{
#if __arm64e__
    return 0;
#else
    if (n_params > MAX_REMOTE_ARGS || n_params < 0) {
        LOG("unsupported number of arguments to remote function (%d)", n_params);
        return 0;
    }

    kern_return_t err;
    //#if 0
    // suspend the target thread we'll hijack:
    err = thread_suspend(thread_port);
    if (err != KERN_SUCCESS) {
        LOG("failed to suspend the thread we're trying to hijack: %s", mach_error_string(err));
        return 0;
    }
    //#endif

    // save its suspended state so we can restore it:
    _STRUCT_ARM_THREAD_STATE64 saved_thread_state = { 0 };
    mach_msg_type_number_t saved_thread_stateCnt = sizeof(saved_thread_state) / 4;
    // LOG("saved thread state count before: %d", saved_thread_stateCnt);
    err = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&saved_thread_state, &saved_thread_stateCnt);
    if (err != KERN_SUCCESS) {
        LOG("error getting thread state to save: %s", mach_error_string(err));
        return 0;
    }

    // dump the state:
    //LOG("pc: 0x%016llx", saved_thread_state.__pc);
    //LOG("sp: 0x%016llx", saved_thread_state.__sp);
    //for (int i = 0; i < 29; i++) {
    //  LOG("x%d: 0x%016llx", i, saved_thread_state.__x[i]);
    //}

    // build the state we need for the arbitrary call:
    _STRUCT_ARM_THREAD_STATE64 fcall_thread_state = { 0 };
    mach_msg_type_number_t fcall_thread_stateCnt = sizeof(fcall_thread_state) / 4;
    memcpy(&fcall_thread_state, &saved_thread_state, sizeof(fcall_thread_state));

    // make sure we can determine when the function call is done
    fcall_thread_state.__x[19] = find_blr_x19_gadget();
    fcall_thread_state.__lr = find_blr_x19_gadget();

    // set the pc
    fcall_thread_state.__pc = (uint64_t)fptr;

    // load the arguments
    va_list ap;
    va_start(ap, n_params);

    arg_desc* args[MAX_REMOTE_ARGS] = { 0 };

    for (int i = 0; i < n_params; i++) {
        arg_desc* arg = va_arg(ap, arg_desc*);

        args[i] = arg;

        switch (arg->type) {
        case ARG_LITERAL: {
            //LOG("setting arg %d to literal %llx", i, arg->value);
            fcall_thread_state.__x[i] = arg->value;
            break;
        }
#if 0
            case ARG_BUFFER:
            case ARG_BUFFER_PERSISTENT:
            {
                uint64_t remote_buffer = alloc_and_fill_remote_buffer(task_port, arg->value, arg->length);
                remote_buffers[i] = remote_buffer;
                thread_state.__x[i] = remote_buffer;
                break;
            }
                
            case ARG_OUT_BUFFER:
            {
                uint64_t remote_buffer = remote_alloc(task_port, arg->length);
                LOG("allocated a remote out buffer: %llx", remote_buffer);
                remote_buffers[i] = remote_buffer;
                thread_state.__x[i] = remote_buffer;
                break;
            }
#endif
        default: {
            LOG("invalid argument type!");
        }
        }
    }

    va_end(ap);
#if 0
    LOG("fcall thread state:");
    LOG("pc: 0x%016llx", fcall_thread_state.__pc);
    LOG("sp: 0x%016llx", fcall_thread_state.__sp);
    LOG("fp: 0x%016llx", fcall_thread_state.__fp);
    LOG("lr: 0x%016llx", fcall_thread_state.__lr);
    for (int i = 0; i < 29; i++) {
        LOG("x%d: 0x%016llx", i, fcall_thread_state.__x[i]);
    }
#endif

    // set the thread state:
    err = thread_set_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&fcall_thread_state, fcall_thread_stateCnt);
    if (err != KERN_SUCCESS) {
        LOG("error setting new thread state for hijacked thread: %s", mach_error_string(err));
        return 0;
    }

    // let the thread continue running with the new state:
    err = thread_resume(thread_port);
    if (err != KERN_SUCCESS) {
        LOG("error resuming hijacked thread: %s", mach_error_string(err));
        return 0;
    }
    //LOG("resumed thread");

    // monitor for the function call ending and the thread hitting the infinite loop:
    // we're reusing fcall state so we can also get the return value via x0
    while (1) {
        usleep(100 * 1000);
        thread_suspend(thread_port);
        err = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&fcall_thread_state, &fcall_thread_stateCnt);
        if (err != KERN_SUCCESS) {
            LOG("error getting thread state: %s", mach_error_string(err));
            return 0;
        }

        thread_resume(thread_port);

        if (fcall_thread_state.__pc == find_blr_x19_gadget()) {
            // thread has returned from the target function
            //LOG("hit looper!");
            break;
        }
        //LOG("got bad pc: 0x%llx", fcall_thread_state.__pc);
    }

    uint64_t ret_val = fcall_thread_state.__x[0];

    return ret_val;
#endif
}
