//
//  panic.c
//  Undecimus
//
//  Created by Pwn20wnd on 4/20/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#include <stdlib.h>
#include <mach/mach.h>
#include <common.h>
#include "kalloc_crash.h"

struct simple_msg
{
    mach_msg_header_t hdr;
    char buf[0];
};

/* credits to ian beer */
static mach_port_t send_kalloc_message(uint8_t *replacer_message_body, uint32_t replacer_body_size)
{
    // allocate a port to send the messages to
    mach_port_t q = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);
    if (err != KERN_SUCCESS)
    {
        printf(" [-] failed to allocate port\n");
        exit(EXIT_FAILURE);
    }
    
    mach_port_limits_t limits = {0};
    limits.mpl_qlimit = MACH_PORT_QLIMIT_LARGE;
    err = mach_port_set_attributes(mach_task_self(),
                                   q,
                                   MACH_PORT_LIMITS_INFO,
                                   (mach_port_info_t)&limits,
                                   MACH_PORT_LIMITS_INFO_COUNT);
    if (err != KERN_SUCCESS)
    {
        printf(" [-] failed to increase queue limit\n");
        exit(EXIT_FAILURE);
    }
    
    mach_msg_size_t msg_size = sizeof(struct simple_msg) + replacer_body_size;
    struct simple_msg *msg = malloc(msg_size);
    memset(msg, 0, sizeof(struct simple_msg));
    memcpy(&msg->buf[0], replacer_message_body, replacer_body_size);
    
    for (int i = 0; i < 256; i++)
    {
        msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
        msg->hdr.msgh_size = msg_size;
        msg->hdr.msgh_remote_port = q;
        msg->hdr.msgh_local_port = MACH_PORT_NULL;
        msg->hdr.msgh_id = 0x41414142;
        
        err = mach_msg(&msg->hdr,
                       MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                       msg_size,
                       0,
                       MACH_PORT_NULL,
                       MACH_MSG_TIMEOUT_NONE,
                       MACH_PORT_NULL);
        
        if (err != KERN_SUCCESS)
        {
            printf(" [-] failed to send message %x (%d): %s\n", err, i, mach_error_string(err));
            exit(EXIT_FAILURE);
        }
    }
    
    return q;
}

static uint32_t message_size_for_kalloc_size(uint32_t size)
{
    return ((size * 3) / 4) - 0x74;
}

void do_kalloc_crash() {
    for (;;) {
        uint32_t body_size = message_size_for_kalloc_size(16384) - sizeof(mach_msg_header_t); // 1024
        uint8_t *body = malloc(body_size);
        memset(body, 0x41, body_size);
        send_kalloc_message(body, body_size);
        SafeFreeNULL(body);
    }
}
