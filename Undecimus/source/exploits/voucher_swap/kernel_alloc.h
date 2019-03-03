/*
 * kernel_alloc.h
 * Brandon Azad
 */
#ifndef VOUCHER_SWAP__KERNEL_ALLOC_H_
#define VOUCHER_SWAP__KERNEL_ALLOC_H_

#include <mach/mach.h>
#include <stddef.h>

/*
 * message_size_for_kalloc_size
 *
 * Description:
 * 	Return the Mach message size needed for the ipc_kmsg to be allocated from the specified
 * 	kalloc zone. This is exactly correct when kalloc_size is a multiple of 16, otherwise it
 * 	could be slightly small.
 */
size_t message_size_for_kalloc_size(size_t kalloc_size);

/*
 * kalloc_size_for_message_size
 *
 * Description:
 * 	Return the kalloc allocation size corresponding to sending a message of the specified size.
 *
 * 	This is only correct for messages large enough that the ipc_kmsg struct is allocated with
 * 	kalloc().
 */
size_t kalloc_size_for_message_size(size_t message_size);

/*
 * ipc_kmsg_size_for_message_size
 *
 * Description:
 * 	Return the allocation size of the ipc_kmsg for the given message size.
 */
size_t ipc_kmsg_size_for_message_size(size_t message_size);

/*
 * ool_ports_spray_port
 *
 * Description:
 * 	Spray the given Mach port with Mach messages that contain out-of-line ports descriptors
 * 	with the given ports. The goal is to spray the target kalloc zone with many copies of a
 * 	particular array of OOL ports.
 *
 * 	Make sure that the port's queue limits are sufficient to hold the specified number of
 * 	messages.
 *
 * 	Unfortunately, we cannot avoid the creation of ipc_kmsg objects to hold the messages
 * 	enqueued on the port. You should ensure that the appropriate kalloc zone's freelist has
 * 	sufficiently many intermediates to ensure that ipc_kmsg allocation does not interfere with
 * 	the OOL ports spray.
 *
 * 	There are limits on the number of OOL ports that can be sent in a message, the number of
 * 	descriptors in a message, and the number of messages that can be queued on a port. Be sure
 * 	that the parameters you supply are valid, since this function does not check whether or not
 * 	the kernel will let your message through (or even whether they make sense).
 *
 * Parameters:
 * 	holding_port			The port on which to enqueue the Mach messages.
 * 	ool_ports			The OOL Mach ports to spray.
 * 	port_count			The number of OOL Mach ports.
 * 	ool_disposition			The disposition to send the OOL ports.
 * 	ool_count			The number of OOL ports descriptors to send per message.
 * 	message_size			The size of each message.
 * 	message_count			The number of messages to enqueue on the holding port.
 *
 * Returns:
 * 	Returns the number of messages that were successfully sent.
 */
size_t ool_ports_spray_port(mach_port_t holding_port,
		const mach_port_t *ool_ports, size_t port_count,
		mach_msg_type_name_t ool_disposition, size_t ool_count,
		size_t message_size, size_t message_count);

/*
 * kalloc_spray_port
 *
 * Description:
 * 	Spray the specified kalloc_zone with at least kalloc_count allocations by sending Mach
 * 	messages containing OOL ports to the specified holding port. Returns the number of kalloc
 * 	allocations that were actually performed.
 *
 * 	The point of this function is to quickly make as many kalloc allocations in the target zone
 * 	as possible using the specified holding port. The way we do this is by sending messages
 * 	with many OOL ports descriptors (consisting of empty ports) such that both the ipc_kmsg
 * 	struct for the message and the OOL port arrays fall into the target kalloc zone. We will
 * 	continue sending messages to the port until either we've created the required number of
 * 	allocations or we've filled up the port's message queue.
 *
 * 	To free the allocations, call mach_port_destroy() on the holding port. Note that this will
 * 	also free the holding port if there are no other references.
 *
 * Parameters:
 * 	holding_port			The port on which to enqueue the Mach messages.
 * 	min_kalloc_size			The minimum sized allocation that is handled by this zone.
 * 	kalloc_zone			The kalloc zone in which to spray allocations.
 * 	kalloc_count			The desired number of allocations to make.
 *
 * Returns:
 * 	Returns the number of kalloc allocations actually made, which may be less than the number
 * 	requested if the port fills up or if an error is encountered.
 */
size_t kalloc_spray_port(mach_port_t holding_port, size_t min_kalloc_size, size_t kalloc_zone,
		size_t kalloc_count);

/*
 * kalloc_spray_size
 *
 * Description:
 * 	Spray the specified kalloc_zone with spray_size bytes of allocations by sending Mach
 * 	messages containing OOL ports to the given holding ports.
 *
 * 	See kalloc_spray_port().
 *
 * 	To free the allocations, call destroy_ports() on the holding ports. Note that
 * 	destroy_ports() will also free the holding ports themselves if there are no other
 * 	references.
 *
 * Parameters:
 * 	holding_ports			The array of holding ports.
 * 	port_count		inout	On entry, the number of holding ports available. On exit,
 * 					the number of holding ports used.
 * 	min_kalloc_size			The minimum sized allocation that is handled by this zone.
 * 	kalloc_zone			The kalloc zone in which to spray allocations.
 * 	spray_size			The number of bytes to try and spray to the target zone.
 *
 * Returns:
 * 	Returns the number of bytes actually sprayed to the kalloc zone. This could be less than
 * 	the requested size if an error is encountered or more than the requested size if the spray
 * 	size was not an even multiple of the zone size.
 */
size_t kalloc_spray_size(mach_port_t *holding_ports, size_t *port_count,
		size_t min_kalloc_size, size_t kalloc_zone, size_t spray_size);

/*
 * ool_ports_spray_size_with_gc
 *
 * Description:
 * 	Spray spray_size bytes of kernel memory with the specified out-of-line ports.
 *
 * Parameters:
 * 	holding_ports			The array of holding ports.
 * 	holding_port_count	inout	On entry, the number of holding ports available. On exit,
 * 					the number of holding ports used.
 * 	message_size			The size of each message to send. This parameter should be
 * 					chosen carefully, as allocations will be taken out of the
 * 					corresponding kalloc zone.
 * 	ool_ports			The OOL Mach ports to spray.
 * 	ool_port_count			The number of OOL Mach ports.
 * 	ool_disposition			The disposition to send the OOL ports.
 * 	spray_size			The number of bytes of OOL ports to try and spray.
 *
 * Returns:
 * 	Returns the number of bytes of OOL ports actually sprayed.
 */
size_t ool_ports_spray_size_with_gc(mach_port_t *holding_ports, size_t *holding_port_count,
		size_t message_size, const mach_port_t *ool_ports, size_t ool_port_count,
		mach_msg_type_name_t ool_disposition, size_t spray_size);

/*
 * create_ports
 *
 * Description:
 * 	Create an array of Mach ports. The Mach ports are receive rights only. Once the array is no
 * 	longer needed, deallocate it with free().
 */
mach_port_t *create_ports(size_t count);

/*
 * destroy_ports
 *
 * Description:
 * 	Destroys the specified Mach ports and sets them to MACH_PORT_DEAD.
 */
void destroy_ports(mach_port_t *ports, size_t count);

/*
 * deallocate_ports
 *
 * Description:
 * 	Deallocates the specified Mach ports and sets them to MACH_PORT_DEAD.
 */
void deallocate_ports(mach_port_t *ports, size_t count);

/*
 * port_increase_queue_limit
 *
 * Description:
 * 	Increase the queue limit on the specified Mach port to MACH_PORT_QLIMIT_MAX.
 */
void port_increase_queue_limit(mach_port_t port);

/*
 * port_insert_send_right
 *
 * Description:
 * 	Insert a send right on the specified port, which must name a receive right.
 */
void port_insert_send_right(mach_port_t port);

/*
 * port_drain_messages
 *
 * Description:
 * 	Drain all the messages currently queued on the specified port. The messages are passed to
 * 	the message_handler block, which is responsible for processing the messages and freeing any
 * 	associated resources (e.g. with mach_msg_destroy()).
 */
void port_drain_messages(mach_port_t port, void (^message_handler)(mach_msg_header_t *));

/*
 * port_discard_messages
 *
 * Description:
 * 	Discard all the messages currently queued on the specified port. The messages are received
 * 	and passed directly to mach_msg_destroy().
 */
void port_discard_messages(mach_port_t port);

/*
 * ool_ports_spray_receive
 *
 * Description:
 * 	Receive all the messages queued on the holding ports and pass the OOL ports descriptors to
 * 	the specified handler block. The messages are destroyed after they are processed.
 */
void ool_ports_spray_receive(mach_port_t *holding_ports, size_t holding_port_count,
		void (^ool_ports_handler)(mach_port_t *, size_t));

/*
 * increase_file_limit
 *
 * Description:
 * 	Increase our process's limit on the number of open files.
 */
void increase_file_limit(void);

/*
 * pipe_close
 *
 * Description:
 * 	Close the file descriptors of a pipe.
 */
void pipe_close(int pipefds[2]);

/*
 * create_pipes
 *
 * Description:
 * 	Create a spray of pipes. On entry, pipe_count specifies the requested number of pipes, and
 * 	on return it contains the number of pipes actually created.
 *
 * 	The pipes are returned as an array of file descriptors.
 */
int *create_pipes(size_t *pipe_count);

/*
 * close_pipes
 *
 * Description:
 * 	Close the pipes in an array.
 */
void close_pipes(int *pipefds, size_t pipe_count);

/*
 * pipe_spray
 *
 * Description:
 * 	Spray data to the pipes. Note that XNU limits the collective size of all pipe buffers to
 * 	16 MB, so that's the maximum we'll be able to spray.
 *
 * 	Note that the last byte of the sprayed data won't be written to memory!
 *
 * Parameters:
 * 	pipefds				The pipe file descriptors.
 * 	pipe_count			The number of pipe fd pairs.
 * 	pipe_buffer			The data to spray.
 * 	pipe_buffer_size		The size of the data to spray.
 * 	update				A callback to modify the data on each iteration.
 *
 * Returns:
 * 	Returns the number of pipes actually filled.
 */
size_t pipe_spray(const int *pipefds, size_t pipe_count,
		void *pipe_buffer, size_t pipe_buffer_size,
		void (^update)(uint32_t pipe_index, void *data, size_t size));

#endif
