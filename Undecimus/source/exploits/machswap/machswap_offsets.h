#ifndef OFFSETS_H
#define OFFSETS_H

typedef struct {
    struct {
        /* strings kernel | grep 'Darwin' */ 
        const char *version;

        /* basically will always be: 0xfffffff007004000 */
        uint64_t kernel_image_base;
    } constant;

    struct {
        /* nm kernel | grep '_copyin' */
        uint64_t copyin;

        /* nm kernel | grep '_copyout' */
        uint64_t copyout;

        /* nm kernel | grep '_kalloc_external' */
        uint64_t kalloc_external;

        /* nm kernel | grep '_csblob_get_cdhash' */
        uint64_t csblob_get_cdhash;
    } funcs;

    struct {
        /* 
            str 'zone_init: kmem_suballoc failed', 
            first addrp ins above will load address of zone_map,
            image: https://i.imgur.com/ygMcZYs.png
        */
        uint64_t zonemap;

        /* nm kernel | grep '_kernproc' */
        uint64_t kernproc;

        /*
            _host_priv_self symbol
            'adrp x0, #realhost [...]'
            image: https://i.imgur.com/17CkpY8.png
        */
        uint64_t realhost;
        
        /*
            joker -m kernel | grep 'clock_sleep_trap'
            look for part of there code where it loads system_clock: 'adr x8, system_clock'
            compares it against another register (ie. X23)
            if they are not equal, it will load #5 into some wN register, and branch to the exit/func prologue
            image: https://i.imgur.com/tidJdZz.png
        */
        uint64_t system_clock;
    } data;

    struct {
        /* 
            nm kernel | grep '_proc_pid'
            'ldr w0, [x0, #offset]
        */
        uint32_t proc_pid;
        
        /*
            nm kernel | grep '_proc_task'
            'ldr x0, [x0, #offset]
        */
        uint32_t proc_task;
        
        /*
            nm kernel | grep '_proc_ucred'
            'ldr x0, [x0, #offset]
        */
        uint32_t proc_ucred;
        
        /*
            nm kernel | grep '_get_task_map'
            'ldr x0, [x0, #offset]
        */
        uint32_t task_vm_map;
        
        /*
            nm kernel | grep '_get_bsdtask_info'
            'ld rx0, [x0, #offset]
        */
        uint32_t task_bsd_info;

        /*
            joker -m kernel | grep 'task_self_trap'
            go into 'bl' call
            near the start of the func, just after _lck_mtx_lock,
            it will load two values from a reg and compare them
            one is later loaded into x0, this is the one you *dont'* want 
            you need the offset of the one which *isn't* later loaded into x0
            ldr xN, [xN, #offset]
            image: https://i.imgur.com/RlauIez.png
        */
        uint32_t task_itk_self;

        /*
            joker -m kernel | grep mach_ports_lookup
            about 1/3rd the way into the func it will load a value from a reg,
            call a function, and store the return value, 3 times in a row
            it will load from 3 offsets such as 0x2F0, 0x2F8, and 0x300 (notice they are all contiguous)
            the lowest of the three offsets is the one you want 
            image: https://i.imgur.com/0M1mUSM.png
            (note the repeating pattern of 'ldr x0, [x20, #offset]', 'bl identical_func', 'str x0, [x21 #off]')
        */
        uint32_t task_itk_registered;

        /*
            joker -m kernel | grep 'task_info'
            about halfway down the func, just before a _task_deallocate call, it will
            load reg x0-x3, and then call a func 
            within that func there is a jumptable, you need to find case 17 (TASK_DYLD_INFO)
            in here it will do two loads and stores, the first load is your _image_info_addr offset,
            the second is your _image_info_size offset (however this should be the _info_addr offset +0x8)
            image: https://i.imgur.com/WpG6Ub6.png
        */
        uint32_t task_all_image_info_addr;
        uint32_t task_all_image_info_size;
    } struct_offsets;

    struct {
        /* 
            if IOSurface::create_surface fails, this offset being wrong is why 
            you can find the offset manually, but it's usually either 
            0x6c8 for 11.0.x, 0xbc8 for 11.1.x-11.4.x, or 0xdd0 for 12.x
        */
        uint32_t create_outsize;

        /* 
            iometa -Csov IOUserClient kernel | grep 'getExternalTrapForIndex'
            take the index (usually 0x5b8) and divide by 0x8
        */
        uint32_t get_external_trap_for_index;
    } iosurface;
} machswap_offsets_t;

machswap_offsets_t *get_machswap_offsets(void);

#endif
