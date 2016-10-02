//
//  librop.c
//  librop
//
//  Created by jndok on 15/01/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#include "librop.h"

/* globals */

uint64_t gKERNEL_SLIDE = 0x0;

#pragma mark ANALYSIS

macho_map_t *map_file_with_path(const char *path)
{
    if (!path)
        return NULL;
    
    int32_t fd = open(path, O_RDONLY);
    if (fd<0)
        return NULL;
    
    struct stat st;
    if (fstat(fd, &st) < 0)
        return NULL;
    
    void *base = mmap((void*)0x0, (uint32_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0x0);
    if (!base)
        return NULL;
    
    if (((struct mach_header_64*)base)->magic != MH_MAGIC_64) {
        munmap(base, st.st_size);
        return NULL;
    }
    
    macho_map_t *map = (macho_map_t*)malloc(sizeof(macho_map_t));
    map->base = base;
    map->size = (uint32_t)st.st_size;
   
    return map;
}

#pragma mark EXPLOITATION

__attribute__((always_inline)) int64_t obtain_kernel_slide(void)
{
    uint64_t slide=0;
    uint64_t slide_sz=sizeof(uint64_t);
    if(syscall(SYS_kas_info, 0, &slide, &slide_sz) != 0)
        return KSLIDE_UNKNOWN;
    
    return slide;
}

int64_t find_symbol_address(macho_map_t *map, const char *symbol_name)
{
    if (!map)
        return 0x0;
    
    void *symbol_table=NULL, *string_table=NULL;
    uint32_t nsyms=0;
    
    struct mach_header_64 *header = (struct mach_header_64*)map->base;
    if (header->magic != MH_MAGIC_64)
        return 0x0;
    
    struct symtab_command *symtab_cmd = (struct symtab_command *)macho_parsing_find_load_command(map, LC_SYMTAB);
    if (!symtab_cmd)
        return 0x0;
    
    symbol_table=((void*)header + symtab_cmd->symoff);
    string_table=((void*)header + symtab_cmd->stroff);
    nsyms=symtab_cmd->nsyms;

    struct nlist_64 *entry=(struct nlist_64*)symbol_table;
    for (uint32_t i=0; i<nsyms; ++i) {
        if (strcmp(string_table+(entry->n_un.n_strx), symbol_name) == 0) {
            return entry->n_value;
        }
        entry=((void*)entry + sizeof(struct nlist_64));
    }
    
    return 0x0;
}

__attribute__((always_inline)) void *find_gadget_address(macho_map_t *map, gadget_t *gadget, gadget_size_t gadget_size)
{
    if (!map)
        return NULL;
    
    return memmem(map->base, map->size, gadget, gadget_size);
}

#pragma mark PARSING

__attribute__((always_inline)) struct mach_header_64 *macho_parsing_find_mach_header(macho_map_t *map)
{
    if (!map || !map->size) {
        return NULL;
    }
    
    struct mach_header_64 *header=(struct mach_header_64*)map->base;
    if (header->magic!=MH_MAGIC_64) {
        return NULL;
    }
    
    return header;
}

__attribute__((always_inline)) struct load_command *macho_parsing_find_load_command(macho_map_t *map, uint32_t cmd)
{
    struct mach_header_64 *header=macho_parsing_find_mach_header(map);
    if (!header) {
        return NULL;
    }
    
    struct load_command *lcmd=((void*)header+sizeof(struct mach_header_64));
    for (uint32_t i=0; i<header->ncmds; ++i) {
        if (lcmd->cmd==cmd) {
            return lcmd;
        }
        
        lcmd = ((void*)lcmd + lcmd->cmdsize);
    }
    
    return NULL;
}

__attribute__((always_inline)) struct segment_command_64 *macho_parsing_find_segment_command(macho_map_t *map, const char *seg_name)
{
    struct mach_header_64 *header=macho_parsing_find_mach_header(map);
    if (!header) {
        return NULL;
    }
    
    struct segment_command_64 *seg_cmd=NULL;
    
    struct load_command *lcmd=((void*)header+sizeof(struct mach_header_64));
    for (uint32_t i=0; i<header->ncmds; ++i) {
        if (lcmd->cmd==LC_SEGMENT_64) {
            seg_cmd=(struct segment_command_64*)lcmd;
            if (strcmp(seg_cmd->segname, seg_name) == 0) {
                return seg_cmd;
            }
        } else { // LC_SEGMENT_64s are located @ the beginning of load commands, so we can assume we have checked them all here.
            return NULL;
        }
        
        lcmd = ((void*)lcmd + lcmd->cmdsize);
    }
    
    return NULL;
}

__attribute__((always_inline)) struct section_64 *macho_parsing_find_section_command(macho_map_t *map, const char *seg_name, const char *sect_name)
{
    struct mach_header_64 *header=macho_parsing_find_mach_header(map);
    if (!header) {
        return NULL;
    }
    
    struct segment_command_64 *seg_cmd = macho_parsing_find_segment_command(map, seg_name);
    if (!seg_cmd) {
        return NULL;
    }
    
    struct section_64 *sect_cmd=(struct section_64*)((void*)seg_cmd+sizeof(struct segment_command_64));
    for (uint32_t i=0; i<seg_cmd->nsects; ++i) {
        if (strcmp(sect_cmd->sectname, sect_name) == 0) {
            return sect_cmd;
        }
        
        sect_cmd = ((void*)sect_cmd + sizeof(struct section_64));
    }
    
    return NULL;
}