
#ifndef H_ELF_BUILD
#define H_ELF_BUILD

#include <stdint.h>
#include "dump.h"
uint32_t mem_build(struct mem_info* mem_info, uint64_t* base, char* dir_path, char* module_name);
uint32_t elf_repair(uint64_t base, uint8_t* mem, uint32_t size);






#endif
