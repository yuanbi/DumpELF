
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include "elf_build.h"
#include "dump.h"
#include "log.h"

typedef uint32_t (*fn_read_mem)(struct mem_info* mem_info, uint64_t addr, void* mem, uint32_t size);
fn_read_mem g_read_mem  = 0;

uint32_t elf_ana(uint64_t base, Elf64_Ehdr* hdr)
{
	
	return 0;
}

uint32_t elf_build(pid_t pid, struct mem_info* mem_info, fn_read_mem func_read_mem)
{
	uint32_t result = 0;

	if(!func_read_mem) result = -1;

	return result;
}
