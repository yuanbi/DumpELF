
#include "log.h"
#include "dump.h"
#include "elf_build.h"
#include <errno.h>
#include <stdio.h>

void show_mems_info(struct mem_info* mem_info)
{
	for(struct mem_info* next = mem_info; next; next = next->next)
	{
		printf("Addr start:%lx, Addr end: %lx path: %s\n", next->addr_start, next->addr_end, next->path);
	}

	return;
}

int main()
{
	uint32_t pid = 1948;
	char buf[0x200] = {0};
	uint32_t result = 0;

	/*result = dump_process(pid, "/mnt/d/dump", MODE_WHOLE_MEM);*/
	/*if(result)*/
	/*{*/
		/*printf("Error occur: %08x\n", result);*/
		/*printf("Errno: %08x\n", errno);*/
	/*}*/

	struct mem_info* mem_info = 0;
	/*result = dumpnot_init("/data/data/com.termux/files/home/GitHub/DumpELF/debug_dump", &mem_info);*/
	result = dump_memory(pid,"/mnt/d/dump/", MODE_WHOLE_MEM);
	/*show_mems_info(mem_info);*/

	if((result = dumpnot_init("/mnt/d/dump/", &mem_info)))
	{
		printf("Init failed: %08x!\n", result);
	}

	if((result = elf_build(mem_info, "/mnt/d/dump/", "main")))
	{
		printf("Build elf failed\n");
	}

	printf("Build elf end: %08x\n", result);
	dumpnot_release(mem_info);

	return 0;
}
