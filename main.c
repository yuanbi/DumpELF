
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
	uint32_t pid = 2663;
	char buf[0x200] = {0};
	uint32_t result = 0;
	uint64_t base = 0;

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

	if((result = mem_build(mem_info, &base, "/mnt/d/dump/", "main")))
	{
		printf("Build elf failed\n");
	}

	printf("Build elf end: %08x\n", result);
	dumpnot_release(mem_info);


	FILE* fp = fopen("/mnt/d/dump/main_dump", "rb");
	fseek(fp, SEEK_END, SEEK_SET);
	uint32_t size = ftell(fp);
	rewind(fp);

	uint8_t* mem = (uint8_t*)malloc(size);
	memset(mem, 0, size);
	fread(mem, 1, size, fp);
	
	elf_repair(base, mem, size);

	free(mem);
	fclose(fp);

	return 0;
}
