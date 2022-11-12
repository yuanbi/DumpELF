
#include "log.h"
#include "dump.h"
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
	uint32_t pid = 1309;
	char buf[0x200] = {0};
	uint32_t result = 0;

	/*result = dump_process(pid, "/mnt/d/dump", MODE_WHOLE_MEM);*/
	/*if(result)*/
	/*{*/
		/*printf("Error occur: %08x\n", result);*/
		/*printf("Errno: %08x\n", errno);*/
	/*}*/

	struct mem_info* mem_info = 0;
	result = dumpnot_init("/data/data/com.termux/files/home/GitHub/DumpELF/debug_dump", &mem_info);
	show_mems_info(mem_info);

	read_mem(mem_info, 0x7f6197ab9002,  buf, 3);
	dumpnot_release(mem_info);

	buf[3] = '\0';
	printf("readed string: %s", buf);


	return 0;
}
