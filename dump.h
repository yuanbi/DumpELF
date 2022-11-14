#ifndef H_DUMP
#define H_DUMP
#include <stdint.h>

#define MODE_PROCESS 0x01
#define MODE_WHOLE_MEM 0x02

struct list_entry
{
	void* next;
	void* prev;
};

struct mem_info
{
	struct mem_info* next;
	uint64_t addr_start;
	uint64_t addr_end;
	uint8_t mode;
	uint32_t offset;
	uint32_t size;
	uint8_t private;
	uint16_t map_major;
	uint16_t map_minor;
	uint32_t inode_id;
	uint8_t process_mem;
	char path[0x200];
};

uint32_t read_mem(struct mem_info* mem_info, uint64_t addr, void* mem, uint32_t size);

uint32_t dumpnot_init(char* path, struct mem_info** mem_info);
void dumpnot_release(struct mem_info* meminfo);
uint32_t dump_memory(uint32_t pid, char* dir_path, uint32_t mode);

#endif

