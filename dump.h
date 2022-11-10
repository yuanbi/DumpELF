#include <stdint.h>

#define MODE_PROCESS	0x01
#define MODE_WHOLE_MEM  0x02

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
	uint32_t size;
	uint8_t private;
	uint16_t map_major;
	uint16_t map_minor;
	uint32_t inode_id;
	char path[0x200];
};


void free_nodes(void* head);
uint32_t get_pid_name(uint32_t pid, char* name, uint32_t name_len);
uint32_t get_pid_mem(uint32_t pid, struct mem_info** base);
uint32_t dump_process(uint32_t pid, char* dir_path, uint32_t mode);
