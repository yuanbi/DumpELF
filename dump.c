#include "dump.h"

#include <memory.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "errors.h"
#include "log.h"

pid_t g_attached_pid = 0;

void append_node(void* head, void* node)
{
	if (head == NULL)
	{
		head = node;
	}
	else
	{
		while (((struct list_entry*)head)->next)
			head = ((struct list_entry*)head)->next;
		((struct list_entry*)head)->next = node;
	}
}

void* next_node(void* node)
{
	return ((struct list_entry*)node)->next;
}

void free_nodes(void* head)
{
	void* prev = head;
	void* next = ((struct list_entry*)prev)->next;

	do
	{
		free(prev);
		prev = next;
		next = ((struct list_entry*)prev)->next;
	} while (next != NULL && next != head);
}

//
// @brief None
// @param name 输出值
// @param name_len name 长度
// @return 成功返回 0
//
uint32_t get_pid_name(uint32_t pid, char* name, uint32_t name_len)
{
	char buf[0x200] = {0};

	sprintf(buf, "/proc/%d/status", pid);

	FILE* fp = fopen(buf, "r");
	if (fp <= 0)
	{
		// TODO: ERROR_CODE
		return 1;
	}

	fgets(buf, 0x200 - 1, fp);
	fclose(fp);

	sscanf(buf, "%*s %s", name);

	if (strlen(name) <= 0)
	{
		// TODO: ERROR_CODE
		return 1;
	}

	return 0;
}

uint32_t save_mapsinfo(uint32_t pid, char* path)
{
	uint32_t result = 0;
	char buf[0x200] = {0};
	sprintf((char*)buf, "/proc/%d/maps", pid);

	do
	{
		FILE* fp = fopen((char*)buf, "rb");
		if (fp <= 0)
		{
			result = ERROR_GET_BASE;
			break;
		}

		while (fgets(buf, 0x200, fp))
		{
		}
	} while (0);

	return 0;
}

uint32_t parse_map_line(char* line, struct mem_info* mem)
{
	char prot_r = 0x00, prot_w = 0x00, prot_x = 0x00, private = 0x00;

	sscanf(line, "%lx-%lx %c%c%c%c %x %hu:%hu %d %s", &mem->addr_start, &mem->addr_end,
		   &prot_r, &prot_w, &prot_x, &private, &mem->size, &mem->map_major, &mem->map_minor, &mem->inode_id, mem->path);

	mem->mode = prot_r == 'r' ? mem->mode | PROT_READ : mem->mode;
	mem->mode = prot_w == 'w' ? mem->mode | PROT_WRITE : mem->mode;
	mem->mode = prot_x == 'x' ? mem->mode | PROT_EXEC : mem->mode;

	mem->private = private == 'p' ? 1 : 0;

	return 0;
}

uint32_t get_pid_mem(uint32_t pid, struct mem_info** base)
{
	uint32_t result = 0;
	char buf[0x200] = {0};
	FILE* fp		= NULL;

	struct list_entry head = {0, 0};

	sprintf((char*)buf, "/proc/%d/maps", pid);

	do
	{
		fp = fopen((char*)buf, "rb");
		if (fp <= 0)
		{
			result = ERROR_GET_BASE;
			break;
		}

		while (fgets(buf, 0x200, fp))
		{
			struct mem_info* mem = (struct mem_info*)malloc(sizeof(struct mem_info));
			memset(mem, 0, sizeof(struct mem_info));

			if ((result = parse_map_line(buf, mem)))
				break;

			append_node(&head, mem);
		}

		if (result)
			free_nodes(&head);
		else
			*base = head.next;

	} while (0);

	return result;
}

uint32_t do_wait(uint32_t pid)
{
	int sig	   = 0;
	int status = 0;

	do
	{
		waitpid(pid, &status, __WALL);
		if (!WIFSTOPPED(sig) || sig != SIGSTOP)
		{
			syscall(SYS_tkill, pid, sig);  // 如果不是 SIGSTOP 发送给 tracee
			continue;
		}
		break;
	} while (1);

	return 0;
}

uint32_t attach_pid(uint32_t pid)
{
	int status = 0;

	if (ptrace(PTRACE_SEIZE, pid) <= 0)
		return -1;

	/*if (waitpid(pid, &status, __WALL) <= 0)*/
	/*{*/
	/*ptrace(PTRACE_DETACH, pid);*/
	/*return -1;*/
	/*}*/

	/*int sig = WSTOPSIG(status);*/
	/*while (!WIFSTOPPED(sig) || sig != SIGSTOP)*/
	/*{*/
	/*syscall(SYS_tkill, pid, sig); // 如果不是 SIGSTOP 发送给 tracee*/
	/*waitpid(pid, &status, __WALL);*/
	/*}*/

	/*if(ptrace(PTRACE_CONT, pid) <= 0)*/
	/*{*/
	/*ptrace(PTRACE_DETACH, pid);*/
	/*return -1;*/
	/*}*/

	g_attached_pid = pid;
	return 0;
}

uint32_t deatch_pid(uint32_t pid)
{
	if (!g_attached_pid)
		return -1;

	ptrace(PTRACE_DETACH, g_attached_pid);

	return 0;
}

uint32_t readmem_by_ptrace(uint64_t addr, void* mem, uint32_t size)
{
	long m = 0;
	if (!g_attached_pid)
		return -1;

	if (size % 2)
		return ERROR_READ_MEM_SIZE;

	for (int i = 0; i < size; i += 2)
	{
		m = ptrace(PTRACE_PEEKDATA, g_attached_pid);
		if ((m & 0xFFFF) == 0xFFFF)
			return ERROR_READ_MEM;

		*(uint16_t*)mem = (uint16_t)m & 0xFFFF;
		mem				= (void*)(((uint64_t)mem) + 2);
	}

	return 0;
}

uint32_t readmem_by_procmem(uint64_t addr, void* mem, uint32_t size)
{
	return 0;
}

uint32_t readmem_by_syscall(uint64_t addr, void* mem, uint32_t size)
{
	return 0;
}

uint32_t read_mem(uint64_t addr, void* mem, uint32_t size)
{
	return 0;
}

uint32_t dump_process(uint32_t pid, char* dir_path, uint32_t mode)
{
	int result				 = 0;
	struct mem_info* mems	 = NULL;
	char name_process[0x200] = {0};
	char name_file[0x200]	 = {0};

	if (mode == MODE_WHOLE_MEM)
	{
		char path[0x512] = {0};
		strcat(path, dir_path);
		if (path[strlen(path) - 1] != '/')
			path[strlen(path) - 1] = '/';

		strcat(path, "mem_info.txt");
	}

	do
	{
		if ((result = get_pid_mem(pid, &mems)))
			break;

		if (mems == NULL)
		{
			// TODO: ERROR_COD
			result = 0x00003;
			break;
		}

		if ((result = get_pid_name(pid, name_process, 0x200)))
			break;

		if ((result = attach_pid(pid)))
			break;

	} while (0);

	return 0;
}
