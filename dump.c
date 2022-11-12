#include "dump.h"
#include "log.h"

#include <errno.h>
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

struct dump_info
{
	pid_t g_attached_pid;
	char mem_path[0x200];
};

struct dump_info g_dump_info = {0, {0}};

void append_node(void* head, void* node)
{
	if (head == 0)
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
	} while (next != 0 && next != head);
}

void* path2name(char* path)
{
	if (strlen(path) <= 0)
		return 0;

	char* name = strrchr(path, '/');

	if (name)
		name = name + 1;
	else
		name = path;

	return name;
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
	if (fp <= 0) return ERROR_READ_FILE;
	fgets(buf, 0x200 - 1, fp);
	fclose(fp);

	sscanf(buf, "%*s %s", name);
	if (strlen(name) <= 0) return ERROR_PROCESS_NAME;

	return 0;
}

uint32_t save_mapsinfo(uint32_t pid, char* path)
{
	uint32_t result = 0;
	char buf[0x200] = {0};
	sprintf((char*)buf, "/proc/%d/maps", pid);

	do
	{
		FILE* fp_in	 = fopen((char*)buf, "rb");
		FILE* fp_out = fopen((char*)path, "w");
		if (fp_in <= 0 || fp_out <= 0)
		{
			result = ERROR_CREATE_FILE;
			break;
		}

		while (fgets(buf, 0x200, fp_in))
		{
			fputs(buf, fp_out);
		}

		fclose(fp_in);
		fclose(fp_out);
	} while (0);

	return 0;
}

uint32_t parse_map_line(char* line, struct mem_info* mem)
{
	char prot_r = 0x00, prot_w = 0x00, prot_x = 0x00, private = 0x00;

	sscanf(line, "%lx-%lx %c%c%c%c %x %hu:%hu %d %s", &mem->addr_start, &mem->addr_end,
		   &prot_r, &prot_w, &prot_x, &private, &mem->offset, &mem->map_major, &mem->map_minor, &mem->inode_id, mem->path);

	mem->mode = prot_r == 'r' ? mem->mode | PROT_READ : mem->mode;
	mem->mode = prot_w == 'w' ? mem->mode | PROT_WRITE : mem->mode;
	mem->mode = prot_x == 'x' ? mem->mode | PROT_EXEC : mem->mode;

	mem->private = private == 'p' ? 1 : 0;
	mem->size	 = mem->addr_end - mem->addr_start;

	return 0;
}

//
// 单向链表手动释放
// 若 pid = 0, 则根据给定目录的 mem_info.txt 初始化链表
//
uint32_t get_mems_info(uint32_t pid, struct mem_info** base)
{
	uint32_t result = 0;
	char buf[0x200] = {0};
	FILE* fp		= 0;

	struct list_entry head = {0, 0};

	do
	{
		if (pid)
			sprintf((char*)buf, "/proc/%d/maps", pid);
		else
			sprintf((char*)buf, "%smem_info.txt", g_dump_info.mem_path);

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

		if (*base == 0)
			return ERROR_GET_MEMS;

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
		sig = WSTOPSIG(status);
		if (sig != SIGSTOP)
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

	if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0)
		return ERROR_NOT_ATTACH;

	do_wait(pid);

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
	/*return errno;*/
	/*}*/
	/*LOG_INFO("Conted\n");*/

	g_dump_info.g_attached_pid = pid;
	return 0;
}

uint32_t deatch_pid(uint32_t pid)
{
	if (!pid)
		return -1;

	ptrace(PTRACE_DETACH, g_dump_info.g_attached_pid);

	return 0;
}

uint32_t readmem_by_ptrace(uint64_t addr, void* mem, uint32_t size)
{
	uint64_t m = 0;
	if (!g_dump_info.g_attached_pid)
		return -1;

	if (size % 8)
	{
		LOG_INFO("Read mem region not aligned, Addr: %lx\n", addr);
		return -1;
	}

	for (int i = 0; i < size; i += 8)
	{
		m = 0;
		m = ptrace(PTRACE_PEEKDATA, g_dump_info.g_attached_pid, addr + i, 0);
		if (errno != 0)
		{
			LOG_INFO("Read mem failed, will fill 0, size 8, Addr: %lu\n", addr + i);
			m = 0;
		}

		*(uint64_t*)((uint64_t)mem + i) = (uint64_t)m;
	}

	return 0;
}

uint32_t readmem_by_procmem(uint64_t addr, void* mem, uint32_t size)
{
	int result = -1;
	char path[0x100] = {0};
	
	do{
		if(!g_dump_info.g_attached_pid)
			break;

		sprintf(path, "/proc/%d/mem", g_dump_info.g_attached_pid);
		int fd = open(path, O_RDONLY);
		if(fd <= 0)
			break;

		lseek64(fd, addr, SEEK_SET);
		read(fd, mem, size);
		close(fd);

		result = 0;

	}while(0);

	return result;
}

uint32_t readmem_by_syscall(uint64_t addr, void* mem, uint32_t size)
{
	return 0;
}

uint32_t readmem_by_file(struct mem_info* mem_info, uint64_t addr, void* mem, uint32_t size)
{
	char path[0x230] = {0};
	char* name_path = 0;
	FILE* fp = 0;
	uint32_t offset = 0;
	uint32_t file_size = 0;

	for (; mem_info; mem_info = next_node(mem_info))
		if (mem_info->addr_start <= addr && mem_info->addr_end > addr)
			break;

	if (!mem_info) return -1;
	offset = addr - mem_info->addr_start;

	name_path = path2name(mem_info->path);
	if(!name_path) return -1;

	sprintf(path, "%s%lx-%lx__%s",g_dump_info.mem_path, mem_info->addr_start, mem_info->addr_end, name_path);
	/*LOG_INFO("Read mem by file: %s\n", path);*/
	fp = fopen(path, "rb");
	if(fp <= 0) return -1;

	fseek(fp, SEEK_SET, SEEK_END);
	file_size = ftell(fp);
	rewind(fp);

	offset = addr - mem_info->addr_start;
	if(size > file_size || (offset + size) > file_size)
	{
		fclose(fp);
		return -1;
	}

	fseek(fp, offset, SEEK_SET);
	fread(mem, 1, size, fp);
	fclose(fp);
	return 0;
}

uint32_t read_mem(struct mem_info* mem_info, uint64_t addr, void* mem, uint32_t size)
{
	uint32_t result = 0;

	do
	{
		if (!(result = readmem_by_ptrace(addr, mem, size)))
			break;

		if (!(result = readmem_by_procmem(addr, mem, size)))
		break;

		/*if (!(result = readmem_by_syscall(addr, mem, size)))*/
		/*break;*/

		if (!(result = readmem_by_file(mem_info, addr, mem, size)))
			break;

	} while (0);

	if (result) ERROR_READ_MEM;

	return result;
}


uint32_t write_mem_file(char* path, struct mem_info* meminfo)
{
	uint32_t result = 0;
	void* mem		= 0;
	FILE* fp		= 0;

	do
	{
		mem = malloc(0x1000);
		fp	= fopen(path, "wb");
		if (fp <= 0)
		{
			result = ERROR_CREATE_FILE;
			break;
		}

		if (!(meminfo->mode & PROT_READ))
		{
			LOG_INFO("%lx-%lx not has read privilege\n", meminfo->addr_start, meminfo->addr_end);
			return 0;
		}

		for (int i = 0; i < meminfo->size; i += 0x1000)
		{
			if ((result =
					read_mem(meminfo, meminfo->addr_start + i, mem,
							 0x1000)))
				break;
			fwrite(mem, 1, 0x1000, fp);
		}

		if ((meminfo->size & 0xFFF) != 0)
		{
			LOG_INFO("Finded mem not aligned. Start: %lx End: %lx\n", meminfo->addr_start, meminfo->addr_end);
			if ((result =
					read_mem(meminfo, meminfo->addr_start + (meminfo->size & (~0xFFF)), mem,
							 meminfo->size & 0xFFF)))
				break;
			fwrite(mem, 1, meminfo->size & 0xFFF, fp);
		}

	} while (0);

	if (fp > 0) fclose(fp);
	if (mem) free(mem);
	return result;
}

uint32_t dump_process(uint32_t pid, char* dir_path, uint32_t mode)
{
	uint32_t result		  = 0;
	struct mem_info* mems = 0;
	char* name_process	  = 0;
	char path[0x200]	  = {0};
	char file_path[0x230] = {0};
	void* mem			  = 0;
	char* name_file		  = 0;

	if (strlen(dir_path) > 0x200 - 0x50)
		return ERROR_TOO_LONG_PATH;

	do
	{
		mem = malloc(0x1000);
		memset(mem, 0, 0x1000);

		memset(path, 0, 0x200);
		strcat(path, dir_path);

		if (path[strlen(path) - 1] != '/')
			path[strlen(path)] = '/';

		strcat(g_dump_info.mem_path, path);

		if (mode == MODE_WHOLE_MEM)
		{
			strcat(file_path, path);
			strcat(file_path, "mem_info.txt");
			save_mapsinfo(pid, file_path);
		}
		else if (mode == MODE_PROCESS)
		{
			name_process = malloc(0x100);
			memset(name_process, 0, 0x100);

			if ((result = get_pid_name(pid, name_process, 0x200)))
				break;
		}
		else
		{
			result = ERROR_MODE;
			break;
		}

		if ((result = get_mems_info(pid, &mems)))
			break;

		if ((result = attach_pid(pid)))
			break;

		for (struct mem_info* next = mems; next; next = next_node(next))
		{
			if (name_process && !strstr(next->path, name_process))
				continue;

			if ((name_file = path2name(next->path)) == 0)
				name_file = "Unknow";

			sprintf(file_path, "%s%lx-%lx__%s", path,
					next->addr_start, next->addr_end, name_file);

			if ((result = write_mem_file(file_path, next)))
				break;
		}
	} while (0);

	if (g_dump_info.g_attached_pid) deatch_pid(g_dump_info.g_attached_pid);
	if (name_process) free(name_process);
	if (mem) free(mem);
	if (mems) free_nodes(mems);

	return result;
}

//
//与 dumpnot_release 搭配使用
//若需在文件中解析内存数据，则使用此函数初始化
//
uint32_t dumpnot_init(char* path, struct mem_info** mem_info)
{
	uint32_t result = 0;
	
	memset(g_dump_info.mem_path, 0, 0x200);
	strcat(g_dump_info.mem_path, path);
	if(g_dump_info.mem_path[strlen(g_dump_info.mem_path) - 1] != '/')
		g_dump_info.mem_path[strlen(g_dump_info.mem_path)] = '/';

	result = get_mems_info(0, mem_info);
	
	return result;
}


void dumpnot_release(struct mem_info* mem_info)
{
	free_nodes(mem_info);
}
