
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "errors.h"
#include "elf_build.h"
#include "log.h"

typedef uint32_t (*fn_read_mem)(struct mem_info* mem_info, uint64_t addr, void* mem, uint32_t size);
fn_read_mem g_read_mem = 0;

uint32_t elf_build(struct mem_info* mem_info, char* dir_path, char* module_name)
{
	char path[0x200] = {0};
	uint32_t result = 0;
	uint64_t base = 0;
	uint32_t file_size = 0;
	Elf64_Ehdr hdr;
	Elf64_Phdr* phdr = 0;
	Elf64_Dyn dyn;
	void* p = NULL;

	do
	{

		if(strlen(dir_path) > 0x170)
		{
			result = ERROR_TOO_LONG_PATH;
			break;
		}

		strcat(path, dir_path);
		if(path[strlen(path) - 1] != '/')
			path[strlen(path)] = '/';

		strcat(path, module_name);
		strcat(path, "_dump");

		FILE* fp = fopen(path, "wb");
		if(fp <= 0)
		{
			result = ERROR_CREATE_FILE;
			break;
		}

		for (; mem_info; mem_info = mem_info->next)
			if (strstr((char*)mem_info->path, module_name))
				break;

		if (mem_info == NULL)
		{
			result = ERROR_NOT_FOUND_MODULE;
			break;
		}

		base = mem_info->addr_start;
		if((result = read_mem(mem_info, base, (void*)&hdr, sizeof(Elf64_Ehdr))))
			break;

		phdr = malloc(hdr.e_phnum * hdr.e_phentsize);
		if((result = read_mem(mem_info, base + hdr.e_phoff, (void*)phdr, hdr.e_phnum * hdr.e_phentsize)))
			break;

		for(int i = 0; i < hdr.e_phnum; i++)
		{
			if(phdr[i].p_type != PT_LOAD && phdr[i].p_type != PT_DYNAMIC)
				continue;

			if(phdr[i].p_offset > file_size)
			{
				LOG_INFO("Append bytes: %08x\n", phdr[i].p_offset - file_size);
				p = malloc(phdr[i].p_offset - file_size);
				memset(p, 0, phdr[i].p_offset - file_size);
				fwrite(p, 1, phdr[i].p_offset - file_size, fp);
				file_size = file_size + phdr[i].p_offset - file_size;

				free(p);
			}

			LOG_INFO("Read addr: %lx, size: %08x\n", base + phdr[i].p_paddr, phdr[i].p_filesz);
			p = malloc(phdr[i].p_filesz);
			if((result = read_mem(mem_info, base + phdr[i].p_vaddr, (void*)p, phdr[i].p_filesz)))
				break;

			fwrite(p, 1, phdr[i].p_filesz, fp);
			file_size = file_size + phdr[i].p_filesz;

			free(p);
			p = NULL;
		}

		fclose(fp);
		if(p) free(p);

	} while (0);

	if(phdr) free(phdr);

	return result;
}
