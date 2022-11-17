
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "errors.h"
#include "elf_build.h"
#include "log.h"

typedef uint32_t (*fn_read_mem)(struct mem_info* mem_info, uint64_t addr, void* mem, uint32_t size);
fn_read_mem g_read_mem = 0;

uint32_t mem_build(struct mem_info* mem_info, uint64_t* base, char* dir_path, char* module_name)
{
	char path[0x200] = {0};
	uint32_t result = 0;
	uint64_t _base = 0;
	uint32_t file_size = 0;
	Elf64_Ehdr hdr;
	Elf64_Phdr* phdr = 0;
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

		*base = _base = mem_info->addr_start;
		if((result = read_mem(mem_info, _base, (void*)&hdr, sizeof(Elf64_Ehdr))))
			break;

		phdr = malloc(hdr.e_phnum * hdr.e_phentsize);
		if((result = read_mem(mem_info, _base + hdr.e_phoff, (void*)phdr, hdr.e_phnum * hdr.e_phentsize)))
			break;

		for(int i = 0; i < hdr.e_phnum; i++)
		{
			if(phdr[i].p_type != PT_LOAD && phdr[i].p_type != PT_DYNAMIC)
				continue;

			if(phdr[i].p_offset > file_size)
			{
				LOG_INFO("Append bytes: %08lx\n", phdr[i].p_offset - file_size);
				p = malloc(phdr[i].p_offset - file_size);
				memset(p, 0, phdr[i].p_offset - file_size);
				fwrite(p, 1, phdr[i].p_offset - file_size, fp);
				file_size = file_size + phdr[i].p_offset - file_size;

				free(p);
			}

			LOG_INFO("Read addr: %lx, size: %08lx\n", _base + phdr[i].p_paddr, phdr[i].p_filesz);
			p = malloc(phdr[i].p_filesz);
			if((result = read_mem(mem_info, _base + phdr[i].p_vaddr, (void*)p, phdr[i].p_filesz)))
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

uint32_t rva_fva(uint8_t *mem, uint64_t va)
{
	uint32_t result = 0;

	Elf64_Ehdr* hdr = 0;
	Elf64_Phdr* phdr = 0;
	
	hdr = (Elf64_Ehdr*)mem;
	phdr = (Elf64_Phdr*)((uint64_t)mem + hdr->e_phoff);

	for (int i = 0; i < hdr->e_phnum; i++) 
	{
		if(phdr[i].p_type != PT_DYNAMIC || phdr[i].p_type != PT_LOAD)
			continue;

		if(phdr[i].p_vaddr <= va && (phdr[i].p_vaddr + phdr[i].p_memsz) > va)
		{
			result = va - phdr[i].p_vaddr;
			LOG_INFO("Va to fva: %lx - %x", va, result);
			break;
		}
	}

	return result;
}

uint32_t elf_repair(uint64_t base, uint8_t* mem, uint32_t size)
{
	uint32_t result = 0;
	uint32_t dymnic_id = 0;
	Elf64_Ehdr* hdr = 0;
	Elf64_Phdr* phdr = 0;
	Elf64_Dyn* dyn = 0;

	uint32_t got_off = 0;
	uint32_t got_size = 0;
	
	hdr = (Elf64_Ehdr*)mem;
	phdr = (Elf64_Phdr*)((uint64_t)mem + hdr->e_phoff);

	hdr->e_shentsize = 0;
	hdr->e_shnum = 0;
	hdr->e_shoff = 0;
	hdr->e_shstrndx = 0;

	do{
		for(dymnic_id = 0; dymnic_id < hdr->e_phnum; dymnic_id++)
			if(phdr[dymnic_id].p_type == PT_DYNAMIC)
				break;

		if(dymnic_id == 0)
		{
			// TODO: ERROR_CODE
			result = -1;
			break;
		}

		dyn = (Elf64_Dyn*)(mem + phdr[dymnic_id].p_offset);
		for(int i = 0; dyn[i].d_tag || dyn[i].d_un.d_ptr; i++)
		{
			switch (dyn[i].d_tag) 
			{
				case DT_DEBUG:
						dyn[i].d_un.d_ptr = 0;
						break;
				case DT_VERSYM:
				case DT_RELA:
				case DT_JMPREL:
				case DT_PLTGOT:
				case DT_SYMTAB:
				case DT_STRTAB:
				case DT_GNU_HASH:
						dyn[i].d_un.d_ptr = (uint64_t)dyn[i].d_un.d_ptr - base;
					break;
				default:
					break;
			}

			if(dyn[i].d_tag == DT_PLTGOT)
				got_off = rva_fva(mem, dyn[i].d_un.d_ptr);
		}

	}while(0);

	return result;
}
