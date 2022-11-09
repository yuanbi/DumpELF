#include "dump.h"
#include "errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

// 
// @brief None
// @param name 输出值
// @param name_len name 长度
// @return 成功返回 0
// 
uint32_t get_pid_name(uint32_t pid, char* name, uint32_t name_len)
{
	
	
	return 0;
}

uint64_t get_pid_base(uint32_t pid)
{
	uint64_t result = 0;
	uint8_t buf[0x200] = {0};
	FILE* fp = NULL;

	sprintf((char*)buf, "/proc/%d/maps", pid);


	do{

		fp = fopen((char*)buf, "rb");
		if(fp <= 0)
		{
			result = ERROR_GET_BASE;
			break;
		}

		
	}while(0);









	return result;
}

