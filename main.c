
#include "log.h"
#include "dump.h"
#include <errno.h>

int main()
{
	uint32_t pid = 18282;
	char buf[0x200] = {0};
	get_pid_name(pid, buf, 0x200);

	uint32_t result = dump_process(pid, "/mnt/d/dump", MODE_WHOLE_MEM);
	if(result)
	{
		printf("Error occur: %08x\n", result);
		printf("Errno: %08x\n", errno);
	}
	return 0;
}
