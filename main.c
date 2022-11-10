
#include "log.h"
#include "dump.h"

int main()
{
	char buf[0x200] = {0};
	get_pid_name(19739, buf, 0x200);

	struct mem_info* mems = 0;
	if(get_pid_mem(19739, &mems))
	{
		LOG_INFO("Mems read failed!\n");
		return -1;
	}


	return 0;
}
