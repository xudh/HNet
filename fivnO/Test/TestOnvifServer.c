// 注意要防火墙放行，或者关闭防火墙
#include <unistd.h>
#include "OnvifServer.h"

int main(void)
{
	OnvifServerInit(4);
	OnvifServerAddNic("eth0");
	//OnvifServerAddNic("wlan0");
	while (1)
		sleep(5);
	return 0;
}

