#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "NetInterface.h"
#include "NetIConfig.h"

int main(void)
{
	char ni[4][8] = {{0}};
	size_t niCnt = GetNetInterface(ni, sizeof(ni) / sizeof(ni[0]));
	for (size_t i = 0; i < niCnt; ++i)
	{
		if (strcmp(ni[i], "lo") == 0)
			continue;
		printf("%s:%d ni[i] = %s\n", __func__, __LINE__, ni[i]);
		uint8_t mac[6] = {0};
		char ip[16] = {0}, mask[16] = {0};
		if (GetMACAndIp(&mac, &ip, &mask, ni[i]) == 0)
		{
			printf("%s:%d mac = %02X:%02X:%02X:%02X:%02X:%02X, ip = %s, mask = %s\n",
					__func__, __LINE__, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip, mask);
		}
	}

	return 0;
}

