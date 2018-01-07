#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include "Route.h"

size_t GetRoute(char route[][64], size_t count)
{
	FILE *pF = fopen("/proc/net/route", "r");
	if (pF == NULL)
	{
		printf("%s:%d errno = %d, means: %s.\n", __func__, __LINE__, errno, strerror(errno));
	}

	char buf[512] = "";
	char ni[8] = "";
	uint32_t dst = 0, gw = 0, flg = 0, mask = 0;
	unsigned int refCnt = 0, use = 0, metric = 0, mtu = 0, win = 0, irtt = 0;
	char *pRet = fgets(buf, sizeof(buf), pF);	// 第一行是标题
	while (pRet != NULL)
	{
		pRet = fgets(buf, sizeof(buf), pF);
		if (pRet != NULL)
		{
			if (sscanf(pRet, "%7s%x%x%x%u%u%u%x%u%u%u", ni, &dst, &gw, &flg, &refCnt, &use, &metric, &mask, &mtu, &win, &irtt) == 7)
			{
			}
			else
			{
				printf("%s:%d pRet = %s.\n", __func__, __LINE__, pRet);
				break;
			}
		}
	}
	return 0;
}

int SetRoute(const char *pRoute[], size_t count)
{
	return 0;
}

int AddRoute(const char *pRoute)
{
	return 0;
}

int RemoveRoute(const char *pRoute)
{
	return 0;
}

