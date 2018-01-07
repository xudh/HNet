#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "NetInterface.h"

size_t GetNetInterface(char ni[][8], size_t count)
{
	DIR *pDir = opendir("/sys/class/net");
	if (pDir == NULL)
	{
		printf("%s:%d errno = %d, means: %s.\n", __func__, __LINE__, errno, strerror(errno));
		return 0;
	}

	size_t ret = 0;
	struct dirent *pEnt = NULL;
	while (ret < count && (pEnt = readdir(pDir)) != NULL)
	{
		if (pEnt->d_name[0] != '.' && strlen(pEnt->d_name) < (size_t)8)
		{
			strcpy(ni[ret], pEnt->d_name);
			++ret;
		}
	}

	closedir(pDir);
	return ret;
}

_Bool IsNicLink(const char *pNI)
{
	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		return false;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFFLAGS, &ifr) != 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return false;
	}

	_Bool bRet = (ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING);
	close(sockFD);
	return bRet;
}

