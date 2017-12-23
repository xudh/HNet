#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
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

