#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "OnvifClient.h"

int main(void)
{
	struct IPCInfo ipc[8] = {{{0}}};
	size_t ipcCnt = OnvifDiscovery(ipc, sizeof(ipc) / sizeof(ipc[0]), NULL);
	printf("%s:%d ipcCnt = %zu\n", __func__, __LINE__, ipcCnt);
	for (size_t i = 0; i < ipcCnt; ++i)
	{
		printf("ipc[%zu].service Address = %s, EP Address = %s, metadataVersion = %u\n", i, ipc[i].srvAddr, ipc[i].EPAddr, ipc[i].metadataVer);
		strcpy(ipc[i].usrInf.name, "admin");	// 给默认的账号
		strcpy(ipc[i].usrInf.pswd, "123456");
		if (OnvifGetCapabilities(&ipc[i]) == 0)
		{
			for (enum CapaId id = eCapaAnalytic; id < eCapaMax; ++id)
			{
				printf("pCapURI->uri[%d] = %s\n", id, ipc[i].pCapURI->uri[id]);
			}

			if (OnvifGetProfiles(&ipc[i]) == 0)
			{
				printf("prfCount = %zu\n", ipc[i].prfCount);
				for (size_t j = 0; j < ipc[i].prfCount; ++j)
				{
					printf("Profiles: name = %s, token = %s\n", ipc[i].pPrf[j].name, ipc[i].pPrf[j].token);
					char streamUri[128] = "";
					if (OnvifGetStreamURI(&ipc[i], j, &streamUri) == 0)
						printf("streamUri = %s\n", streamUri);
				}
			}
		}

		IPCInfoFree(&ipc[i]);
		printf("\n");
	}
	return 0;
}

