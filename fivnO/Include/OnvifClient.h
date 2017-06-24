#ifndef ONVIF_CLIENT___H
#define ONVIF_CLIENT___H

#include <stddef.h>
#include <arpa/inet.h>

struct UserInfo
{
	char name[64];
	char pswd[32];
};

enum CapaId		// 能力集编号
{
	eCapaAnalytic,
	eCapaDevice,
	eCapaEvnet,
	eCapaImg,
	eCapaMedia,
	eCapaPTZ,
	eCapaMax
};

struct CapaURI	// 能力集地址
{
	char uri[eCapaMax][128];
};

struct Profile
{
	char name[64];
	char token[64];
};

struct IPCInfo // IPC基本信息(用完后要调用IPCInfoFree释放指针参数)
{
	char srvAddr[128];
	char EPAddr[48];
	unsigned int metadataVer;
	struct UserInfo usrInf;	// 用于鉴权，需要人工配置
	struct CapaURI *pCapURI;
	size_t prfCount;		// Profile个数
	struct Profile *pPrf;
};

// 发现IPC设备，返回发现的个数，count是个数上限，pInAddr不为NULL时表示指定网卡的ip
size_t OnvifDiscovery(struct IPCInfo ipcInfo[], size_t count, struct in_addr *pInAddr);
int OnvifGetCapabilities(struct IPCInfo *pIPCInf);	// 获取IPC设备的能力集
int OnvifGetProfiles(struct IPCInfo *pIPCInf);
int OnvifGetStreamURI(struct IPCInfo *pIPCInf, size_t prfId, char (*pUri)[128]);
void IPCInfoFree(struct IPCInfo *pIPCInf);	// 释放pIPCInf的指针参数

#endif

