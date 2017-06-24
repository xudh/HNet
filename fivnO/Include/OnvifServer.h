#ifndef ONVIF_SERVER___H
#define ONVIF_SERVER___H

#include <stdint.h>

void OnvifServerInit(uint8_t chnCount);	// 传入通道数，支持多通道IPC(也可以将DVR当IPC用)
int OnvifServerAddNic(const char *pNIC);	// 增加网卡，并在此网卡上提供Onvif服务
int OnvifServerRmNic(const char *pNIC);	// 移除在该网卡上提供Onvif服务
void OnvifServerRmAllNic(void);			// 移出所有网卡上提供Onvif服务
void OnvifServerRun(void);
void OnvifServerPause(void);

#endif

