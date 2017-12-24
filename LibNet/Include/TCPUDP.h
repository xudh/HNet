#ifndef TCP_UDP___H
#define TCP_UDP___H

#include <stdint.h>
#include <stdbool.h>

// 连接到服务器，并进行缺省的设置，返回Socket句柄
int ConnectToServer(const char *pSrvIp, uint16_t port, _Bool tcpOrUdp);

#endif

