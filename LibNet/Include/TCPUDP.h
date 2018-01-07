#ifndef TCP_UDP___H
#define TCP_UDP___H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// 连接到服务器，并进行缺省的设置，返回Socket句柄
int ConnectToServer(const char *pSrvIp, uint16_t port, _Bool tcpOrUdp);

// 提供网络服务，返回Socket句柄，pIp表示指定ip，可以为NULL
int NetServer(const char *pIp, uint16_t port, _Bool tcpOrUdp, size_t maxLink);

int SetMuticastOpt(int sockFD, const char *pIp);		// 设置组播选项
#endif

