#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "TCPUDP.h"

int ConnectToServer(const char *pSrvIp, uint16_t port, _Bool tcpOrUdp)
{
	if (port == 0 || strcmp(pSrvIp, "0.0.0.0") == 0 || strcmp(pSrvIp, "127.0.0.1") == 0)
	{
		printf("%s:%d pSrvIp = %s, port = %"PRIu16" won't connect\n", __func__, __LINE__, pSrvIp, port);
		return -1;
	}

	int sockFD = -1;
	if (tcpOrUdp)
		sockFD = socket(AF_INET, SOCK_STREAM, 0);
	else
		sockFD = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%d errno = %d, means: %s.\n", __func__, __LINE__, errno, strerror(errno));
		return -1;
	}
	struct timeval tv = {0};
	if (tcpOrUdp)
	{
		int flag = 1;
		setsockopt(sockFD, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));	// 不使用Nagle算法(要等到一定量才外发)
		tv.tv_sec = 20;
	}
	else
		tv.tv_sec = 10;
	setsockopt(sockFD, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));		// 发送超时
	setsockopt(sockFD, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));		// 接收超时
	struct sockaddr_in sockDest;
	memset(&sockDest, 0, sizeof sockDest);
	sockDest.sin_family = AF_INET;
	sockDest.sin_addr.s_addr = inet_addr(pSrvIp);
	sockDest.sin_port = htons(port);
	printf("%s:%d connect pSrvIp = %s, port = %"PRIu16"\n", __func__, __LINE__, pSrvIp, port);
	if (connect(sockFD, (struct sockaddr *)&sockDest, sizeof(sockDest)) == -1)	// UDP不会真连接，这样使用避免sendto/recvfrom里面每次传地址
	{
		printf("%s:%d errno = %d, means: %s.\n", __func__, __LINE__, errno, strerror(errno));
		close(sockFD);
		sockFD = -1;
	}

	return sockFD;
}

