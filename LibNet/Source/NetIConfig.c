#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "NetIConfig.h"

int GetMAC(uint8_t (*pMAC)[6], const char *pNIC)
{
	memset(pMAC, 0, sizeof(*pMAC));

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFHWADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	memcpy(pMAC, ifr.ifr_hwaddr.sa_data, sizeof(*pMAC));
	close(sockFD);
	return 0;
}

int GetIp(char (*pIP)[16], const char *pNIC)
{
	memset(pIP, 0, sizeof(*pIP));

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pIP, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr), sizeof(*pIP) - 1);
	close(sockFD);
	return 0;
}

int GetIpMask(char (*pIP)[16], char (*pMask)[16], const char *pNIC)
{
	memset(pIP, 0, sizeof(*pIP));

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pIP, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr), sizeof(*pIP) - 1);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFNETMASK, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pMask, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr), sizeof(*pMask) - 1);

	close(sockFD);
	return 0;
}

int GetMACAndIp(uint8_t (*pMAC)[6], char (*pIP)[16], char (*pMask)[16], const char *pNIC)
{
	memset(pMAC, 0, sizeof(*pMAC));
	memset(pIP, 0, sizeof(*pIP));

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFHWADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	memcpy(pMAC, ifr.ifr_hwaddr.sa_data, sizeof(*pMAC));

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pIP, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr), sizeof(*pIP) - 1);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFNETMASK, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pMask, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr), sizeof(*pMask) - 1);

	close(sockFD);
	return 0;
}

int SetMAC(const uint8_t (*pMAC)[6], const char *pNIC)
{
	return 0;
}

int SetIp(char (*pIP)[16], const char *pNIC)
{
	return 0;
}

int SetIpMask(const char (*pIP)[16], const char (*pMask)[16], const char *pNIC)
{
	return 0;
}

int SetMACAndIp(const uint8_t (*pMAC)[6], const char (*pIP)[16], const char (*pMask)[16], const char *pNIC)
{
	return 0;
}

