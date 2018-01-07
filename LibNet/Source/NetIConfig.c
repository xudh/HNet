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

int GetMAC(uint8_t (*pMAC)[6], const char *pNI)
{
	memset(pMAC, 0, sizeof(*pMAC));

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFHWADDR, &ifr) != 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	memcpy(pMAC, ifr.ifr_hwaddr.sa_data, sizeof(*pMAC));
	close(sockFD);
	return 0;
}

static int GetIp(struct in_addr *pIn, const char *pNI)
{
	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	close(sockFD);
	*pIn = ((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr;
	return 0;
}

int GetIpVal(uint32_t *pIp, const char *pNI)
{
	struct in_addr in = {0};
	if (GetIp(&in, pNI) != 0)
		return -1;
	else
	{
		*pIp = in.s_addr;
		return 0;
	}
}

int GetIpAddr(char (*pIP)[16], const char *pNI)
{
	memset(pIP, 0, sizeof(*pIP));
	struct in_addr in = {0};
	if (GetIp(&in, pNI) != 0)
		return -1;
	else
	{
		strncpy((char *)pIP, inet_ntoa(in), sizeof(*pIP) - 1);
		return 0;
	}
}

int GetIpMask(char (*pIP)[16], char (*pMask)[16], const char *pNI)
{
	memset(pIP, 0, sizeof(*pIP));

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pIP, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr), sizeof(*pIP) - 1);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFNETMASK, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pMask, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr), sizeof(*pMask) - 1);

	close(sockFD);
	return 0;
}

int GetMACAndIp(uint8_t (*pMAC)[6], char (*pIP)[16], char (*pMask)[16], const char *pNI)
{
	memset(pMAC, 0, sizeof(*pMAC));
	memset(pIP, 0, sizeof(*pIP));

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFHWADDR, &ifr) != 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	memcpy(pMAC, ifr.ifr_hwaddr.sa_data, sizeof(*pMAC));

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pIP, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr), sizeof(*pIP) - 1);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFNETMASK, &ifr) != 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pMask, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr), sizeof(*pMask) - 1);

	close(sockFD);
	return 0;
}

int SetMAC(const uint8_t (*pMAC)[6], const char *pNI)
{
	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFHWADDR, &ifr) != 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	memcpy(ifr.ifr_hwaddr.sa_data, pMAC, sizeof(*pMAC));
	if (ioctl(sockFD, SIOCSIFHWADDR, &ifr) != 0)
	{
		printf("%s:%d pNI = %s, errno = %d, means: %s\n", __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	close(sockFD);
	return 0;
}

static int SetIp(const struct in_addr *pIn, const char *pNI)
{
	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr = *pIn;
	if (ioctl(sockFD, SIOCSIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	close(sockFD);
	return 0;
}

int SetIpVal(uint32_t ip, const char *pNI)
{
	struct in_addr in = {0};
	in.s_addr = ip;
	return SetIp(&in, pNI);
}

int SetIpAddr(const char *pIP, const char *pNI)
{
	struct in_addr in = {0};
	if (inet_aton(pIP, &in) != 0)
		return SetIp(&in, pNI);
	else
	{
		printf("%s:%d pIP = %s error\n", __func__, __LINE__, pIP);
		return -1;
	}
}

int SetIpMask(const char *pIP, const char *pMask, const char *pNI)
{
	struct in_addr in = {0};
	if (inet_aton(pIP, &in) == 0)
	{
		printf("%s:%d pIP = %s error\n", __func__, __LINE__, pIP);
		return -1;
	}
	struct in_addr inMask = {0};
	if (inet_aton(pMask, &inMask) == 0)
	{
		printf("%s:%d pMask = %s error\n", __func__, __LINE__, pMask);
		return -1;
	}

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr.s_addr = in.s_addr;
	if (ioctl(sockFD, SIOCSIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	if (ioctl(sockFD, SIOCGIFNETMASK, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr.s_addr = inMask.s_addr;
	if (ioctl(sockFD, SIOCSIFNETMASK, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	close(sockFD);
	return 0;
}

int SetMACAndIp(const uint8_t (*pMAC)[6], const char *pIP, const char *pMask, const char *pNI)
{
	struct in_addr in = {0};
	if (inet_aton(pIP, &in) == 0)
	{
		printf("%s:%d pIP = %s error\n", __func__, __LINE__, pIP);
		return -1;
	}
	struct in_addr inMask = {0};
	if (inet_aton(pMask, &inMask) == 0)
	{
		printf("%s:%d pMask = %s error\n", __func__, __LINE__, pMask);
		return -1;
	}

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNI, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFHWADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	memcpy(ifr.ifr_hwaddr.sa_data, pMAC, sizeof(*pMAC));
	if (ioctl(sockFD, SIOCSIFHWADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr.s_addr = in.s_addr;
	if (ioctl(sockFD, SIOCSIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	if (ioctl(sockFD, SIOCGIFNETMASK, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr.s_addr = inMask.s_addr;
	if (ioctl(sockFD, SIOCSIFNETMASK, &ifr) != 0)
	{
		printf("%s:%s:%d pNI = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNI, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	close(sockFD);
	return 0;
}

