#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "Domain.h"

_Bool IsIP(const char *pStr)
{
	int a = 0, b = 0, c = 0, d = 0;
	if (sscanf(pStr, "%d.%d.%d.%d ", &a, &b, &c, &d) == 4)
		return (a>=0 && a<=255 && b>=0 && b<=255 && c>=0 && c<=255 && d>=0 && d<=255);

	return false;
}

int DomainToIP(char (*pIP)[16], const char *pDomain)
{
	struct hostent *pEnt = gethostbyname(pDomain);
	if (pEnt == NULL)
	{
		herror("gethostbyname");
		return -1;
	}

	strncpy((char *)pIP, inet_ntoa(*((struct in_addr *)pEnt->h_addr)), sizeof(pIP) - 1);
	return 0;
}

