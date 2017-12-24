#ifndef DOMAIN___H
#define DOMAIN___H

#include <stdbool.h>

_Bool IsIP(const char *pStr);

int DomainToIP(char (*pIP)[16], const char *pDomain);

#endif

