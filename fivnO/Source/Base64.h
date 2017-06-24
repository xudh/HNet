#ifndef BASE64___H
#define BASE64___H

#include <stddef.h>

int Base64Encode(char *pDst, size_t dstSize, const void *pSrc, size_t srcLen);
int Base64Decode(void *pDst, size_t dstSize, const char *pSrc);

#endif

