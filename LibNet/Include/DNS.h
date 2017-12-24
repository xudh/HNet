#ifndef DNS___H
#define DNS___H

#include <stddef.h>

// 获取DNS，返回获取到的个数，count表示支持的最大数量
size_t GetDNS(char dns[][64], size_t count);

int SetDNS(const char *pDNS[], size_t count);

int AddDNS(const char *pDNS);

int RemoveDNS(const char *pDNS);

#endif

