#ifndef Route___H
#define Route___H

#include <stddef.h>

// 获取Route，返回获取到的个数，count表示支持的最大数量
size_t GetRoute(char route[][64], size_t count);

int SetRoute(const char *pRoute[], size_t count);

int AddRoute(const char *pRoute);

int RemoveRoute(const char *pRoute);

#endif

