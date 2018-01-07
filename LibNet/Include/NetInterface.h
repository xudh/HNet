#ifndef NETWORK_INTERFACE___H
#define NETWORK_INTERFACE___H

#include <stddef.h>
#include <stdbool.h>

// 获取网卡，返回获取到的个数，count表示支持的最大数量
size_t GetNetInterface(char ni[][8], size_t count);
_Bool IsNicLink(const char *pNI);

#endif

