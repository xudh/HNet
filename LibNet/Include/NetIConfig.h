#ifndef NETWORK_INTERFACE_CONFIG___H
#define NETWORK_INTERFACE_CONFIG___H

#include <stdint.h>

int GetMAC(uint8_t (*pMAC)[6], const char *pNI);
int GetIpVal(uint32_t *pIP, const char *pNI);
int GetIpAddr(char (*pIP)[16], const char *pNI);
int GetIpMask(char (*pIP)[16], char (*pMask)[16], const char *pNI);
int GetMACAndIp(uint8_t (*pMAC)[6], char (*pIP)[16], char (*pMask)[16], const char *pNI);
int SetMAC(const uint8_t (*pMAC)[6], const char *pNI);
int SetIpVal(uint32_t ip, const char *pNI);
int SetIpAddr(const char *pIP, const char *pNI);
int SetIpMask(const char *pIP, const char *pMask, const char *pNI);
int SetMACAndIp(const uint8_t (*pMAC)[6], const char *pIP, const char *pMask, const char *pNI);
#endif

