#ifndef NETWORK_INTERFACE_CONFIG___H
#define NETWORK_INTERFACE_CONFIG___H

#include <stdint.h>

int GetMAC(uint8_t (*pMAC)[6], const char *pNIC);
int GetIp(char (*pIP)[16], const char *pNIC);
int GetIpMask(char (*pIP)[16], char (*pMask)[16], const char *pNIC);
int GetMACAndIp(uint8_t (*pMAC)[6], char (*pIP)[16], char (*pMask)[16], const char *pNIC);
int SetMAC(const uint8_t (*pMAC)[6], const char *pNIC);
int SetIp(char (*pIP)[16], const char *pNIC);
int SetIpMask(const char (*pIP)[16], const char (*pMask)[16], const char *pNIC);
int SetMACAndIp(const uint8_t (*pMAC)[6], const char (*pIP)[16], const char (*pMask)[16], const char *pNIC);
#endif

