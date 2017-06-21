// Short Messaging Service短信服务，解析短信
// 在线测试http://www.multisilicon.com/_a/blog/a22201774~/pdu.htm
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

struct PDUAddr	// PDU地址
{
	uint8_t len;
	uint8_t type;
	char addr[21];	// OA地址长度上限*2+1
};

struct DeliverPDU	// 接受方PDU
{
	struct PDUAddr sca;	// 服务中心地址
	uint8_t pduType;
	struct PDUAddr oa;	// 源(发送方)地址
	uint8_t pid;
	uint8_t dcs;
	uint8_t scts[7];
	uint8_t udl;
	uint8_t ud[141];	// 长度上限+1
};

struct InfoElement		// 信息元素
{
	uint8_t id;
	uint8_t len;
	uint16_t refNum;	// 顶多2字节
	uint8_t total;
	uint8_t current;
};

struct UsrDataHead		// 长短信的用户数据头
{
	uint8_t len;
	struct InfoElement ie;
};

struct LongMsg			// 长短信分包
{
	char oaAddr[21];	// oa地址
	struct UsrDataHead udh;
	size_t msgLen;
	uint8_t msg[161];	// 长度上限+1
};

enum
{
	eSMS7Bit = 0,
	eSMS8Bit = 4,
	eSMSUCS2 = 8
};

static const uint8_t tSmsAnsiMap[128] =
{
	0x40, 0xa3, 0x24, 0xa5, 0xe8, 0xe9, 0xf9, 0xec, 0xf2, 0xc7, 0x0a, 0xd8, 0xf8, 0x0d, 0xc5, 0xe5,
	0x20, 0x5f, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xc6, 0xe6, 0xdf, 0xc9,
	0x20, 0x21, 0x22, 0x23, 0xa4, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0xa1, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0xc4, 0xd6, 0xd1, 0xdc, 0xa7,
	0xbf, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0xe4, 0xf6, 0xf1, 0xfc, 0xe0,
};

static size_t Decode7bit(const uint8_t *pSrc, uint8_t *pDst, size_t nSrcLen)
{
	int nSrc = 0, nDst = 0;
	int nByte = 0;				// 当前正在处理的组内字节的序号，范围是0-6
	uint8_t nLeft = 0;			// 上一字节残余数据
	uint8_t srcInPduLen = (nSrcLen % 8 == 0) ? (nSrcLen * 7 / 8) : (nSrcLen * 7 / 8 + 1);	// PDU码实际长度

	// 将源字节串每7个分为一组，解压缩成8个字节
	while (nSrc < srcInPduLen)
	{
		// 将源字节右边部分与残余数据相加，去掉最高位，得到一个目标字节
		*pDst = ((*pSrc << nByte) | nLeft) & 0x7f;
		// 将该字节组剩下的左边部分，作为残余数据保存
		nLeft = *pSrc >> (7 - nByte);
		++pDst;
		++nDst;
		++nByte;

		// 到了一组最后一个字节，且尚未解码完
		if (nByte == 7 && nDst != nSrcLen)
		{
			*pDst = nLeft;
			++pDst;
			++nDst;
			nByte = 0;
			nLeft = 0;
		}

		++pSrc;
		++nSrc;
	}
	*pDst = 0;
	return nDst;
}

static size_t Decode8bit(const uint8_t *pSrc, uint8_t *pDst, size_t nSrcLength)
{
	memcpy(pDst, pSrc, nSrcLength);
	return nSrcLength;
}

static int String2Bytes(const char *pSrc, uint8_t *pDst, size_t nSrcLength)	// 两字符转化成1字节
{
	for (size_t i = 0; i + 1 < nSrcLength; i += 2)
	{
		// 输出高4位
		if (*pSrc>='0' && *pSrc<='9')
			*pDst = (*pSrc - '0') << 4;
		else if (*pSrc>='A' && *pSrc<='F')
			*pDst = (*pSrc - 'A' + 10) << 4;
		else
		{
			printf("%s:%s:%d *pSrc = %hhd\n", __FILE__, __func__, __LINE__, *pSrc);
			return -1;
		}

		++pSrc;

		// 输出低4位
		if (*pSrc >= '0' && *pSrc <= '9')
			*pDst |= *pSrc - '0';
		else if (*pSrc>='A' && *pSrc<='F')
			*pDst |= *pSrc - 'A' + 10;
		else
		{
			printf("%s:%s:%d *pSrc = %hhd\n", __FILE__, __func__, __LINE__, *pSrc);
			return -1;
		}

		++pSrc;
		++pDst;
	}

	return (nSrcLength / 2);	// 返回目标数据长度
}

static void BitDown(const uint8_t *pSrc, uint8_t *pDst, size_t nSrcLength, size_t movBit)	// 位下移
{
	if (movBit < 1 || movBit > 7)
		return;
	if (nSrcLength < 2)
	{
		*pDst = *pSrc >> movBit;
		return;
	}

	uint8_t low = 0, high = 0;
	for (size_t i = 0; i < nSrcLength; ++i)
	{
		low = *pSrc >> movBit;
		high = *(pSrc + 1) << (8 - movBit);	// 高位用后面一字节的低位
		*pDst = high + low;
		++pSrc;
		++pDst;
	}

	*pDst = *pSrc >> movBit;	// 最后一字节
}

void GsmMapConvert(uint8_t *pSrc, size_t nSrcLength)
{
	uint8_t id = 0;
	for (size_t i = 0; i < nSrcLength; ++i)
	{
		id = pSrc[i];
		pSrc[i] = tSmsAnsiMap[id];
	}
}

static void SerializeNumbers(const char *pSrc, char *pDst, size_t nSrcLength)
{
	char ch = 0;
	// 两两颠倒
	for (size_t i = 0; i + 1 < nSrcLength; i += 2)
	{
		ch = *pSrc++;		// 保存先出现的字符
		*pDst++ = *pSrc++;	// 复制后出现的字符
		*pDst++ = ch;		// 复制先出现的字符
	}

	*pDst = '\0';	// 输出字符串加个结束符
}

static int UserDataHead(const char *pStr, struct UsrDataHead *pUDH)		// 长短信有数据头，返回头字节数
{
	memset(pUDH, 0, sizeof (*pUDH));

	if (strncmp(pStr, "050003", 6) == 0)
	{
		pStr += 6;
		if (strlen(pStr) >= 6)
		{
			pUDH->len = 5;
			pUDH->ie.id = 0;
			pUDH->ie.len = 3;
			if (String2Bytes(pStr, (uint8_t *)&pUDH->ie.refNum, 2) < 0
				|| String2Bytes(pStr + 1 * 2, &pUDH->ie.total, 2) < 0 || String2Bytes(pStr + 2 * 2, &pUDH->ie.current, 2) < 0)
			{
				printf("%s:%s:%d\n", __FILE__, __func__, __LINE__);
				return -1;
			}
			return (pUDH->len + 1);
		}
		else
		{
			printf("%s:%s:%d\n", __FILE__, __func__, __LINE__);
			return -1;
		}
	}
	else if (strncmp(pStr, "060804", 6) == 0)
	{
		pStr += 6;
		if (strlen(pStr) >= 8)
		{
			pUDH->len = 6;
			pUDH->ie.id = 8;
			pUDH->ie.len = 4;
			if (String2Bytes(pStr, (uint8_t *)&pUDH->ie.refNum, 4) < 0
				|| String2Bytes(pStr + 2 * 2, &pUDH->ie.total, 2) < 0 || String2Bytes(pStr + 3 * 2, &pUDH->ie.current, 2) < 0)
			{
				printf("%s:%s:%d\n", __FILE__, __func__, __LINE__);
				return -1;
			}
			return (pUDH->len + 1);
		}
		else
		{
			printf("%s:%s:%d\n", __FILE__, __func__, __LINE__);
			return -1;
		}
	}
	else
	{
		printf("%s:%s:%d\n", __FILE__, __func__, __LINE__);
		return -1;
	}

	return -1;

}

static int StringBeforeComma(char *pStr, char **pCommaEnd, char *pDest, size_t dstSize)	// 找逗号，逗号前的字符串提取
{
	if (pStr == NULL)
	{
		*pCommaEnd = NULL;
		return 0;
	}

	*pCommaEnd = strchr(pStr, ',');
	if (*pCommaEnd != NULL)
		**pCommaEnd = '\0';
	size_t len = strlen(pStr);
	if (len < dstSize)
	{
		strcpy(pDest, pStr);
		return 0;
	}
	else
		return -1;
}

static void JoinLongMesg(const char *pOAAddr, const struct UsrDataHead *pUDH, const uint8_t *pData, size_t dataLen)
{
	if (pUDH->ie.total < 2)
	{
		printf("%s:%s:%d pData = %s, dataLen = %zu\n", __FILE__, __func__, __LINE__, (const char *)pData, dataLen);
		return;
	}

	static struct LongMsg LMesg[32] = {{{0}}};		// 缓存32条长短信分包
	size_t arraySize = sizeof(LMesg) / sizeof(LMesg[0]);
	if (pUDH->ie.total > arraySize)
		return;		// 处理不了
	
	int partnerId[32] = {0};					// 同组的短信在LMesg中的下标
	size_t partnerCount = 0;
	size_t i = 0;
	_Bool conflict = false;
	for (i = 0; i < arraySize; ++i)
	{
		if (LMesg[i].udh.len==pUDH->len && LMesg[i].udh.ie.refNum==pUDH->ie.refNum && strcmp(LMesg[i].oaAddr, pOAAddr)==0)	// 同组
		{
			if (LMesg[i].udh.ie.total != pUDH->ie.total)
				conflict = true;
			else if (LMesg[i].udh.ie.current == pUDH->ie.current)
			{
				if (LMesg[i].msgLen == dataLen && memcmp(LMesg[i].msg, pData, dataLen) == 0)	// 重复的短信
					return;
				else
					conflict = true;
			}

			if (conflict)	// 有冲突则删除所有同组短信缓存
			{
					for (i = 0; i < arraySize; ++i)
					{
						if (LMesg[i].udh.len==pUDH->len && LMesg[i].udh.ie.refNum==pUDH->ie.refNum && strcmp(LMesg[i].oaAddr, pOAAddr)==0)
							LMesg[i].udh.len = 1;	// 失效，变相删除它
					}
					return;
			}

			partnerId[partnerCount] = i;
			++partnerCount;
		}
	}

	if (partnerCount + 1 >= pUDH->ie.total)			// 同组的短信都在，+1表示还有本条短信
	{
		// 按短信编号排序
		int id1 = 0, id2 = 0, swap = 0;
		size_t j = 0;
		for (i = 0; i < partnerCount - 1; ++i)
		{
			for (j = 0; j < partnerCount - 1 - i; ++j)
			{
				id1 = partnerId[j];
				id2 = partnerId[j + 1];
				if (LMesg[id1].udh.ie.current > LMesg[id2].udh.ie.current)
				{
					swap = partnerId[j];
					partnerId[j] = partnerId[j + 1];
					partnerId[j + 1] = swap;
				}
			}
		}

		// 组装成长短信
		uint8_t totalBuf[32 * 161] = "";	// 保证放得下所有短信
		size_t totalLen = 0;
		_Bool selfPend = true;				// 本条短信还未处理
		for (i = 0; i < partnerCount; ++i)
		{
			id1 = partnerId[i];
			if (LMesg[id1].udh.ie.current > pUDH->ie.current && selfPend)	// 处理本条短信
			{
				memcpy(totalBuf + totalLen, pData, dataLen);
				totalLen += dataLen;
				selfPend = false;
			}
			memcpy(totalBuf + totalLen, LMesg[id1].msg, LMesg[id1].msgLen);
			totalLen += LMesg[id1].msgLen;
			LMesg[id1].udh.len = 0;		// 用完了，失效，变相删除它
		}

		if (selfPend)	// 本条短信是最后一条
		{
			memcpy(totalBuf + totalLen, pData, dataLen);
			totalLen += dataLen;
		}

		printf("%s:%s:%d totalBuf = %s, totalLen = %zu\n", __FILE__, __func__, __LINE__, (const char *)totalBuf, totalLen);
	}
	else
	{
		// 找缓存数组中空闲的
		for (i = 0; i < arraySize; ++i)
		{
			if (LMesg[i].udh.len == 0)	// 无效的，可以使用
				break;
		}

		// 无空闲的，删除所有非本组的短信
		if (i >= arraySize)
		{
			for (i = 0; i < arraySize; ++i)
			{
				if (LMesg[i].udh.len!=pUDH->len || LMesg[i].udh.ie.refNum!=pUDH->ie.refNum || strcmp(LMesg[i].oaAddr, pOAAddr)!=0)
					LMesg[i].udh.len = 0;	// 失效，变相删除它
			}
		}

		// 放到缓存数组
		for (i = 0; i < arraySize; ++i)
		{
			if (LMesg[i].udh.len == 0)		// 无效的，可以使用
			{
				strcpy(LMesg[i].oaAddr, pOAAddr);
				LMesg[i].udh = *pUDH;
				LMesg[i].msgLen = dataLen;
				memcpy(LMesg[i].msg, pData, dataLen);
				break;
			}
		}
	}
}

static void DecodeUserData(const char *pStr, struct DeliverPDU *pPDU)
{
	if (pPDU->udl < 1)
		return;

	struct UsrDataHead udh = {0};
	int headLen = 0;
	if (pPDU->pduType & 0x40)
	{
		headLen = UserDataHead(pStr, &udh);
		if (headLen < 0)
			return;
		pStr += headLen * 2;
	}

	size_t len = strlen(pStr);
	uint8_t msg[161] = "";		// 短信内容
	size_t msgLen = 0;			// 解析后的数据长度
	if (len > 1 && len % 2 == 0)
	{
		size_t dataLen = 0;			// 去头后的数据长度
		if (pPDU->dcs & eSMSUCS2)
		{
			dataLen = pPDU->udl - headLen;
			if (dataLen * 2 != len)
				return;
			if (String2Bytes(pStr, pPDU->ud, len) < 0)
				return;
			msgLen = strlen((const char *)msg);
		}
		else if (pPDU->dcs & eSMS8Bit)
		{
			dataLen = pPDU->udl - headLen;
			if (dataLen * 2 != len)
				return;
			if (String2Bytes(pStr, pPDU->ud, len) < 0)
				return;
			msgLen = Decode8bit(pPDU->ud, msg, dataLen);
		}
		else	// 7Bit的
		{
			size_t headByte = headLen * 8 / 7;		// 头占用的字节
			size_t headAlign = (7 - (headLen * 8) % 7) % 7;	// 头字节7位对齐还剩下的位
			size_t headByte2 = headByte + ((headAlign > 0) ? 1 : 0);	// 头和对齐位占用的字节
			if (pPDU->udl < headByte2)
				return;
			// 8个7bit为一整组，否则有零的
			size_t decDataLen = ((pPDU->udl % 8 == 0) ? (pPDU->udl * 7 / 8) : (pPDU->udl * 7 / 8 + 1)) * 2;
			if (decDataLen != len + headLen * 2)
				return;
			if (String2Bytes(pStr, pPDU->ud, len) < 0)
				return;

			size_t alignByte = 0;
			if (headAlign > 0)
			{
				if (headAlign == 1)
				{
					msg[0] = (pPDU->ud[0] >> 1);		// 第一bit被对齐占用掉，后面7bit就是对齐前的值
					alignByte = 1;
				}
				else
				{
					BitDown(pPDU->ud, msg, len / 2, headAlign);
					memcpy(pPDU->ud, msg, len / 2);	// 复制回来
				}
			}

			if (pPDU->udl - headByte - alignByte > 0)
			{
				if (Decode7bit(pPDU->ud + alignByte, msg + alignByte,  pPDU->udl - headByte - alignByte) == pPDU->udl - headByte - alignByte)
				{
					GsmMapConvert(msg, pPDU->udl - headByte);
					msgLen = pPDU->udl - headByte;
				}
			}
			else if (alignByte > 0)
			{
				GsmMapConvert(msg, alignByte);
				msgLen = alignByte;
			}
		}
	}

	if (pPDU->pduType & 0x40)
		JoinLongMesg(pPDU->oa.addr, &udh, msg, msgLen);
	else if (msgLen > 0)
		printf("%s:%s:%d msg = %s, msgLen = %zu\n", __FILE__, __func__, __LINE__, (const char *)msg, msgLen);
}
	
void DecodePDU(const char *pStr)
{	
	size_t len = strlen(pStr);
	if (len < 14 * 2)	// 收到的PDU最少14字节，每字节用两字符表示
	{
		printf("%s:%d, len = %zd\n", __func__, __LINE__, len);
		return;
	}

	struct DeliverPDU pdu = {{0}};
	if (String2Bytes(pStr, &pdu.sca.len, 2) < 0)
		return;

	printf("%s:%d, pdu.sca.len = %u\n", __func__, __LINE__, pdu.sca.len);
	if (pdu.sca.len < 12)
	{
		const char *pStrEnd = pStr + len;
		pStr += (pdu.sca.len + 1) * 2;
		printf("%s:%d, pStr = %s\n", __func__, __LINE__, pStr);
		if (String2Bytes(pStr, &pdu.pduType, 2) < 0)
			return;

		printf("%s:%d, pdu.pduType = %u\n", __func__, __LINE__, pdu.pduType);
		pStr += 2 * 2;
		if (pStr + 2 < pStrEnd)
		{
			printf("%s:%d, pStr = %s\n", __func__, __LINE__, pStr);
			if (String2Bytes(pStr, &pdu.oa.len, 2) < 0)
				return;

			pStr += 1 * 2;
			uint8_t halfByte = pdu.oa.len % 2;		// 半字节的情况
			if (pdu.oa.len > 0 && pdu.oa.len <= 10 * 2 && (pStr + pdu.oa.len + halfByte) < pStrEnd)
			{
				SerializeNumbers(pStr, pdu.oa.addr, pdu.oa.len + halfByte);
				*(pdu.oa.addr + pdu.oa.len) = '\0';		// halfByte可能导致多出的裁剪掉
				printf("pdu.oa.addr = %s\n", pdu.oa.addr);

				pStr += pdu.oa.len + halfByte;
				if (pStr + 10 * 2 <= pStrEnd)
				{
					pStr += 1 * 2;
					if (String2Bytes(pStr, &pdu.dcs, 2) < 0)
						return;

					if ((pdu.dcs&0x20) || (pdu.dcs&0x0C) == 0x0C)
						return;

					pStr += 8 * 2;
					if (String2Bytes(pStr, &pdu.udl, 2) < 0)
						return;

					pStr += 1 * 2;
					DecodeUserData(pStr, &pdu);
				}
			}
			else
				printf("%s:%d, pdu.oa.len = %u\n", __func__, __LINE__, pdu.oa.len);
		}
	}
}

int main(void)
{
	return 0;
}

