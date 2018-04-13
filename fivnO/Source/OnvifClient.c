#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "OnvifClient.h"
#include "wsdd.h"
#include "Base64.h"
#include "SHA1.h"

static void WS_UsrNameToken(char *dst, size_t dstSize, const char *pswd, const char *nonce, const char *time)
{
	unsigned char nonceRaw[32] = {0};
	Base64Decode(nonceRaw, sizeof(nonceRaw), nonce);
	char allRaw[128] = {0};
	sprintf(allRaw,"%s%s%s", (char *)nonceRaw, time, pswd);
	uint8_t shaDst[20] = {0};
	SHA1Byte(&shaDst, allRaw);
	Base64Encode(dst, dstSize, (const unsigned char *)shaDst, sizeof(shaDst));
}

static struct soap *InitSoap(struct SOAP_ENV__Header *header, const char *was_To, const char *was_Action, int timeout, const struct UserInfo *pUsrInf)
{
	struct soap *pSoap = soap_new();
	if (pSoap == NULL)
	{
		printf("%s:%d pSoap = NULL\n", __func__, __LINE__);
		return NULL;
	}
	soap_set_namespaces(pSoap, namespaces);
	if (timeout < 1)
		timeout = 10;
	pSoap->recv_timeout = timeout;
	pSoap->send_timeout = timeout;
	pSoap->connect_timeout = timeout;
	memset(header, 0, sizeof(*header));

	static int msgId = 1000;	// 每次搜索时msgId不同，且保证是四位整数
	char msg[48] = "";
	sprintf(msg,"urn:uuid:%ud68a-1dd2-11b2-a105-060504030201", msgId);
	++msgId;
	if (msgId > 9999)
		msgId = 1000;

	header->wsa__MessageID =(char *)soap_malloc(pSoap, 100);
	strcpy(header->wsa__MessageID, msg);

	if (pUsrInf != NULL)
	{
		header->wsse__Security = (struct _wsse__Security *)soap_malloc(pSoap, sizeof(struct _wsse__Security));
		memset(header->wsse__Security, 0, sizeof(struct _wsse__Security));
		header->wsse__Security->UsernameToken = (struct _wsse__UsernameToken *)soap_malloc(pSoap, sizeof(struct _wsse__UsernameToken));
		memset(header->wsse__Security->UsernameToken, 0, sizeof(struct _wsse__UsernameToken));
		header->wsse__Security->UsernameToken->Username = (char *)soap_malloc(pSoap, 64);
		strcpy(header->wsse__Security->UsernameToken->Username, pUsrInf->name);
		header->wsse__Security->UsernameToken->Nonce = (char *)soap_malloc(pSoap, 64);
		strcpy(header->wsse__Security->UsernameToken->Nonce, "U3VwZXIgSERWUg=="); // Base64加过密的Super HDVR
		header->wsse__Security->UsernameToken->wsu__Created = (char *)soap_malloc(pSoap, 64);
		strcpy(header->wsse__Security->UsernameToken->wsu__Created,"2017-06-25T18:50:45Z");
		header->wsse__Security->UsernameToken->Password = (struct _wsse__Password *)soap_malloc(pSoap, sizeof(struct _wsse__Password));
		memset(header->wsse__Security->UsernameToken->Password, 0, sizeof(struct _wsse__Password));
		header->wsse__Security->UsernameToken->Password->Type = (char *)soap_malloc(pSoap, 128);
		strcpy(header->wsse__Security->UsernameToken->Password->Type, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest");  
		header->wsse__Security->UsernameToken->Password->__item = (char *)soap_malloc(pSoap, 128);
		memset(header->wsse__Security->UsernameToken->Password->__item, 0, 128);
		WS_UsrNameToken(header->wsse__Security->UsernameToken->Password->__item, 128, pUsrInf->pswd,
						header->wsse__Security->UsernameToken->Nonce, header->wsse__Security->UsernameToken->wsu__Created);
	}

	if (was_Action != NULL)
	{
		header->wsa__Action =(char *)soap_malloc(pSoap, 128);
		memset(header->wsa__Action, 0, 128);
		strncpy(header->wsa__Action, was_Action, 127);	// "http://schemas.xmlpSoap.org/ws/2005/04/discovery/Probe";
	}
	if (was_To != NULL)
	{
		header->wsa__To =(char *)soap_malloc(pSoap, 128);
		memset(header->wsa__To, 0, 128);
		strncpy(header->wsa__To,  was_To, 127);		// "urn:schemas-xmlpSoap-org:ws:2005:04:discovery";	
	}

	pSoap->header = header;
	return pSoap;
} 

size_t OnvifDiscovery(struct IPCInfo ipcInfo[], size_t count, struct in_addr *pInAddr)
{
	printf("%s\n", __func__);
	if (count < 1)
		return 0;

	static const char *was_To = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";
	static const char *was_Action = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
	// 这个就是传递过去的组播的ip地址和对应的端口发送广播信息	
	static const char *soap_endpoint = "soap.udp://239.255.255.250:3702/";

	struct SOAP_ENV__Header header = {0};
	struct soap *pSoap = InitSoap(&header, was_To, was_Action, 5, NULL);
	if (pSoap == NULL)
		return 0;

	if (pInAddr != NULL)	// 指定了在IP(某个网卡上的)上发组播
	{
		pSoap->ipv4_multicast_if = (char *)soap_malloc(pSoap, sizeof(*pInAddr));  
		memset(pSoap->ipv4_multicast_if, 0, sizeof(*pInAddr));	
		memcpy(pSoap->ipv4_multicast_if, (char *)pInAddr, sizeof(*pInAddr));
	}

	wsdd__ScopesType sScope = {0};
	sScope.__item = "";
	wsdd__ProbeType req = {0};
	req.Scopes = &sScope;
	req.Types = ""; //"dn:NetworkVideoTransmitter";

	size_t devCnt = 0;
	if (soap_send___wsdd__Probe(pSoap, soap_endpoint, NULL, &req) != SOAP_OK)
	{
		printf("%s:%d\n", __func__, __LINE__);
		soap_print_fault(pSoap, stderr);
	}
	else
	{
		// 发送组播消息成功后，开始循环接收各位设备发送过来的消息
		struct __wsdd__ProbeMatches resp = {0};
		while (devCnt < count && soap_recv___wsdd__ProbeMatches(pSoap, &resp) == SOAP_OK)
		{
			if (resp.wsdd__ProbeMatches == NULL || resp.wsdd__ProbeMatches->ProbeMatch == NULL || resp.wsdd__ProbeMatches->ProbeMatch->XAddrs == NULL
						|| resp.wsdd__ProbeMatches->ProbeMatch->wsa__EndpointReference.Address == NULL)
			{
				printf("%s:%d resp.wsdd__ProbeMatches = %p\n", __func__, __LINE__, resp.wsdd__ProbeMatches);
			}
			else
			{
				strncpy(ipcInfo[devCnt].srvAddr, resp.wsdd__ProbeMatches->ProbeMatch->XAddrs, sizeof(ipcInfo[devCnt].srvAddr) - 1);
				strncpy(ipcInfo[devCnt].EPAddr, resp.wsdd__ProbeMatches->ProbeMatch->wsa__EndpointReference.Address, sizeof(ipcInfo[devCnt].EPAddr) - 1);
				ipcInfo[devCnt].metadataVer = resp.wsdd__ProbeMatches->ProbeMatch->MetadataVersion;
				++devCnt;
			}
		}
	}

	soap_destroy(pSoap);
	soap_end(pSoap); 
	soap_free(pSoap);
	return devCnt;
}

int OnvifGetCapabilities(struct IPCInfo *pIPCInf)
{
	if (pIPCInf->pCapURI == NULL)
		pIPCInf->pCapURI = (struct CapaURI *)calloc(1, sizeof(struct CapaURI));
	else
		memset(pIPCInf->pCapURI, 0, sizeof(*pIPCInf->pCapURI));

	struct SOAP_ENV__Header header = {0};
	struct soap *pSoap = InitSoap(&header, NULL, NULL, 10, &pIPCInf->usrInf);
	if (pSoap == NULL)
		return -1;

	struct _tds__GetCapabilities capReq = {0};
	capReq.Category = (enum tt__CapabilityCategory *)soap_malloc(pSoap, sizeof(enum tt__CapabilityCategory));  
	capReq.__sizeCategory = 1;  
	*(capReq.Category) = tt__CapabilityCategory__All;  
	// 此句也可以不要，因为在接口soap_call___tds__GetCapabilities中判断了，如果此值为NULL,则会给它赋值
	const char *soap_action = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities";

	int retval = -1;
	struct _tds__GetCapabilitiesResponse capResp = {0};
	if (soap_call___tds__GetCapabilities(pSoap, pIPCInf->srvAddr, soap_action, &capReq, &capResp) != SOAP_OK)
	{
		printf("%s:%d\n", __func__, __LINE__);
		soap_print_fault(pSoap, stderr);
	}
	else
	{
		struct tt__Capabilities *pCap = capResp.Capabilities;
		if (pCap == NULL)
			printf("%s:%d pCap == NULL\n", __func__, __LINE__);
		else
		{
			if (pCap->Analytics != NULL && pCap->Analytics->XAddr != NULL)
				strncpy(pIPCInf->pCapURI->uri[eCapaAnalytic], pCap->Analytics->XAddr, sizeof(pIPCInf->pCapURI->uri[eCapaAnalytic]) - 1);
			if (pCap->Device != NULL && pCap->Device->XAddr != NULL)
				strncpy(pIPCInf->pCapURI->uri[eCapaDevice], pCap->Device->XAddr, sizeof(pIPCInf->pCapURI->uri[eCapaDevice]) - 1);
			if (pCap->Events != NULL && pCap->Events->XAddr != NULL)
				strncpy(pIPCInf->pCapURI->uri[eCapaEvnet], pCap->Events->XAddr, sizeof(pIPCInf->pCapURI->uri[eCapaEvnet]) - 1);
			if (pCap->Imaging != NULL && pCap->Imaging->XAddr != NULL)
				strncpy(pIPCInf->pCapURI->uri[eCapaImg], pCap->Imaging->XAddr, sizeof(pIPCInf->pCapURI->uri[eCapaImg]) - 1);
			if (pCap->Media != NULL && pCap->Media->XAddr != NULL)
				strncpy(pIPCInf->pCapURI->uri[eCapaMedia], pCap->Media->XAddr, sizeof(pIPCInf->pCapURI->uri[eCapaMedia]) - 1);
			if (pCap->PTZ != NULL && pCap->PTZ->XAddr != NULL)
				strncpy(pIPCInf->pCapURI->uri[eCapaPTZ], pCap->PTZ->XAddr, sizeof(pIPCInf->pCapURI->uri[eCapaPTZ]) - 1);
		}

		retval = 0;
	}

	soap_destroy(pSoap);
	soap_end(pSoap); 
	soap_free(pSoap);
	return retval;
}

int OnvifGetProfiles(struct IPCInfo *pIPCInf)
{
	// 释放掉可能曾经获取过的
	pIPCInf->prfCount = 0;
	if (pIPCInf->pPrf != NULL)
	{
		free(pIPCInf->pPrf);
		pIPCInf->pPrf = NULL;
	}

	if (pIPCInf->pCapURI == NULL || strlen(pIPCInf->pCapURI->uri[eCapaMedia]) < 1)
	{
		printf("%s:%d\n", __func__, __LINE__);
		return -1;
	}

	struct SOAP_ENV__Header header = {0};
	struct soap *pSoap = InitSoap(&header, NULL, NULL, 10, &pIPCInf->usrInf);
	if (pSoap == NULL)
		return -1;

	struct _trt__GetProfiles prfReq;
	int retval = -1;
	struct _trt__GetProfilesResponse prfResp = {0};
	if (soap_call___trt__GetProfiles(pSoap, pIPCInf->pCapURI->uri[eCapaMedia], NULL, &prfReq, &prfResp) != SOAP_OK)
	{
		printf("%s:%d\n", __func__, __LINE__);
		soap_print_fault(pSoap, stderr);
	}
	else
	{
		printf("%s:%d prfResp.__sizeProfiles = %d\n", __func__, __LINE__, prfResp.__sizeProfiles);
		if (prfResp.__sizeProfiles > 0)
		{
			pIPCInf->pPrf = (struct Profile *)calloc(prfResp.__sizeProfiles, sizeof(struct Profile));
			int i = 0;
			for (i = 0; i < prfResp.__sizeProfiles; ++i)
			{
				strncpy(pIPCInf->pPrf[i].name, prfResp.Profiles[i].Name, sizeof(pIPCInf->pPrf[i].name) - 1);
				strncpy(pIPCInf->pPrf[i].token, prfResp.Profiles[i].token, sizeof(pIPCInf->pPrf[i].token) - 1);
			}
			pIPCInf->prfCount = prfResp.__sizeProfiles;
		}
		retval = 0;
	}

	soap_destroy(pSoap);
	soap_end(pSoap);
	soap_free(pSoap);
	return retval;
}

int OnvifGetStreamURI(struct IPCInfo *pIPCInf, size_t prfId, char (*pUri)[128])
{
	memset(pUri, 0, sizeof(*pUri));
	if (pIPCInf->pCapURI == NULL || strlen(pIPCInf->pCapURI->uri[eCapaMedia]) < 1 || prfId >= pIPCInf->prfCount || pIPCInf->pPrf == NULL)
	{
		printf("%s:%d\n", __func__, __LINE__);
		return -1;
	}

	struct SOAP_ENV__Header header = {0};
	struct soap *pSoap = InitSoap(&header, NULL, NULL, 10, &pIPCInf->usrInf);
	if (pSoap == NULL)
		return -1;

	struct _trt__GetStreamUri uriReq = {0};
	uriReq.StreamSetup = (struct tt__StreamSetup *)soap_malloc(pSoap, sizeof(struct tt__StreamSetup));
	uriReq.StreamSetup->Stream = tt__StreamType__RTP_Unicast;
	uriReq.StreamSetup->Transport = (struct tt__Transport *)soap_malloc(pSoap, sizeof(struct tt__Transport));
	uriReq.StreamSetup->Transport->Protocol = tt__TransportProtocol__RTSP;
	uriReq.StreamSetup->Transport->Tunnel = 0;
	uriReq.StreamSetup->__size = 1;
	uriReq.StreamSetup->__any = NULL;
	uriReq.StreamSetup->__anyAttribute = NULL;
	uriReq.ProfileToken = pIPCInf->pPrf[prfId].token;

	int retval = -1;
	struct _trt__GetStreamUriResponse uriResp = {0};
	if (soap_call___trt__GetStreamUri(pSoap, pIPCInf->pCapURI->uri[eCapaMedia], NULL, &uriReq, &uriResp) != SOAP_OK)
	{
		printf("%s:%d\n", __func__, __LINE__);
		soap_print_fault(pSoap, stderr);
	}
	else
	{
		if (uriResp.MediaUri != NULL && strlen(uriResp.MediaUri->Uri) > 0)
		{
			strncpy((char *)pUri, uriResp.MediaUri->Uri, sizeof(*pUri) - 1);
			retval = 0;
		}
	}

	soap_destroy(pSoap);
	soap_end(pSoap); 
	soap_free(pSoap);
	return retval;
}

void IPCInfoFree(struct IPCInfo *pIPCInf)
{
	pIPCInf->prfCount = 0;
	if (pIPCInf->pPrf != NULL)
	{
		free(pIPCInf->pPrf);
		pIPCInf->pPrf = NULL;
	}

	if (pIPCInf->pCapURI != NULL)
	{
		free(pIPCInf->pCapURI);
		pIPCInf->pCapURI = NULL;
	}
}

