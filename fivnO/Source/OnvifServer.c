// 文件太大不完全上传，需要将soapServer.c:soap_serve_request(*)里用到的函数都实现
// 函数原型在soapStub.h里面有声明
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>
#define _GNU_SOURCE		// -std=c99时要放首行，-std=gnu99时可放这
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <linux/in.h>

#include "OnvifServer.h"
//#include "wsdd.h"	// 防止namespaces重复定义
#include "soapH.h"
#include "Base64.h"
#include "SHA1.h"

#define MAX_ONVIF_SRV_NIC	4	// 支持最多的支持Onvif服务端的网卡数

struct OnvifSrvNic		// 在某网卡上提供Onvif服务的运行参数
{
	char nic[8];			// 网卡设备名
	SOAP_SOCKET sockDisc;	// 设备被发现的Socket
	SOAP_SOCKET sockWebSrv;	// Web Services的Socket
	_Bool exitThr;			// 退出线程
	_Bool runDisc;			// 设备被发现的线程在运行
	_Bool runWebSrv;
	uint8_t mac[6];
	char ip[16];
	char mask[16];
	pthread_mutex_t mutexIp;	// IP相关的信息索，放在结构体最后
};

static uint8_t tiChnCount = 0;
static struct OnvifSrvNic tSrvNic[MAX_ONVIF_SRV_NIC] = {{{0}}};

static _Bool tbRun = true;
static pthread_mutex_t tMutex = PTHREAD_MUTEX_INITIALIZER;
extern SOAP_NMAC struct Namespace namespaces[];

static int GetSockMacAndIp(uint8_t (*pMAC)[6], char (*pIP)[16], char (*pMask)[16], SOAP_SOCKET sockFD, _Bool discOrWebSrv)	// 根据sock找到MAC和IP和掩码
{
	memset(pMAC, 0, sizeof(*pMAC));
	memset(pIP, 0, sizeof(*pIP));
	size_t i = 0;
	if (discOrWebSrv)
	{
		for (i = 0; i < sizeof(tSrvNic) / sizeof(tSrvNic[0]); ++i)
		{
			if (tSrvNic[i].sockDisc == sockFD)
			{
				memcpy(pMAC, tSrvNic[i].mac, sizeof(*pMAC));
				strncpy((char *)pIP, tSrvNic[i].ip, sizeof(*pIP) - 1);
				strncpy((char *)pMask, tSrvNic[i].mask, sizeof(*pMask) - 1);
				return 0;
			}
		}
	}
	else
	{
		for (i = 0; i < sizeof(tSrvNic) / sizeof(tSrvNic[0]); ++i)
		{
			if (tSrvNic[i].sockWebSrv == sockFD)
			{
				memcpy(pMAC, tSrvNic[i].mac, sizeof(*pMAC));
				strncpy((char *)pIP, tSrvNic[i].ip, sizeof(*pIP) - 1);
				strncpy((char *)pMask, tSrvNic[i].mask, sizeof(*pMask) - 1);
				return 0;
			}
		}
	}

	return -1;
}

static _Bool AuthenticateOK(struct SOAP_ENV__Header *header)	// 鉴权
{
	if (header == NULL || header->wsse__Security == NULL || header->wsse__Security->UsernameToken == NULL)
	{
		printf("%s:%s:%d header = %p\n", __FILE__, __func__, __LINE__, header);
		return false;
	}

	struct _wsse__UsernameToken *pUT = header->wsse__Security->UsernameToken;
	if (pUT->Username == NULL || pUT->Nonce == NULL || pUT->wsu__Created == NULL || pUT->Password == NULL || pUT->Password->__item == NULL)
	{
		printf("%s:%s:%d pUT->Username = %p, Nonce = %p, wsu__Created = %p, Password = %p\n", __FILE__, __func__, __LINE__, pUT->Username, pUT->Nonce, pUT->wsu__Created, pUT->Password);
		return false;
	}

	if (strcmp(pUT->Username, "admin") != 0)	// 用户名
	{
		printf("%s:%s:%d pUT->Username = %s\n", __FILE__, __func__, __LINE__, pUT->Username);
		return false;
	}

	unsigned char nonceRaw[32] = {0};
	Base64Decode(nonceRaw, sizeof(nonceRaw), pUT->Nonce);
	char allRaw[128] = {0};
	sprintf(allRaw,"%s%s%s", (char *)nonceRaw, pUT->wsu__Created, "123456");	// 密码
	uint8_t shaDst[20] = {0};
	SHA1Byte(&shaDst, allRaw);
	char dst[128] = {0};
	Base64Encode(dst, sizeof(dst), (const unsigned char *)shaDst, sizeof(shaDst));
	if (strcmp(dst, pUT->Password->__item) == 0)
		return true;
	else
	{
		printf("%s:%s:%d\n", __FILE__, __func__, __LINE__);
		return false;
	}
}

// 空实现的函数都按下面这种方式填充
SOAP_FMAC5 int SOAP_FMAC6 SOAP_ENV__Fault(struct soap *soap, char *faultcode, char *faultstring, char *faultactor, struct SOAP_ENV__Detail *detail, struct SOAP_ENV__Code *SOAP_ENV__Code, struct SOAP_ENV__Reason *SOAP_ENV__Reason, char *SOAP_ENV__Node, char *SOAP_ENV__Role, struct SOAP_ENV__Detail *SOAP_ENV__Detail)
{
	printf("%s:%d\n", __func__, __LINE__);
	return soap_receiver_fault_subcode(soap, __func__, "Not Implemented", "The requested action is not implemented");
}

SOAP_FMAC5 int SOAP_FMAC6 __wsdd__Hello(struct soap *soap, struct wsdd__HelloType *wsdd__Hello)
{
	printf("%s:%d\n", __func__, __LINE__);
	return soap_receiver_fault_subcode(soap, __func__, "Not Implemented", "The requested action is not implemented");
}

SOAP_FMAC5 int SOAP_FMAC6 __wsdd__Bye(struct soap *soap, struct wsdd__ByeType *wsdd__Bye)
{
	printf("%s:%d\n", __func__, __LINE__);
	return soap_receiver_fault_subcode(soap, __func__, "Not Implemented", "The requested action is not implemented");
}

SOAP_FMAC5 int SOAP_FMAC6 __wsdd__Probe(struct soap *soap, struct wsdd__ProbeType *wsdd__Probe)  
{
	printf("%s:%d\n", __func__, __LINE__);
	uint8_t mac[6] = {0};
	char ip[16] = {0}, mask[16] = {0};
	GetSockMacAndIp(&mac, &ip, &mask, soap->master, true);

	struct in_addr ia = {0};
	ia.s_addr = htonl(soap->ip);
	const char *pSoapIp = inet_ntoa(ia);
	#if 0 // 排除自身，根据需要打开
	if (strcmp(pSoapIp, ip) == 0)
		return SOAP_OK;
	#endif

	// 多网卡时排除组播能到，但TCP不能同的访问
	in_addr_t inIp1 = inet_addr(ip);
	in_addr_t inIp2 = inet_addr(pSoapIp);
	in_addr_t inMask = inet_addr(mask);
	if ((inIp1 & inMask) != (inIp2 & inMask))
	{
		printf("%s:%d ip = %s, pSoapIp = %s, mask = %s\n", __func__, __LINE__, ip, pSoapIp, mask);
		return SOAP_OK;
	}

	wsdd__ProbeMatchesType ProbeMatches;  
	ProbeMatches.ProbeMatch = (struct wsdd__ProbeMatchType *)soap_malloc(soap, sizeof(struct wsdd__ProbeMatchType));  
	memset(ProbeMatches.ProbeMatch, 0,  sizeof(struct wsdd__ProbeMatchType));  

	ProbeMatches.ProbeMatch->XAddrs = (char *)soap_malloc(soap, sizeof(char) * 256);  
	memset(ProbeMatches.ProbeMatch->XAddrs, '\0', sizeof(char) * 256);  

	ProbeMatches.ProbeMatch->Types = (char *)soap_malloc(soap, sizeof(char) * 256);  
	memset(ProbeMatches.ProbeMatch->Types, '\0', sizeof(char) * 256);  

	ProbeMatches.ProbeMatch->wsa__EndpointReference.ReferenceProperties = (struct wsa__ReferencePropertiesType*)soap_malloc(soap,sizeof(struct wsa__ReferencePropertiesType));  
	memset(ProbeMatches.ProbeMatch->wsa__EndpointReference.ReferenceProperties, 0, sizeof(struct wsa__ReferencePropertiesType));  

	ProbeMatches.ProbeMatch->wsa__EndpointReference.ReferenceParameters = (struct wsa__ReferenceParametersType*)soap_malloc(soap,sizeof(struct wsa__ReferenceParametersType));  
	memset(ProbeMatches.ProbeMatch->wsa__EndpointReference.ReferenceParameters, 0, sizeof(struct wsa__ReferenceParametersType));  

	ProbeMatches.ProbeMatch->wsa__EndpointReference.ServiceName = (struct wsa__ServiceNameType*)soap_malloc(soap,sizeof(struct wsa__ServiceNameType));  
	memset(ProbeMatches.ProbeMatch->wsa__EndpointReference.ServiceName, 0, sizeof(struct wsa__ServiceNameType));  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.PortType = (char **)soap_malloc(soap, sizeof(char *) * 256);  
	memset(ProbeMatches.ProbeMatch->wsa__EndpointReference.PortType, 0, sizeof(char *) * 256);  

	ProbeMatches.ProbeMatch->wsa__EndpointReference.__any = (char **)soap_malloc(soap, sizeof(char*) * 256);  
	memset(ProbeMatches.ProbeMatch->wsa__EndpointReference.__any, 0, sizeof(char*) * 256);  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.__anyAttribute = (char *)soap_malloc(soap, sizeof(char) * 256);  
	memset(ProbeMatches.ProbeMatch->wsa__EndpointReference.__anyAttribute, 0,  sizeof(char) * 256);  

	ProbeMatches.ProbeMatch->wsa__EndpointReference.Address = (char *)soap_malloc(soap, sizeof(char) * 256);  
	memset(ProbeMatches.ProbeMatch->wsa__EndpointReference.Address, 0, sizeof(char) * 256);  

	char _IPAddr[64] = {0};  
	char _HwId[64] = {0};
	sprintf(_HwId, "urn:uuid:20170625-aabb-ccdd-eeff-%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	sprintf(_IPAddr, "http://%s:80/onvif/device_service", ip);

	ProbeMatches.__sizeProbeMatch = 1;  
	ProbeMatches.ProbeMatch->Scopes = (struct wsdd__ScopesType*)soap_malloc(soap, sizeof(struct wsdd__ScopesType) * ProbeMatches.__sizeProbeMatch);  
	memset(ProbeMatches.ProbeMatch->Scopes, 0, sizeof(struct wsdd__ScopesType) * ProbeMatches.__sizeProbeMatch);  
	//Scopes MUST BE  
	ProbeMatches.ProbeMatch->Scopes->__item =(char *)soap_malloc(soap, 1024);  
	memset(ProbeMatches.ProbeMatch->Scopes->__item, '\0', 1024);  
	strcat(ProbeMatches.ProbeMatch->Scopes->__item, "onvif://www.onvif.org/type/Network_Video_Transmitter");  
	strcat(ProbeMatches.ProbeMatch->Scopes->__item, "onvif://www.onvif.org/type/video_encoder");  
	strcat(ProbeMatches.ProbeMatch->Scopes->__item, "onvif://www.onvif.org/type/audio_encoder");  
	strcat(ProbeMatches.ProbeMatch->Scopes->__item, "onvif://www.onvif.org/location/earth");  
	strcat(ProbeMatches.ProbeMatch->Scopes->__item, "onvif://www.onvif.org/name/programer");  
	strcat(ProbeMatches.ProbeMatch->Scopes->__item, "onvif://www.onvif.org/hardware/TEST_Onvif");  

	ProbeMatches.ProbeMatch->Scopes->MatchBy = NULL;  
	strcpy(ProbeMatches.ProbeMatch->XAddrs, _IPAddr);  
	strcpy(ProbeMatches.ProbeMatch->Types, wsdd__Probe->Types);  
	printf("wsdd__Probe->Types=%s\n",wsdd__Probe->Types);  
	ProbeMatches.ProbeMatch->MetadataVersion = 1;  

	//ws-discovery规定 为可选项  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.ReferenceProperties->__size = 0;  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.ReferenceProperties->__any = NULL;  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.ReferenceParameters->__size = 0;  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.ReferenceParameters->__any = NULL;  

	ProbeMatches.ProbeMatch->wsa__EndpointReference.PortType[0] = (char *)soap_malloc(soap, sizeof(char) * 256);  
	//ws-discovery规定 为可选项  
	strcpy(ProbeMatches.ProbeMatch->wsa__EndpointReference.PortType[0], "ttl");  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.ServiceName->__item = NULL;  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.ServiceName->PortName = NULL;  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.ServiceName->__anyAttribute = NULL;  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.__any[0] = (char *)soap_malloc(soap, sizeof(char) * 256);  
	strcpy(ProbeMatches.ProbeMatch->wsa__EndpointReference.__any[0], "Any");  
	strcpy(ProbeMatches.ProbeMatch->wsa__EndpointReference.__anyAttribute, "Attribute");  
	ProbeMatches.ProbeMatch->wsa__EndpointReference.__size = 0;  
	strcpy(ProbeMatches.ProbeMatch->wsa__EndpointReference.Address, _HwId);  

	soap->header->wsa__To = (char *)"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";  
	soap->header->wsa__Action = (char *)"http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches";  
	soap->header->wsa__RelatesTo = (struct wsa__Relationship*)soap_malloc(soap, sizeof(struct wsa__Relationship));  
	soap->header->wsa__RelatesTo->__item = soap->header->wsa__MessageID;  
	soap->header->wsa__RelatesTo->RelationshipType = NULL;  
	soap->header->wsa__RelatesTo->__anyAttribute = NULL;  

	soap->header->wsa__MessageID =(char *)soap_malloc(soap, sizeof(char) * 1024);  
	strcpy(soap->header->wsa__MessageID, _HwId + 4); //前面四个字节可以是不需要的  

	if (soap_send___wsdd__ProbeMatches(soap, "http://", NULL, &ProbeMatches) == SOAP_OK)
		return SOAP_OK;
	else
	{
		printf("%s:%d\n", __func__, __LINE__);
		soap_print_fault(soap, stderr);
		return soap->error;
	} 
}  

// 中间有省略

SOAP_FMAC5 int SOAP_FMAC6 __tds__GetDeviceInformation(struct soap *soap, struct _tds__GetDeviceInformation *tds__GetDeviceInformation, struct _tds__GetDeviceInformationResponse *tds__GetDeviceInformationResponse)
{
	printf("%s:%d\n", __func__, __LINE__);
	tds__GetDeviceInformationResponse->Manufacturer = (char *)soap_malloc(soap, 16);
	strcpy(tds__GetDeviceInformationResponse->Manufacturer, "Super Project");
	tds__GetDeviceInformationResponse->Model = (char *)soap_malloc(soap, 16);
	strcpy(tds__GetDeviceInformationResponse->Model, "HDVR1x0x");
	tds__GetDeviceInformationResponse->FirmwareVersion = (char *)soap_malloc(soap, 16);
	strcpy(tds__GetDeviceInformationResponse->FirmwareVersion, "FM1001");
	tds__GetDeviceInformationResponse->SerialNumber = (char *)soap_malloc(soap, 16);
	strcpy(tds__GetDeviceInformationResponse->SerialNumber, "1111-2222-3333-4444");
	tds__GetDeviceInformationResponse->HardwareId = (char *)soap_malloc(soap, 16);
	strcpy(tds__GetDeviceInformationResponse->HardwareId, "HW12345");

	return SOAP_OK;
}

// 中间有省略

SOAP_FMAC5 int SOAP_FMAC6 __tds__GetCapabilities(struct soap *soap, struct _tds__GetCapabilities *tds__GetCapabilities, struct _tds__GetCapabilitiesResponse *tds__GetCapabilitiesResponse)
{
	printf("%s:%d\n", __func__, __LINE__);
	if (AuthenticateOK(soap->header) == false)
		return SOAP_FAULT;

	uint8_t mac[6] = {0};
	char ip[16] = {0}, mask[16] = {0};
	GetSockMacAndIp(&mac, &ip, &mask, soap->master, false);

	tds__GetCapabilitiesResponse->Capabilities = (struct tt__Capabilities *)soap_malloc(soap,sizeof(struct tt__Capabilities));
	struct tt__Capabilities *pCap = tds__GetCapabilitiesResponse->Capabilities;
	memset(pCap, 0, sizeof(struct tt__Capabilities));

	pCap->Device = (struct tt__DeviceCapabilities *)soap_malloc(soap,sizeof(struct tt__DeviceCapabilities));
	memset(pCap->Device, 0, sizeof(struct tt__DeviceCapabilities));
	pCap->Device->XAddr = (char *)soap_malloc(soap, 64);
	sprintf(pCap->Device->XAddr, "http://%s:80/onvif/device_service", ip);

	// 设备的一些基本能力值，是否支持那些功能，如果在开发的时候，如果前段设备支持这些功能的话，就可以直接填写true，否则填写false	
	pCap->Device->Network = (struct tt__NetworkCapabilities *)soap_malloc(soap, sizeof(struct tt__NetworkCapabilities ));
	memset(pCap->Device->Network, 0, sizeof(struct tt__NetworkCapabilities ));
	pCap->Device->Network->IPFilter = (enum xsd__boolean *)soap_malloc(soap, sizeof(enum xsd__boolean));
	*(pCap->Device->Network->IPFilter) = xsd__boolean__false_;// xsd__boolean__true_
	pCap->Device->Network->ZeroConfiguration= (enum xsd__boolean *)soap_malloc(soap, sizeof(enum xsd__boolean));
	*(pCap->Device->Network->ZeroConfiguration) = xsd__boolean__true_;// xsd__boolean__false_
	pCap->Device->Network->IPVersion6 = (enum xsd__boolean *)soap_malloc(soap, sizeof(enum xsd__boolean));
	*(pCap->Device->Network->IPVersion6) = xsd__boolean__false_;// xsd__boolean__true_
	pCap->Device->Network->DynDNS = (enum xsd__boolean *)soap_malloc(soap, sizeof(enum xsd__boolean));
	*(pCap->Device->Network->DynDNS) = xsd__boolean__true_;// xsd__boolean__false_

	pCap->Device->System = (struct tt__SystemCapabilities *)soap_malloc(soap, sizeof(struct tt__SystemCapabilities));
	memset( pCap->Device->System, 0, sizeof(struct tt__SystemCapabilities));
	pCap->Device->System->DiscoveryResolve = xsd__boolean__true_;
	pCap->Device->System->DiscoveryBye 	= xsd__boolean__true_;
	pCap->Device->System->RemoteDiscovery	= xsd__boolean__false_;
	pCap->Device->System->SystemBackup 	= xsd__boolean__false_;
	pCap->Device->System->SystemLogging	= xsd__boolean__false_;
	pCap->Device->System->FirmwareUpgrade	= xsd__boolean__false_;
	pCap->Device->System->__sizeSupportedVersions = 1;
	pCap->Device->System->SupportedVersions = (struct tt__OnvifVersion *)soap_malloc(soap, sizeof(struct tt__OnvifVersion));
	pCap->Device->System->SupportedVersions->Major = 2;
	pCap->Device->System->SupportedVersions->Minor = 0;

	// 设备IO的一些支持  
	pCap->Device->IO = (struct tt__IOCapabilities *)soap_malloc(soap, sizeof(struct tt__IOCapabilities));
	memset(pCap->Device->IO, 0, sizeof(struct tt__IOCapabilities));
	pCap->Device->IO->InputConnectors = (int *)soap_malloc(soap, sizeof(int));
	*(pCap->Device->IO->InputConnectors) = 1;
	pCap->Device->IO->RelayOutputs = (int *)soap_malloc(soap, sizeof(int));
	*(pCap->Device->IO->RelayOutputs) = 1;

	//pCap->Device->Security = (struct tt__SecurityCapabilities *)soap_malloc(soap, sizeof(struct tt__SecurityCapabilities));

	// Imaging的一些基本信息，关于视频颜色，IRCut的一些基本信息	
	pCap->Imaging = (struct tt__ImagingCapabilities *)soap_malloc(soap,sizeof(struct tt__ImagingCapabilities));
	memset(pCap->Imaging, 0, sizeof(struct tt__ImagingCapabilities));
	pCap->Imaging->XAddr = (char *)soap_malloc(soap, 64);
	memset(pCap->Imaging->XAddr, '\0', 64);
	sprintf(pCap->Imaging->XAddr, "http://%s:80/onvif/Imaging", ip);

	pCap->Media = (struct tt__MediaCapabilities *)soap_malloc(soap,sizeof(struct tt__MediaCapabilities));
	memset(pCap->Media, 0, sizeof(struct tt__MediaCapabilities));

	// 多媒体
	pCap->Media->XAddr = (char *)soap_malloc(soap, 64);
	memset(pCap->Media->XAddr, 0, 64);
	sprintf(pCap->Media->XAddr, "http://%s:80/onvif/Media", ip);
	pCap->Media->StreamingCapabilities = (struct tt__RealTimeStreamingCapabilities *)soap_malloc(soap,   
				sizeof(struct tt__RealTimeStreamingCapabilities));
	memset(pCap->Media->StreamingCapabilities, 0, sizeof(struct tt__RealTimeStreamingCapabilities));
	pCap->Media->StreamingCapabilities->RTPMulticast	= (enum xsd__boolean *)soap_malloc(soap,sizeof(int));
	*pCap->Media->StreamingCapabilities->RTPMulticast	= xsd__boolean__false_;
	pCap->Media->StreamingCapabilities->RTP_USCORETCP	= (enum xsd__boolean*)soap_malloc(soap,sizeof(int));
	*pCap->Media->StreamingCapabilities->RTP_USCORETCP = xsd__boolean__true_;
	pCap->Media->StreamingCapabilities->RTP_USCORERTSP_USCORETCP = (enum xsd__boolean*)soap_malloc(soap,sizeof(int));
	*pCap->Media->StreamingCapabilities->RTP_USCORERTSP_USCORETCP = xsd__boolean__true_;

	return SOAP_OK;
}

// 中间有省略

SOAP_FMAC5 int SOAP_FMAC6 __trt__GetProfiles(struct soap *soap, struct _trt__GetProfiles *trt__GetProfiles, struct _trt__GetProfilesResponse *trt__GetProfilesResponse)
{
	printf("%s:%d\n", __func__, __LINE__);
	if (AuthenticateOK(soap->header) == false)
		return SOAP_FAULT;

	trt__GetProfilesResponse->Profiles = (struct tt__Profile *)soap_malloc(soap, sizeof(struct tt__Profile) * tiChnCount * 2);	// 支持主子码流
	struct tt__Profile *pPrf = trt__GetProfilesResponse->Profiles;
	memset(pPrf, 0, sizeof(struct tt__Profile) * tiChnCount * 2);
	int i = 0, j = 0;
	for (i = 0; i < tiChnCount; ++i)
	{
		for (j = 0; j < 2; ++j)
		{
			pPrf[i*2+j].Name = (char *)soap_malloc(soap, 64);
			sprintf(pPrf[i*2+j].Name, "profile%"PRIu8"%c", i + 1, (j == 0 ? 'm' : 's'));
			pPrf[i*2+j].token = (char *)soap_malloc(soap, 64);
			//此token也就是每次需要获取对应profiles的一些信息的时候，就需要在请求的时候填写此对应的token来，来进行验证判断	
			sprintf(pPrf[i*2+j].token, "%s_token", pPrf[i*2+j].Name);
		}
	}

	trt__GetProfilesResponse->__sizeProfiles = tiChnCount * 2;

	struct _trt__GetVideoSourceConfigurationsResponse vscResp = {0};
	__trt__GetVideoSourceConfigurations(soap, NULL, &vscResp);
	for (i = 0; i < tiChnCount; ++i)
	{
		for (j = 0; j < 2; ++j)
		{
			pPrf[i*2+j].VideoSourceConfiguration = vscResp.Configurations + i*2+j;
		}
	}

	struct _trt__GetVideoEncoderConfigurationsResponse vecResp = {0};
	__trt__GetVideoEncoderConfigurations(soap, NULL, &vecResp);
	for (i = 0; i < tiChnCount; ++i)
	{
		for (j = 0; j < 2; ++j)
		{
			pPrf[i*2+j].VideoEncoderConfiguration = vecResp.Configurations + i * 2 + j;
		}
	}

	return SOAP_OK;
}

// 中间有省略

SOAP_FMAC5 int SOAP_FMAC6 __trt__GetVideoSourceConfigurations(struct soap *soap, struct _trt__GetVideoSourceConfigurations *trt__GetVideoSourceConfigurations, struct _trt__GetVideoSourceConfigurationsResponse *trt__GetVideoSourceConfigurationsResponse)
{
	printf("%s:%d\n", __func__, __LINE__);
	trt__GetVideoSourceConfigurationsResponse->Configurations = (struct tt__VideoSourceConfiguration *)soap_malloc(soap, sizeof(struct tt__VideoSourceConfiguration) * tiChnCount * 2);	// 支持主子码流
	struct tt__VideoSourceConfiguration *pVSC = trt__GetVideoSourceConfigurationsResponse->Configurations;
	memset(pVSC, 0, sizeof(struct tt__VideoSourceConfiguration) * tiChnCount * 2);
	int i = 0, j = 0;
	for (i = 0; i < tiChnCount; ++i)
	{
		for (j = 0; j < 2; ++j)
		{
			pVSC[i*2+j].Name = (char *)soap_malloc(soap, 64);
			sprintf(pVSC[i*2+j].Name, "VideoSource%d%c", i + 1, (j == 0 ? 'm' : 's'));
			pVSC[i*2+j].token = (char *)soap_malloc(soap, 64);
			sprintf(pVSC[i*2+j].token, "%s_token", pVSC[i*2+j].Name);
			pVSC[i*2+j].SourceToken = (char *)soap_malloc(soap, 64);
			sprintf(pVSC[i*2+j].SourceToken, "%s_stoken", pVSC[i*2+j].Name);
			pVSC[i*2+j].UseCount = 1;
			pVSC[i*2+j].Bounds = (struct tt__IntRectangle *)soap_malloc(soap, sizeof(struct tt__IntRectangle));
			memset(pVSC[i*2+j].Bounds, 0, sizeof(struct tt__IntRectangle));
			pVSC[i*2+j].Bounds->x = 0;
			pVSC[i*2+j].Bounds->y = 0;
			if (j == 0)
			{
				pVSC[i*2+j].Bounds->width = 1280;
				pVSC[i*2+j].Bounds->height = 720;
			}
			else
			{
				pVSC[i*2+j].Bounds->width = 352;
				pVSC[i*2+j].Bounds->height = 288;
			}
		}
	}

	trt__GetVideoSourceConfigurationsResponse->__sizeConfigurations = tiChnCount * 2;
	return SOAP_OK;
}

SOAP_FMAC5 int SOAP_FMAC6 __trt__GetVideoEncoderConfigurations(struct soap *soap, struct _trt__GetVideoEncoderConfigurations *trt__GetVideoEncoderConfigurations, struct _trt__GetVideoEncoderConfigurationsResponse *trt__GetVideoEncoderConfigurationsResponse)
{
	printf("%s:%d\n", __func__, __LINE__);
	trt__GetVideoEncoderConfigurationsResponse->Configurations = (struct tt__VideoEncoderConfiguration *)soap_malloc(soap, sizeof(struct tt__VideoEncoderConfiguration) * tiChnCount * 2);	// 支持主子码流
	struct tt__VideoEncoderConfiguration *pVEC = trt__GetVideoEncoderConfigurationsResponse->Configurations;
	memset(pVEC, 0, sizeof(struct tt__VideoEncoderConfiguration) * tiChnCount * 2);
	int i = 0, j = 0;
	for (i = 0; i < tiChnCount; ++i)
	{
		for (j = 0; j < 2; ++j)
		{
			pVEC[i*2+j].Name = (char *)soap_malloc(soap, 64);
			sprintf(pVEC[i*2+j].Name, "VideoEncoder%d%c", i + 1, (j == 0 ? 'm' : 's'));
			pVEC[i*2+j].token = (char *)soap_malloc(soap, 64);
			sprintf(pVEC[i*2+j].token, "%s_token", pVEC[i*2+j].Name);
			pVEC[i*2+j].UseCount = 1;
			pVEC[i*2+j].Encoding = tt__VideoEncoding__H264;
			pVEC[i*2+j].Resolution = (struct tt__VideoResolution *)soap_malloc(soap, sizeof(struct tt__VideoResolution));
			pVEC[i*2+j].Quality = 2.0;
			pVEC[i*2+j].RateControl = (struct tt__VideoRateControl *)soap_malloc(soap, sizeof(struct tt__VideoRateControl));
			pVEC[i*2+j].H264 = (struct tt__H264Configuration *)soap_malloc(soap, sizeof(struct tt__H264Configuration));

			if (j == 0)
			{
				pVEC[i*2+j].Resolution->Width = 1280;
				pVEC[i*2+j].Resolution->Height = 720;
				pVEC[i*2+j].RateControl->FrameRateLimit = 30;
				pVEC[i*2+j].RateControl->EncodingInterval = 1;
				pVEC[i*2+j].RateControl->BitrateLimit = 4096 * 1024;
				pVEC[i*2+j].H264->GovLength = pVEC[i*2+j].RateControl->FrameRateLimit * 2;
				pVEC[i*2+j].H264->H264Profile = tt__H264Profile__Main;
			}
			else
			{
				pVEC[i*2+j].Resolution->Width = 352;
				pVEC[i*2+j].Resolution->Height = 288;
				pVEC[i*2+j].RateControl->FrameRateLimit = 30;
				pVEC[i*2+j].RateControl->EncodingInterval = 1;
				pVEC[i*2+j].RateControl->BitrateLimit = 1024 * 1024;
				pVEC[i*2+j].H264->GovLength = pVEC[i*2+j].RateControl->FrameRateLimit * 2;
				pVEC[i*2+j].H264->H264Profile = tt__H264Profile__Extended;
			}
		}
	}

	trt__GetVideoEncoderConfigurationsResponse->__sizeConfigurations = tiChnCount * 2;
	return SOAP_OK;
}

// 中间有省略

SOAP_FMAC5 int SOAP_FMAC6 __trt__GetVideoSourceConfiguration(struct soap *soap, struct _trt__GetVideoSourceConfiguration *trt__GetVideoSourceConfiguration, struct _trt__GetVideoSourceConfigurationResponse *trt__GetVideoSourceConfigurationResponse)
{
	printf("%s:%d\n", __func__, __LINE__);
	char *pStr = strstr(trt__GetVideoSourceConfiguration->ConfigurationToken, "VideoSource");
	if (pStr != trt__GetVideoSourceConfiguration->ConfigurationToken)
	{
		printf("%s:%d trt__GetStreamUri->ProfileToken = %s\n", __func__, __LINE__, trt__GetVideoSourceConfiguration->ConfigurationToken);
		return SOAP_FAULT;
	}
	pStr += strlen("profile");
	char *pStr2 = strstr(pStr, "_token");
	if (pStr2 == NULL || pStr2 + strlen("_token") != trt__GetVideoSourceConfiguration->ConfigurationToken + strlen(trt__GetVideoSourceConfiguration->ConfigurationToken))
	{
		printf("%s:%d trt__GetStreamUri->ProfileToken = %s\n", __func__, __LINE__, trt__GetVideoSourceConfiguration->ConfigurationToken);
		return SOAP_FAULT;
	}
	char *pE = NULL;
	long chn = strtol(pStr, &pE, 10);
	if (pE == NULL || pE == pStr || chn < 1 || chn > tiChnCount || (*pE != 'm' && *pE != 's'))
	{
		printf("%s:%d trt__GetStreamUri->ProfileToken = %s\n", __func__, __LINE__, trt__GetVideoSourceConfiguration->ConfigurationToken);
		return SOAP_FAULT;
	}

	trt__GetVideoSourceConfigurationResponse->Configuration = (struct tt__VideoSourceConfiguration *)soap_malloc(soap, sizeof(struct tt__VideoSourceConfiguration));
	struct tt__VideoSourceConfiguration *pVSC = trt__GetVideoSourceConfigurationResponse->Configuration;
	memset(pVSC, 0, sizeof(struct tt__VideoSourceConfiguration));

	pVSC->Name = (char *)soap_malloc(soap, 64);
	sprintf(pVSC->Name, "VideoSource%ld%c", chn, *pE);
	pVSC->token = (char *)soap_malloc(soap, 64);
	sprintf(pVSC->token, "%s_token", pVSC->Name);
	pVSC->SourceToken = (char *)soap_malloc(soap, 64);
	sprintf(pVSC->SourceToken, "%s_stoken", pVSC->Name);
	pVSC->UseCount = 1;
	pVSC->Bounds = (struct tt__IntRectangle *)soap_malloc(soap, sizeof(struct tt__IntRectangle));
	memset(pVSC->Bounds, 0, sizeof(struct tt__IntRectangle));
	pVSC->Bounds->x = 0;
	pVSC->Bounds->y = 0;
	if (*pE == 'm')
	{
		pVSC->Bounds->width = 1280;
		pVSC->Bounds->height = 720;
	}
	else
	{
		pVSC->Bounds->width = 352;
		pVSC->Bounds->height = 288;
	}

	return SOAP_OK;
}

// 中间有省略

SOAP_FMAC5 int SOAP_FMAC6 __trt__GetStreamUri(struct soap *soap, struct _trt__GetStreamUri *trt__GetStreamUri, struct _trt__GetStreamUriResponse *trt__GetStreamUriResponse)
{
	printf("%s:%d\n", __func__, __LINE__);
	if (AuthenticateOK(soap->header) == false)
		return SOAP_FAULT;

	char *pStr = strstr(trt__GetStreamUri->ProfileToken, "profile");
	if (pStr != trt__GetStreamUri->ProfileToken)
	{
		printf("%s:%d trt__GetStreamUri->ProfileToken = %s\n", __func__, __LINE__, trt__GetStreamUri->ProfileToken);
		return SOAP_FAULT;
	}
	pStr += strlen("profile");
	char *pStr2 = strstr(pStr, "_token");
	if (pStr2 == NULL || pStr2 + strlen("_token") != trt__GetStreamUri->ProfileToken + strlen(trt__GetStreamUri->ProfileToken))
	{
		printf("%s:%d trt__GetStreamUri->ProfileToken = %s\n", __func__, __LINE__, trt__GetStreamUri->ProfileToken);
		return SOAP_FAULT;
	}
	char *pE = NULL;
	long chn = strtol(pStr, &pE, 10);
	if (pE == NULL || pE == pStr || chn < 1 || chn > tiChnCount || (*pE != 'm' && *pE != 's'))
	{
		printf("%s:%d trt__GetStreamUri->ProfileToken = %s\n", __func__, __LINE__, trt__GetStreamUri->ProfileToken);
		return SOAP_FAULT;
	}

	uint8_t mac[6] = {0};
	char ip[16] = {0}, mask[16] = {0};
	GetSockMacAndIp(&mac, &ip, &mask, soap->master, false);

	trt__GetStreamUriResponse->MediaUri = (struct tt__MediaUri *)soap_malloc(soap, sizeof(struct tt__MediaUri));
	memset(trt__GetStreamUriResponse->MediaUri, 0, sizeof(struct tt__MediaUri));
	trt__GetStreamUriResponse->MediaUri->Uri = (char *)soap_malloc(soap, 64);
	sprintf(trt__GetStreamUriResponse->MediaUri->Uri, "rtsp://%s:554/chn%ld%c", ip, chn, *pE);
	trt__GetStreamUriResponse->MediaUri->InvalidAfterConnect = (enum xsd__boolean)0;  
	trt__GetStreamUriResponse->MediaUri->InvalidAfterReboot	= (enum xsd__boolean)0;  
	trt__GetStreamUriResponse->MediaUri->Timeout = 200;	

	return SOAP_OK;
}

// 中间有省略

static pid_t gettid(void)
{
	return syscall(__NR_gettid);
}

static int GetMACAndIp(uint8_t (*pMAC)[6], char (*pIP)[16], char (*pMask)[16], const char *pNIC)
{
	memset(pMAC, 0, sizeof(*pMAC));
	memset(pIP, 0, sizeof(*pIP));

	int sockFD = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFD < 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		return -1;
	}
	struct ifreq ifr = {{{0}}};
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFHWADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}

	memcpy(pMAC, ifr.ifr_hwaddr.sa_data, sizeof(*pMAC));
	//uint8_t *pC = (uint8_t *)pMAC;
	//printf("%s:%s:%d mac = %02X:%02X:%02X:%02X:%02X:%02X\n", __FILE__, __func__, __LINE__, pC[0], pC[1], pC[2], pC[3], pC[4], pC[5]);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFADDR, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pIP, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr), sizeof(*pIP) - 1);
	//printf("%s:%s:%d ip = %s\n", __FILE__, __func__, __LINE__, (char *)pIP);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pNIC, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sockFD, SIOCGIFNETMASK, &ifr) != 0)
	{
		printf("%s:%s:%d pNIC = %s, errno = %d, means: %s\n", __FILE__, __func__, __LINE__, pNIC, errno, strerror(errno));
		close(sockFD);
		return -1;
	}
	strncpy((char *)pMask, inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr), sizeof(*pMask) - 1);
	//printf("%s:%s:%d mask = %s\n", __FILE__, __func__, __LINE__, (char *)pMask);

	close(sockFD);
	return 0;
}

static int SetMuticastOpt(struct soap *pSoap, const char *pIp)		// 设置组播选项
{
	const unsigned char cEnable = 1;
	if (setsockopt(pSoap->master, IPPROTO_IP, IP_MULTICAST_LOOP, &cEnable, sizeof(cEnable)) != 0)
	{
		printf("%s:%s:%d errno = %d, means: %s\n", __FILE__, __func__, __LINE__, errno, strerror(errno));
		return -1;
	}

	struct ip_mreq mreq = {{0}};
	mreq.imr_multiaddr.s_addr = inet_addr("239.255.255.250");
	mreq.imr_interface.s_addr = inet_addr(pIp);//htonl(INADDR_ANY);
	if (setsockopt(pSoap->master, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0)
	{
		printf("%s:%s:%d errno = %d, means: %s\n", __FILE__, __func__, __LINE__, errno, strerror(errno));
		return -1;
	}

	return 0;
}

static SOAP_SOCKET SoapBind(struct soap *pSoap, const char *pIp, _Bool bUdp)
{
	SOAP_SOCKET sockFD = SOAP_INVALID_SOCKET;
	if (bUdp)
	{
		sockFD = soap_bind(pSoap, "239.255.255.250", pSoap->port, 100);
		if (soap_valid_socket(sockFD))
		{
			printf("%s:%s:%d bUdp = %d, sockFD = %d, pSoap->master = %d\n", __FILE__, __func__, __LINE__, bUdp, sockFD, pSoap->master);
			if (SetMuticastOpt(pSoap, pIp) != 0)
			{
				soap_closesocket(sockFD);
				sockFD = SOAP_INVALID_SOCKET;
			}
		}
		else
		{
			printf("%s:%s:%d bUdp = %d\n", __FILE__, __func__, __LINE__, bUdp);
			soap_print_fault(pSoap, stderr);
		}
	}
	else
	{
		sockFD = soap_bind(pSoap, pIp, pSoap->port, 100);
		if (soap_valid_socket(sockFD))
			printf("%s:%s:%d bUdp = %d, sockFD = %d, pSoap->master = %d\n", __FILE__, __func__, __LINE__, bUdp, sockFD, pSoap->master);
		else
		{
			printf("%s:%s:%d bUdp = %d\n", __FILE__, __func__, __LINE__, bUdp);
			soap_print_fault(pSoap, stderr);
		}
	}

	return sockFD;
}

static void *OnvifBeDiscovered(void *arg)		// 被广播发现
{
	pthread_detach(pthread_self());
	struct OnvifSrvNic *pSrvNic = (struct OnvifSrvNic *)arg;
	pSrvNic->runDisc = true;
	printf("%s:%s:%d tid = %d, nic = %s\n", __FILE__, __func__, __LINE__, gettid(), pSrvNic->nic);
	//sleep(5);	// 等网络稳定了再启动
	struct soap udpSoap = {0};
	soap_init1(&udpSoap, SOAP_IO_UDP|SOAP_IO_FLUSH);
	udpSoap.connect_flags = SO_BROADCAST;
	udpSoap.port = 3702;
	udpSoap.bind_flags = SO_REUSEADDR;
	udpSoap.accept_timeout = udpSoap.recv_timeout = udpSoap.send_timeout = 5;
	soap_set_namespaces(&udpSoap, namespaces);

	uint8_t mac[6] = {0};
	char ip[16] = {0}, mask[16] = {0};
	struct in_addr ia = {0};
	while (pSrvNic->exitThr == false && strlen(pSrvNic->nic) > 0)	// strlen(pSrvNic->nic) < 1应该是异常情况
	{
		if (tbRun)
		{
			if (GetMACAndIp(&mac, &ip, &mask, pSrvNic->nic) == 0)	// MAC/IP地址可能被别的地方修改
			{
				if (memcmp(mac, pSrvNic->mac, sizeof(mac)) != 0 || strcmp(ip, pSrvNic->ip) != 0 || strcmp(mask, pSrvNic->mask) != 0)
				{
					printf("%s:%s:%d nic = %s, mac = %02X:%02X:%02X:%02X:%02X:%02X, ip = %s, mask = %s\n",
							__FILE__, __func__, __LINE__, pSrvNic->nic, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip, mask);
					if (soap_valid_socket(pSrvNic->sockDisc))
					{
						soap_closesocket(pSrvNic->sockDisc);
						pSrvNic->sockDisc = SOAP_INVALID_SOCKET;
					}
					pSrvNic->sockDisc = SoapBind(&udpSoap, ip, true);
					pthread_mutex_lock(&pSrvNic->mutexIp);
					memcpy(pSrvNic->mac, mac, sizeof(pSrvNic->mac));
					strcpy(pSrvNic->ip, ip);
					strcpy(pSrvNic->mask, mask);
					pthread_mutex_unlock(&pSrvNic->mutexIp);
				}
				else if (!soap_valid_socket(pSrvNic->sockDisc) && strlen(pSrvNic->ip) > 0)
				{
					printf("%s:%s:%d nic = %s, mac = %02X:%02X:%02X:%02X:%02X:%02X, ip = %s, mask = %s\n",
							__FILE__, __func__, __LINE__, pSrvNic->nic, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip, mask);
					pSrvNic->sockDisc = SoapBind(&udpSoap, ip, true);
				}
			}
			else
			{
				memset(mac, 0, sizeof(mac));
				memset(ip, 0, sizeof(ip));
				memset(mask, 0, sizeof(mask));
				if (soap_valid_socket(pSrvNic->sockDisc))
				{
					soap_closesocket(pSrvNic->sockDisc);
					pSrvNic->sockDisc = SOAP_INVALID_SOCKET;
				}
			}

			if (!soap_valid_socket(pSrvNic->sockDisc))
				sleep(4);
			else
			{
				if (soap_serve(&udpSoap) == 0)
				{
					ia.s_addr = htonl(udpSoap.ip);
					printf("%s:%s:%d connect from %s, udpSoap.master = %d, socket = %d\n", __FILE__, __func__, __LINE__, inet_ntoa(ia), udpSoap.master, udpSoap.socket);
				}
				soap_destroy(&udpSoap);
				soap_end(&udpSoap);
			}
		}
		else
		{
			if (soap_valid_socket(pSrvNic->sockDisc))
			{
				soap_closesocket(pSrvNic->sockDisc);
				pSrvNic->sockDisc = SOAP_INVALID_SOCKET;
			}
			sleep(1);
		}
	}

	soap_end(&udpSoap);
	soap_done(&udpSoap);
	pSrvNic->runDisc = false;
	printf("%s:%s:%d tid = %d exit, nic = %s\n", __FILE__, __func__, __LINE__, gettid(), pSrvNic->nic);
	return NULL;
}

static void *OnvifWebServices(void *arg)
{
	pthread_detach(pthread_self());
	struct OnvifSrvNic *pSrvNic = (struct OnvifSrvNic *)arg;
	pSrvNic->runWebSrv = true;
	printf("%s:%s:%d tid = %d, nic = %s\n", __FILE__, __func__, __LINE__, gettid(), pSrvNic->nic);
	//sleep(5);	// 等网络稳定了再启动

	struct soap tcpSoap = {0};
	soap_init(&tcpSoap);
	tcpSoap.port = 80;
	tcpSoap.bind_flags = SO_REUSEADDR;  
	tcpSoap.accept_timeout = tcpSoap.recv_timeout = tcpSoap.send_timeout = 5;
	soap_set_namespaces(&tcpSoap, namespaces);

	SOAP_SOCKET cliSockFD = SOAP_INVALID_SOCKET;
	struct in_addr ia = {0};
	uint8_t mac[6] = {0};
	char ip[16] = {0}, mask[16] = {0};
	const char *pConnFromIp = NULL;		// 连接来自于ip
	while (pSrvNic->exitThr == false && strlen(pSrvNic->nic) > 0)	// strlen(pSrvNic->nic) < 1应该是异常情况
	{
		if (tbRun)
		{
			pthread_mutex_lock(&pSrvNic->mutexIp);
			if (memcmp(mac, pSrvNic->mac, sizeof(mac)) != 0 || strcmp(ip, pSrvNic->ip) != 0 || strcmp(mask, pSrvNic->mask) != 0)
			{
				printf("%s:%s:%d nic = %s, mac = %02X:%02X:%02X:%02X:%02X:%02X, ip = %s, mask = %s\n",
						__FILE__, __func__, __LINE__, pSrvNic->nic, pSrvNic->mac[0], pSrvNic->mac[1], pSrvNic->mac[2],
						pSrvNic->mac[3], pSrvNic->mac[4], pSrvNic->mac[5], pSrvNic->ip, pSrvNic->mask);
				if (soap_valid_socket(pSrvNic->sockWebSrv))
				{
					soap_closesocket(pSrvNic->sockWebSrv);
					pSrvNic->sockWebSrv = SOAP_INVALID_SOCKET;
				}
				memcpy(mac, pSrvNic->mac, sizeof(mac));
				strcpy(ip, pSrvNic->ip);
				strcpy(mask, pSrvNic->mask);
				pthread_mutex_unlock(&pSrvNic->mutexIp);
				pSrvNic->sockWebSrv = SoapBind(&tcpSoap, ip, false);
			}
			else
			{
				pthread_mutex_unlock(&pSrvNic->mutexIp);
				if (!soap_valid_socket(pSrvNic->sockWebSrv) && strlen(ip) > 0)
				{
					printf("%s:%s:%d nic = %s, mac = %02X:%02X:%02X:%02X:%02X:%02X, ip = %s, mask = %s\n",
							__FILE__, __func__, __LINE__, pSrvNic->nic, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip, mask);
					pSrvNic->sockWebSrv = SoapBind(&tcpSoap, ip, false);
				}
			}

			if (!soap_valid_socket(pSrvNic->sockWebSrv))
				sleep(4);
			else
			{
				cliSockFD = soap_accept(&tcpSoap);
				if (soap_valid_socket(cliSockFD))
				{
					ia.s_addr = htonl(tcpSoap.ip);
					pConnFromIp = inet_ntoa(ia);
					#if 0			// 排除自身，根据需要打开
					if (strcmp(pConnFromIp, ip) != 0)
					#endif
					{
						printf("%s:%s:%d request from %s, tcpSoap.master = %d, socket = %d\n", __FILE__, __func__, __LINE__, pConnFromIp, tcpSoap.master, tcpSoap.socket);
						soap_serve(&tcpSoap);
					}
					soap_destroy(&tcpSoap);
					soap_end(&tcpSoap);
				}
			}
		}
		else
		{
			if (soap_valid_socket(pSrvNic->sockWebSrv))
			{
				soap_closesocket(pSrvNic->sockWebSrv);
				pSrvNic->sockWebSrv = SOAP_INVALID_SOCKET;
			}
			sleep(1);
		}
	}

	soap_end(&tcpSoap);
	soap_done(&tcpSoap);
	pSrvNic->runWebSrv = false;
	printf("%s:%s:%d tid = %d exit, nic = %s\n", __FILE__, __func__, __LINE__, gettid(), pSrvNic->nic);
	return NULL;
}

void OnvifServerInit(uint8_t chnCount)
{
	printf("%s:%d chnCount = %"PRIu8"\n", __func__, __LINE__, chnCount);
	tiChnCount = chnCount;
	for (size_t i = 0; i < sizeof(tSrvNic) / sizeof(tSrvNic[0]); ++i)
	{
		tSrvNic[i].sockDisc = SOAP_INVALID_SOCKET;
		tSrvNic[i].sockWebSrv = SOAP_INVALID_SOCKET;
		pthread_mutex_init(&tSrvNic[i].mutexIp, NULL);
	}
}

int OnvifServerAddNic(const char *pNIC)
{
	printf("%s:%d pNIC = %s\n", __func__, __LINE__, pNIC);
	if (strlen(pNIC) < 1 || strlen(pNIC) + 1 > sizeof(tSrvNic[0].nic))
	{
		printf("%s:%d\n", __func__, __LINE__);
		return -1;
	}

	pthread_mutex_lock(&tMutex);
	for (size_t i = 0; i < sizeof(tSrvNic) / sizeof(tSrvNic[0]); ++i)
	{
		if (strcmp(tSrvNic[i].nic, pNIC) == 0)	// 已经在运行
		{
			printf("%s:%d already running\n", __func__, __LINE__);
			pthread_mutex_unlock(&tMutex);
			return 0;
		}
	}
	for (size_t i = 0; i < sizeof(tSrvNic) / sizeof(tSrvNic[0]); ++i)
	{
		if (strlen(tSrvNic[i].nic) < 1)		// 空的
		{
			printf("%s:%d i = %zu\n", __func__, __LINE__, i);
			strcpy(tSrvNic[i].nic, pNIC);
			pthread_t tid = 0;
			pthread_create(&tid, NULL, OnvifBeDiscovered, &tSrvNic[i]);
			pthread_create(&tid, NULL, OnvifWebServices, &tSrvNic[i]);
			sleep(1);
			while (tSrvNic[i].runDisc == false || tSrvNic[i].runWebSrv == false)
			{
				printf("%s:%d wait thread run\n", __func__, __LINE__);
				sleep(1);
			}
			break;
		}
	}
	pthread_mutex_unlock(&tMutex);
	printf("%s:%d\n", __func__, __LINE__);
	return 0;
}

int OnvifServerRmNic(const char *pNIC)
{
	printf("%s:%d pNIC = %s\n", __func__, __LINE__, pNIC);
	if (strlen(pNIC) < 1 || strlen(pNIC) + 1 > sizeof(tSrvNic[0].nic))
	{
		printf("%s:%d\n", __func__, __LINE__);
		return -1;
	}

	pthread_mutex_lock(&tMutex);
	for (size_t i = 0; i < sizeof(tSrvNic) / sizeof(tSrvNic[0]); ++i)
	{
		if (strcmp(tSrvNic[i].nic, pNIC) == 0)
		{
			printf("%s:%d i = %zu\n", __func__, __LINE__, i);
			tSrvNic[i].exitThr = true;
			sleep(1);
			while (tSrvNic[i].runDisc || tSrvNic[i].runWebSrv)
			{
				printf("%s:%d wait thread exit\n", __func__, __LINE__);
				sleep(1);
			}

			memset(&tSrvNic[i], 0, offsetof(struct OnvifSrvNic, mutexIp));
			tSrvNic[i].sockDisc = SOAP_INVALID_SOCKET;
			tSrvNic[i].sockWebSrv = SOAP_INVALID_SOCKET;
			break;
		}
	}
	pthread_mutex_unlock(&tMutex);
	printf("%s:%d\n", __func__, __LINE__);
	return 0;
}

void OnvifServerRmAllNic(void)
{
	printf("%s:%d\n", __func__, __LINE__);
	pthread_mutex_lock(&tMutex);
	for (size_t i = 0; i < sizeof(tSrvNic) / sizeof(tSrvNic[0]); ++i)
	{
		if (tSrvNic[i].runDisc || tSrvNic[i].runWebSrv)
		{
			printf("%s:%d i = %zu\n", __func__, __LINE__, i);
			tSrvNic[i].exitThr = true;
			sleep(1);
			while (tSrvNic[i].runDisc || tSrvNic[i].runWebSrv)
			{
				printf("%s:%d wait thread exit\n", __func__, __LINE__);
				sleep(1);
			}

			memset(&tSrvNic[i], 0, offsetof(struct OnvifSrvNic, mutexIp));
			tSrvNic[i].sockDisc = SOAP_INVALID_SOCKET;
			tSrvNic[i].sockWebSrv = SOAP_INVALID_SOCKET;
		}
	}
	pthread_mutex_unlock(&tMutex);
	printf("%s:%d\n", __func__, __LINE__);
}

void OnvifServerRun(void)
{
	printf("%s:%d\n", __func__, __LINE__);
	pthread_mutex_lock(&tMutex);
	tbRun = true;
	pthread_mutex_unlock(&tMutex);
}

void OnvifServerPause(void)
{
	printf("%s:%d\n", __func__, __LINE__);
	pthread_mutex_lock(&tMutex);
	tbRun = false;
	pthread_mutex_unlock(&tMutex);
}

