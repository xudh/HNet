// 文件太大不上传，要修改
SOAP_FMAC3 int SOAP_FMAC4 soap_out_SOAP_ENV__Header(struct soap *soap, const char *tag, int id, const struct SOAP_ENV__Header *a, const char *type)
{
	// 省略...
	soap->mustUnderstand = 0;	// 改成0，否则Onvif Device Test Tool不能识别这项，导致整体不能识别
	if (soap_out_PointerTo_wsse__Security(soap, "wsse:Security", -1, &a->wsse__Security, ""))
		return soap->error;
	return soap_element_end_out(soap, tag);
}

