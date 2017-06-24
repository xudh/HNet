// 文件太大不上传，需要修改
soap_s2byte(struct soap *soap, const char *s, char *p)
{ if (s)
  { long n;
    char *r;
    n = soap_strtol(s, &r, 10);
    if (/*s == r || *r || */n < -128 || n > 127)	// 注释掉一点，否则空字符会异常
      soap->error = SOAP_TYPE;
    *p = (char)n;
  }
  return soap->error;
}

