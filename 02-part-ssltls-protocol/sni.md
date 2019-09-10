# 六、SNI

## 一、什么是SNI？

     SNI是Server Name Indication的缩写，是为了解决一个服务器使用多个域名和证书的SSL/TLS扩展。它允许客户端在发起SSL握手请求时（客户端发出ClientHello消息中）提交请求的HostName信息，使得服务器能够切换到正确的域并返回相应的证书。  
     在SNI出现之前，HostName信息只存在于HTTP请求中，但SSL/TLS层无法获知这一信息。通过将HostName的信息加入到SNI扩展中，SSL/TLS允许服务器使用一个IP为不同的域名提供不同的证书，从而能够与使用同一个IP的多个“虚拟主机”更方便地建立安全连接。

## 二、RFC中SNI的定义

     RFC 6066《Transport Layer Security \(TLS\) Extensions: Extension Definitions》对SNI扩展做了详细的定义。要点如下：  
 1\)    Client需要在ClientHello中包含一个名为”server\_name”的扩展，这个扩展的”extension\_data”域中需要包含”ServerNameList”；  
 2\)    ServerNameList中包含了多个HostName及其类型（name\_type），但所有HostName的name\_type不能相同（早期的RFC规范允许一个name\_type多个HostName，但  实际上当前的client实现只发送一个HostName，而且client不一定知道server选择了哪个HostName，因此禁止一个name\_type多个HostName）；  
 3\)    HostName中包含的是server的完全合格的DNS主机名，且HostName中不允许包含IPv4或IPv6地址；  
 4\)    如果server收到的ClientHello中带有”server\_name”扩展，它也应该在ServerHello中包含一个”server\_name”扩展，其中的”extension\_data”域应为空；  
 5\)    当执行会话恢复时，clinet应该在ClientHello中包含与上次会话相同的”server\_name”扩展。如果扩展中包含的name与上次的不同，server必须拒绝恢复会话。恢复会话时server必须不能在ServerHello中包含”server\_name”扩展；  
 6\)    如果一个应用程序使用应用层协议协商了一个server name然后升级到TLS，并且发送了”server\_name”扩展，这个扩展中必须包含与在应用层协议中所协商的相同的server name。如果这个server name成功应用在了TLS会话中，client不应该在应用层尝试请求一个不同的server name。

## 三、OpenSSL（基于OpenSSL-1.1.0f）与SNI

### 3.1 Client设置server\_name扩展

     用户可以通过SSL\_set\_tlsext\_host\_name\(s,name\)函数来设置ClientHello中的Server Name：

```text
246 # define SSL_set_tlsext_host_name(s,name) \
247 SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,(char *)name)
```

```text
1670 long SSL_ctrl(SSL *s, int cmd, long larg, void *parg)
1671 {
1672     long l;
1673
1674     switch (cmd) {
…
1747     default:
1748         return (s->method->ssl_ctrl(s, cmd, larg, parg));
1749     }
1750 }
```

    对于TLS\_client\_method\(\)和TLS\_server\_method\(\)，s-&gt;method-&gt;ssl\_ctrl指向ssl3\_ctrl：

```text
2883 long ssl3_ctrl(SSL *s, int cmd, long larg, void *parg)
2884 {
2885     int ret = 0;
2886
2887     switch (cmd) {
…
2961     case SSL_CTRL_SET_TLSEXT_HOSTNAME:
2962         if (larg == TLSEXT_NAMETYPE_host_name) {
2963             size_t len;
2964
2965             OPENSSL_free(s->tlsext_hostname);
2966             s->tlsext_hostname = NULL;
2967
2968             ret = 1;
2969             if (parg == NULL)
2970                 break;
2971             len = strlen((char *)parg);
2972             if (len == 0 || len > TLSEXT_MAXLEN_host_name) {
2973                 SSLerr(SSL_F_SSL3_CTRL, SSL_R_SSL3_EXT_INVALID_SERVERNAME);
2974                 return 0;
2975             }
2976             if ((s->tlsext_hostname = OPENSSL_strdup((char *)parg)) == NULL) {
2977                 SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
2978                 return 0;
2979             }
2980         } else {
2981             SSLerr(SSL_F_SSL3_CTRL, SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE);
2982             return 0;
2983         }
2984         break;
…
```

    可见SSL\_set\_tlsext\_host\_name\(s,name\)函数最终将name保存到s-&gt;tlsext\_hostname上，在构建ClientHello扩展时将其发送出去：

```text
968 unsigned char *ssl_add_clienthello_tlsext(SSL *s, unsigned char *buf,
969                                           unsigned char *limit, int *al)
970 {
…
1027     if (s->tlsext_hostname != NULL) {
1028         /* Add TLS extension servername to the Client Hello message */
1029         size_t size_str;
1030
1031         /*-
1032          * check for enough space.
1033          * 4 for the servername type and extension length
1034          * 2 for servernamelist length
1035          * 1 for the hostname type
1036          * 2 for hostname length
1037          * + hostname length
1038          */
1039         size_str = strlen(s->tlsext_hostname);
1040         if (CHECKLEN(ret, 9 + size_str, limit))
1041             return NULL;
1042
1043         /* extension type and length */
1044         s2n(TLSEXT_TYPE_server_name, ret);
1045         s2n(size_str + 5, ret);
1046
1047         /* length of servername list */
1048         s2n(size_str + 3, ret);
1049
1050         /* hostname type, length and hostname */
1051         *(ret++) = (unsigned char)TLSEXT_NAMETYPE_host_name;
1052         s2n(size_str, ret);
1053         memcpy(ret, s->tlsext_hostname, size_str);
1054         ret += size_str;
1055     }
…
```

    发送的ClientHello中的扩展信息如图：

![](https://img-blog.csdn.net/20170914133218652?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMTEzMDU3OA==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)

### 3.2 Server设置servername\_callback

     为了根据ClientHello中的servername返回相应的证书以及进行其它相关处理，server需要设置callback函数来完成这些功能：

```text
279 # define SSL_CTX_set_tlsext_servername_callback(ctx, cb) \
280 SSL_CTX_callback_ctrl(ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,(void (*)(void))cb)
```

```text
1882 long SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void))
1883 {
1884     switch (cmd) {
1885     case SSL_CTRL_SET_MSG_CALLBACK:
1886         ctx->msg_callback = (void (*)
1887                              (int write_p, int version, int content_type,
1888                               const void *buf, size_t len, SSL *ssl,
1889                               void *arg))(fp);
1890         return 1;
1891
1892     default:
1893         return (ctx->method->ssl_ctx_callback_ctrl(ctx, cmd, fp));
1894     }
1895 }
```

```text
3488 long ssl3_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void))
3489 {
3490     switch (cmd) {
…
3498     case SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:
3499         ctx->tlsext_servername_callback = (int (*)(SSL *, int *, void *))fp;
3500         break;
…
```

    这里设置的callback函数会在Server处理server\_name扩展时调用。  
     通常server在回调函数被调用时都需要知道ClientHello中包含的Host Name的内容，这可以通过SSL\_get\_servername\(\)函数来实现：

```text
2081 const char *SSL_get_servername(const SSL *s, const int type)
2082 {
2083     if (type != TLSEXT_NAMETYPE_host_name)
2084         return NULL;
2085
2086     return s->session && !s->tlsext_hostname ?
2087         s->session->tlsext_hostname : s->tlsext_hostname;
2088 }
```

### 3.3 Server处理server\_name扩展

     Server在检查ClientHello时，如果发现了”server\_name”扩展则会对其进行解析：

```text
1890 static int ssl_scan_clienthello_tlsext(SSL *s, PACKET *pkt, int *al)
1891 {
…
1986         else if (type == TLSEXT_TYPE_server_name) {
1987             unsigned int servname_type;
1988             PACKET sni, hostname;
1989
1990             if (!PACKET_as_length_prefixed_2(&extension, &sni)
1991                 /* ServerNameList must be at least 1 byte long. */
1992                 || PACKET_remaining(&sni) == 0) {
1993                 return 0;
1994             }
1995
1996             /*
1997              * Although the server_name extension was intended to be
1998              * extensible to new name types, RFC 4366 defined the
1999              * syntax inextensibility and OpenSSL 1.0.x parses it as
2000              * such.
2001              * RFC 6066 corrected the mistake but adding new name types
2002              * is nevertheless no longer feasible, so act as if no other
2003              * SNI types can exist, to simplify parsing.
2004              *
2005              * Also note that the RFC permits only one SNI value per type,
2006              * i.e., we can only have a single hostname.
2007              */
2008             if (!PACKET_get_1(&sni, &servname_type)
2009                 || servname_type != TLSEXT_NAMETYPE_host_name
2010                 || !PACKET_as_length_prefixed_2(&sni, &hostname)) {
2011                 return 0;
2012             }
2013
2014             if (!s->hit) {
2015                 if (PACKET_remaining(&hostname) > TLSEXT_MAXLEN_host_name) {
2016                     *al = TLS1_AD_UNRECOGNIZED_NAME;
2017                     return 0;
2018                 }
2019
2020                 if (PACKET_contains_zero_byte(&hostname)) {
2021                     *al = TLS1_AD_UNRECOGNIZED_NAME;
2022                     return 0;
2023                 }
2024
2025                 if (!PACKET_strndup(&hostname, &s->session->tlsext_hostname)) {
2026                     *al = TLS1_AD_INTERNAL_ERROR;
2027                     return 0;
2028                 }
2029
2030                 s->servername_done = 1;
2031             } else {
2032                 /*
2033                  * TODO(openssl-team): if the SNI doesn't match, we MUST
2034                  * fall back to a full handshake.
2035                  */
2036                 s->servername_done = s->session->tlsext_hostname
2037                     && PACKET_equal(&hostname, s->session->tlsext_hostname,
2038                                     strlen(s->session->tlsext_hostname));
2039             }
2040         }
…
```

    2009行：OpenSSL中的Server Name Type只有TLSEXT\_NAMETYPE\_host\_name一种。  
     2014-2039：如果不是出于会话恢复过程中，则将hostname解析到s-&gt;session-&gt;tlsext\_hostname；否则对比扩展中的hostname和上次保存的hostname，不一致则发起全新的握手（不允许恢复会话）。  
     在解析完server\_name扩展之后，OpenSSL会在ssl\_check\_clienthello\_tlsext\_early\(\)函数中调用server设置的回调函数：

```text
2319 int ssl_parse_clienthello_tlsext(SSL *s, PACKET *pkt)
2320 {
2321     int al = -1;         
2322     custom_ext_init(&s->cert->srv_ext);
2323     if (ssl_scan_clienthello_tlsext(s, pkt, &al) <= 0) {
2324         ssl3_send_alert(s, SSL3_AL_FATAL, al);
2325         return 0;        
2326     }
2327     if (ssl_check_clienthello_tlsext_early(s) <= 0) {
2328         SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT, SSL_R_CLIENTHELLO_TLSEXT);
2329         return 0;
2330     }
2331     return 1;
2332 }
```

```text
2670 static int ssl_check_clienthello_tlsext_early(SSL *s)
2671 {
2672     int ret = SSL_TLSEXT_ERR_NOACK;
2673     int al = SSL_AD_UNRECOGNIZED_NAME;
2674
2675 #ifndef OPENSSL_NO_EC
2676     /*
2677      * The handling of the ECPointFormats extension is done elsewhere, namely
2678      * in ssl3_choose_cipher in s3_lib.c.
2679      */
2680     /*
2681      * The handling of the EllipticCurves extension is done elsewhere, namely
2682      * in ssl3_choose_cipher in s3_lib.c.
2683      */
2684 #endif
2685
2686     if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
2687         ret =
2688             s->ctx->tlsext_servername_callback(s, &al,
2689                                          s->ctx->tlsext_servername_arg);
2690     else if (s->session_ctx != NULL
2691              && s->session_ctx->tlsext_servername_callback != 0)
2692         ret =
2693             s->session_ctx->tlsext_servername_callback(s, &al,
2694                                          s->
2695                                          session_ctx->tlsext_servername_arg);
2696
2697     switch (ret) {
2698     case SSL_TLSEXT_ERR_ALERT_FATAL:
2699         ssl3_send_alert(s, SSL3_AL_FATAL, al);
2700         return -1;
2701
2702     case SSL_TLSEXT_ERR_ALERT_WARNING:
2703         ssl3_send_alert(s, SSL3_AL_WARNING, al);
2704         return 1;
2705
2706     case SSL_TLSEXT_ERR_NOACK:
2707         s->servername_done = 0;
2708     default:
2709         return 1;
2710     }
2711 }
```

    如果call\_back函数返回的是SSL\_TLSEXT\_ERR\_OK，则OpenSSL会在ServerHello中添加一个内容为空的server\_name扩展：

```text
1449 unsigned char *ssl_add_serverhello_tlsext(SSL *s, unsigned char *buf,
1450                                           unsigned char *limit, int *al)
1451 {
…
1500     if (!s->hit && s->servername_done == 1
1501         && s->session->tlsext_hostname != NULL) {
1502         /*-
1503          * check for enough space.
1504          * 4 bytes for the server name type and extension length
1505          */
1506         if (CHECKLEN(ret, 4, limit))
1507             return NULL;
1508
1509         s2n(TLSEXT_TYPE_server_name, ret);
1510         s2n(0, ret);
1511     }
…
```

    发送的样式如下图所示：  
![](https://img-blog.csdn.net/20170914133354117?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMTEzMDU3OA==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)

### 3.4 Client处理server\_name扩展

     Client在处理ServerHello中如果发现了server\_name扩展，则会检查自己之前是否发送过这个扩展。如果发送过则将扩展的名字记录在会话中：

```text
2354 static int ssl_scan_serverhello_tlsext(SSL *s, PACKET *pkt, int *al)
2355 {
2356     unsigned int length, type, size;
2357     int tlsext_servername = 0;
…
2405         } else if (type == TLSEXT_TYPE_server_name) {
2406             if (s->tlsext_hostname == NULL || size > 0) {
2407                 *al = TLS1_AD_UNRECOGNIZED_NAME;
2408                 return 0;
2409             }
2410             tlsext_servername = 1;
2411         }
…
2610     if (!s->hit && tlsext_servername == 1) {
2611         if (s->tlsext_hostname) {
2612             if (s->session->tlsext_hostname == NULL) {
2613                 s->session->tlsext_hostname =
2614                     OPENSSL_strdup(s->tlsext_hostname);
2615                 if (!s->session->tlsext_hostname) {
2616                     *al = SSL_AD_UNRECOGNIZED_NAME;
2617                     return 0;
2618                 }
2619             } else {
2620                 *al = SSL_AD_DECODE_ERROR;
2621                 return 0;
2622             }
2623         }
2624     }
…
```

### 3.5 总结

    综上，对于OpenSSL的SNI扩展，client端的处理主要是通过SSL\_set\_tlsext\_host\_name\(s, name\)函数将Host Name的信息添加到Client扩展中，这样就可以在SSL/TLS层使得server或者Host Name信息。

    Server对SNI功能的支持就要复杂一些：它需要注册一个回调函数，在回调函数中调用SSL\_get\_servername\(\)函数获取Host Name，再处理Host Name与证书的绑定关系等。这个部分是SNI的核心功能，需要由OpenSSL的用户来实现。  


    此外，OpenSSL还会在会话恢复过程中检查Host Name的一致性，如果不一致则不允许恢复会话，必须重新发起handshake。  


## 四、Nginx与SNI

### 4.1 检查SNI功能

     执行nginx –V。如果输出的信息中有“TLS SNI support enabled”，则证明nginx支持SNI。

### 4.2 配置

#### 4.2.1 Nginx作为server

     Nginx通过server命令配置多个virtual server，并通过server\_name命令区分不同的Server Name，对应加载不同的SSL配置：

```text
server {
    listen       443 ssl;
    server_name  servername1.net;

    #charset koi8-r;
    #access_log  /var/log/nginx/host.access.log  main;
    ssl_protocols       TLSv1.2;
    ssl_ciphers         AES128-SHA:AES256-SHA:RC4-SHA:DES-CBC3-SHA:RC4-MD5;
    ssl_verify_depth 1;
    ssl_certificate     /root/server1.cer;
    ssl_certificate_key /root/server1.key; 
    …
}
server {
  listen       443 ssl;
  server_name  servername2.net;

  #charset koi8-r;
  #access_log  /var/log/nginx/host.access.log  main;
  ssl_protocols       TLSv1.2;
  ssl_ciphers         AES128-SHA:AES256-SHA:RC4-SHA:DES-CBC3-SHA:RC4-MD5;
  ssl_verify_depth 1;
  ssl_certificate     /root/server2.cer;
     ssl_certificate_key /root/server2.key;
     …
}
```

    如果client访问servername1.net，server会返回server1.cer证书；如果访问servername2.net，则返回server2.cer证书。这样的配置允许client访问相同的IP但使用不同的域名，server会根据域名的不同返回相应的证书。  
     Client的应用程序应该将域名信息添加到ClientHello的server\_name扩展中才能使得server支持SNI功能。  
     注：配置文件中ssl\_certificate所指向的证书中CN必须与server\_name所配置的域名完全一致。

#### 4.2.2 Nginx作为client

     Nginx的proxy模式可以使nginx与后端SSL server建立SSL连接，这时nginx作为ssl client可以使用SNI功能。配置举例：

```text
upstream servername2.net {
    server 192.168.135.128:447;
}

server {
    listen       8081;

    ssl_protocols       TLSv1.2;
    proxy_ssl_server_name on;
proxy_ssl_verify on;
#proxy_ssl_name servername1.net;
    proxy_ssl_trusted_certificate /home/remy/ca-server.cer;

    ssl_ciphers         AES128-SHA:AES256-SHA:RC4-SHA:DES-CBC3-SHA:RC4-MD5;
    location / {
        proxy_pass https://servername2.net;
    }
}
```

    其中的关键配置是“proxy\_ssl\_server\_name on”、“proxy\_pass https://servername2.net”和“upstream servername2.net”相关配置。其中upstream的名字必须与server的域名一致（即4.2.1中的server\_name命令所配置的域名）。也可以使用proxy\_ssl\_name命令设置server name，这个设置会替代proxy\_pass中的host name被填入到ClientHello的server\_name扩展中。

### 4.3 代码分析（基于nginx-1.12.1）

#### 4.3.1 Nginx作为server

     Nginx在解析server\_name命令时使用ngx\_http\_core\_server\_name\(\)函数将所有的server\_name保存到队列中：

```text
4297 static char *
4298 ngx_http_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
4299 {
4300     ngx_http_core_srv_conf_t *cscf = conf;
4301    
4302     u_char                   ch;
4303     ngx_str_t               *value;
4304     ngx_uint_t               i;
4305     ngx_http_server_name_t  *sn;
…
4327         sn = ngx_array_push(&cscf->server_names);
…
4335         sn->server = cscf;
4336
4337         if (ngx_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
4338             sn->name = cf->cycle->hostname;
4339
4340         } else {
4341             sn->name = value[i];
4342         }
…
4349 #if (NGX_PCRE)  
4350         {
4351         u_char               *p;
4352         ngx_regex_compile_t   rc;
4353         u_char                errstr[NGX_MAX_CONF_ERRSTR];
4354
4355         if (value[i].len == 1) {
4356             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
4357                                "empty regex in server name \"%V\"", &value[i]);
4358             return NGX_CONF_ERROR;
4359         }
4360
4361         value[i].len--;
4362         value[i].data++;
4363
4364         ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
4365
4366         rc.pattern = value[i];
4367         rc.err.len = NGX_MAX_CONF_ERRSTR;
4368         rc.err.data = errstr;
4369
4370         for (p = value[i].data; p < value[i].data + value[i].len; p++) {
4371             if (*p >= 'A' && *p <= 'Z') {
4372                 rc.options = NGX_REGEX_CASELESS;
4373                 break;
4374             }
4375         }
4376
4377         sn->regex = ngx_http_regex_compile(cf, &rc);
4378         if (sn->regex == NULL) {
4379             return NGX_CONF_ERROR;
4380         }
4381
4382         sn->name = value[i];
4383         cscf->captures = (rc.captures > 0);
4384         }
4385 #else
…
```

    这样一个server\_name就会通过cscf的server\_names成员与一个cscf关联，而一个cscf会与一个CTX关联（从而可以与一个server证书关联）。详见下文。  
     在merge config时，nginx会调用SSL\_CTX\_set\_tlsext\_servername\_callback\(\)函数设置回调：

```text
562 static char *
563 ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
564 {
…
671     if (ngx_ssl_create(&conf->ssl, conf->protocols, conf) != NGX_OK) {
672         return NGX_CONF_ERROR;
673     }
674
675 #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
676
677     if (SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
678                                                ngx_http_ssl_servername)
679         == 0)
680     {
681         ngx_log_error(NGX_LOG_WARN, cf->log, 0,
682             "nginx was built with SNI support, however, now it is linked "
683             "dynamically to an OpenSSL library which has no tlsext support, "
684             "therefore SNI is not available");
685     }
686
687 #endif
…
706     if (ngx_ssl_certificates(cf, &conf->ssl, conf->certificates,
707                              conf->certificate_keys, conf->passwords)
708         != NGX_OK)
709     {
710         return NGX_CONF_ERROR;
711     }
…
```

    671：为当前的ngx\_http\_ssl\_srv\_conf\_t配置创建CTX结构并进行设置；

    706：将证书载入到CTX结构中。

    在解析server指令下listen指令所配置的端口时，nginx会执行如下操作：

```text
1790 static ngx_int_t
1791 ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
1792     ngx_http_conf_addr_t *addr)    
1793 {
1794     ngx_uint_t                 i;  
1795     ngx_http_in_addr_t        *addrs;
1796     struct sockaddr_in        *sin;
1797     ngx_http_virtual_names_t  *vn;
1798
1799     hport->addrs = ngx_pcalloc(cf->pool,
1800                                hport->naddrs * sizeof(ngx_http_in_addr_t));
1801     if (hport->addrs == NULL) {    
1802         return NGX_ERROR;
1803     }
1804
1805     addrs = hport->addrs;
1806
1807     for (i = 0; i < hport->naddrs; i++) {
…
1833         vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
1834         if (vn == NULL) {
1835             return NGX_ERROR;
1836         }
1837
1838         addrs[i].conf.virtual_names = vn;
1839
1840         vn->names.hash = addr[i].hash;
1841         vn->names.wc_head = addr[i].wc_head;
1842         vn->names.wc_tail = addr[i].wc_tail;
1843 #if (NGX_PCRE)
1844         vn->nregex = addr[i].nregex;
1845         vn->regex = addr[i].regex;
1846 #endif
1847     }
1848
1849     return NGX_OK;
1850 }
```

    这样addrs\[i\].conf.virtual\_names就与addr\[i\].hash、addr\[i\].wc\_head、addr\[i\].wc\_tail关联起来。对于4.2.1中的配置（两个server block，端口一样，server\_name不同），i为0。  
     在解析http block的最后，nginx会调用ngx\_http\_optimize\_servers\(\)函数优化端口和server name列表：

```text
1379 static ngx_int_t
1380 ngx_http_optimize_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
1381     ngx_array_t *ports)
1382 {
1383     ngx_uint_t             p, a;
1384     ngx_http_conf_port_t  *port;
1385     ngx_http_conf_addr_t  *addr;
1386
1387     if (ports == NULL) {
1388         return NGX_OK;
1389     }
1390
1391     port = ports->elts;
1392     for (p = 0; p < ports->nelts; p++) {
1393     
1394         ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
1395                  sizeof(ngx_http_conf_addr_t), ngx_http_cmp_conf_addrs);
1396                  
1397         /*
1398          * check whether all name-based servers have the same
1399          * configuration as a default server for given address:port
1400          */
1401
1402         addr = port[p].addrs.elts;
1403         for (a = 0; a < port[p].addrs.nelts; a++) {
1404
1405             if (addr[a].servers.nelts > 1
1406 #if (NGX_PCRE)
1407                 || addr[a].default_server->captures
1408 #endif          
1409                )
1410             {
1411                 if (ngx_http_server_names(cf, cmcf, &addr[a]) != NGX_OK) {
1412                     return NGX_ERROR;
1413                 }
1414             }
1415         }
…
```

    1411：ngx\_http\_server\_names\(\)函数优化serve name列表：

```text
1426 static ngx_int_t
1427 ngx_http_server_names(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
1428     ngx_http_conf_addr_t *addr)
1429 {
1430     ngx_int_t                   rc;
1431     ngx_uint_t                  n, s;
1432     ngx_hash_init_t             hash;
1433     ngx_hash_keys_arrays_t      ha;
1434     ngx_http_server_name_t     *name;
1435     ngx_http_core_srv_conf_t  **cscfp;
1436 #if (NGX_PCRE)
1437     ngx_uint_t                  regex, i;
1438
1439     regex = 0;
1440 #endif
…
1451     if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
1452         goto failed;
1453     }
1454
1455     cscfp = addr->servers.elts;
1456
1457     for (s = 0; s < addr->servers.nelts; s++) {
1458
1459         name = cscfp[s]->server_names.elts;
1460
1461         for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
1462
1463 #if (NGX_PCRE)
1464             if (name[n].regex) {
1465                 regex++;
1466                 continue;
1467             }
1468 #endif
1469
1470             rc = ngx_hash_add_key(&ha, &name[n].name, name[n].server,
1471                                   NGX_HASH_WILDCARD_KEY);
…
1492     hash.key = ngx_hash_key_lc;    
1493     hash.max_size = cmcf->server_names_hash_max_size;
1494     hash.bucket_size = cmcf->server_names_hash_bucket_size;
1495     hash.name = "server_names_hash";
1496     hash.pool = cf->pool;
1497
1498     if (ha.keys.nelts) {
1499         hash.hash = &addr->hash;       
1500         hash.temp_pool = NULL;
1501
1502         if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
1503             goto failed;
1504         }
1505     }
…
1545 #if (NGX_PCRE)
1546
1547     if (regex == 0) {    
1548         return NGX_OK;   
1549     }
1550
1551     addr->nregex = regex;
1552     addr->regex = ngx_palloc(cf->pool, regex * sizeof(ngx_http_server_name_t));                                                                                                                        
1553     if (addr->regex == NULL) {
1554         return NGX_ERROR;
1555     }
1556
1557     i = 0;
1558
1559     for (s = 0; s < addr->servers.nelts; s++) {                                                                                                                                                        
1560
1561         name = cscfp[s]->server_names.elts;                                                                                                                                                            
1562
1563         for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
1564             if (name[n].regex) {               
1565                 addr->regex[i++] = name[n];
1566             }
1567         }
1568     }
1569
1570 #endif
1571
1572     return NGX_OK;
…
```

    1451-1471：将所有的server name全部加入到ha hash队列中；  
     1492-1504：将ha hash队列与addr-&gt;hash相关联（addr与一个IP\|port对一一对应），从而与前面提到的addrs\[i\].conf.virtual\_names关联起来；  
     1551-1568：将所有server name的正则表达式信息全部添加到addr-&gt;regex数组中。  
     至此，server name的配置文件解析工作全部完成，接下来需要在nginx处理ClientHello的SNI回调函数中利用上述关联关系实现server name与SSL配置（证书等）的绑定。  
     SSL\_CTX\_set\_tlsext\_servername\_callback\(\)函数所设置的ngx\_http\_ssl\_servername\(\)函数会作为回调完成Server Name匹配的相关核心工作：

```text
825 int
826 ngx_http_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
827 {
828     ngx_str_t                  host;
829     const char                *servername;
830     ngx_connection_t          *c;
831     ngx_http_connection_t     *hc;
832     ngx_http_ssl_srv_conf_t   *sscf;
833     ngx_http_core_loc_conf_t  *clcf;
834     ngx_http_core_srv_conf_t  *cscf;
835
836     servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);
…
842     c = ngx_ssl_get_connection(ssl_conn);
…

851     host.len = ngx_strlen(servername);
 852
 853     if (host.len == 0) {
 854         return SSL_TLSEXT_ERR_NOACK;
 855     }
 856
 857     host.data = (u_char *) servername;
…
863     hc = c->data;
864
865     if (ngx_http_find_virtual_server(c, hc->addr_conf->virtual_names, &host,
 866                                      NULL, &cscf)
 867         != NGX_OK)
 868     {
 869         return SSL_TLSEXT_ERR_NOACK;
 870     }
…
885     sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module);
…
889     if (sscf->ssl.ctx) {
 890         SSL_set_SSL_CTX(ssl_conn, sscf->ssl.ctx);
 891  
 892         /*
 893          * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
 894          * adjust other things we care about
 895          */
 896
 897         SSL_set_verify(ssl_conn, SSL_CTX_get_verify_mode(sscf->ssl.ctx),
 898                        SSL_CTX_get_verify_callback(sscf->ssl.ctx));
 899
 900         SSL_set_verify_depth(ssl_conn, SSL_CTX_get_verify_depth(sscf->ssl.ctx));
 901
 902 #ifdef SSL_CTRL_CLEAR_OPTIONS
 903         /* only in 0.9.8m+ */
 904         SSL_clear_options(ssl_conn, SSL_get_options(ssl_conn) &
 905                                     ~SSL_CTX_get_options(sscf->ssl.ctx));
 906 #endif
 907
 908         SSL_set_options(ssl_conn, SSL_CTX_get_options(sscf->ssl.ctx));
 909     }
…
```

    836：从ClientHello的server\_name扩展中获取server name；  
     851-857：将serve name记录在host中；  
     865：通过与IP\|port绑定的addr\_conf的virtual\_names成员和host关键字找到与server name对应的配置文件指针cscf；  
     885-909：找到与cscf相关联的CTX结构体指针，将其与ssl结构关联，后续在发送证书时就会使用server name对应的CTX所载入的证书。  
     我们不妨来看看ngx\_http\_find\_virtual\_server\(\)函数是如何查找server name对应的配置的：

```text
2101 static ngx_int_t
2102 ngx_http_find_virtual_server(ngx_connection_t *c,
2103     ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
2104     ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp)                                                                                                                                           
2105 {
2106     ngx_http_core_srv_conf_t  *cscf;                                                                                                                                                                   
2107
2108     if (virtual_names == NULL) {       
2109         return NGX_DECLINED;
2110     }
2111
2112     cscf = ngx_hash_find_combined(&virtual_names->names,         
2113                                   ngx_hash_key(host->data, host->len),
2114                                   host->data, host->len);                                                                                                                                              
2115
2116     if (cscf) {
2117         *cscfp = cscf;
2118         return NGX_OK;
2119     }
2120
2121 #if (NGX_PCRE)
2122
2123     if (host->len && virtual_names->nregex) {
2124         ngx_int_t                n;    
2125         ngx_uint_t               i;    
2126         ngx_http_server_name_t  *sn;                                                                                                                                                                   
2127
2128         sn = virtual_names->regex;                                                                                                                                                                     
2129
2130 #if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)                                                                                                                                             
2131
2132         if (r == NULL) {
2133             ngx_http_connection_t  *hc;                                                                                                                                                                
2134
2135             for (i = 0; i < virtual_names->nregex; i++) {                                                                                                                                              
2136
2137                 n = ngx_regex_exec(sn[i].regex->regex, host, NULL, 0);                                                                                                                                 
2138
2139                 if (n == NGX_REGEX_NO_MATCHED) {   
2140                     continue;
2141                 }
2142
2143                 if (n >= 0) {
2144                     hc = c->data;                  
2145                     hc->ssl_servername_regex = sn[i].regex;                                                                                                                                            
2146
2147                     *cscfp = sn[i].server;         
2148                     return NGX_OK;             
2149                 }
2150
2151                 ngx_log_error(NGX_LOG_ALERT, c->log, 0,      
2152                               ngx_regex_exec_n " failed: %i "
2153                               "on \"%V\" using \"%V\"",      
2154                               n, host, &sn[i].regex->name);                                                                                                                                            
2155
2156                 return NGX_ERROR;
2157             }
2158
2159             return NGX_DECLINED;
2160         }
…
```

    2112-2119：ngx\_hash\_find\_combined\(\)函数在virtual\_names-&gt;names.hash（即addr-&gt;hash）中保存的全部serve name的列表中根据server name关键字来查询cscf：

```text
210 void *
211 ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key, u_char *name,
212     size_t len)
213 {                   
214     void  *value;
215
216     if (hash->hash.buckets) {
217         value = ngx_hash_find(&hash->hash, key, name, len);
218
219         if (value) {
220             return value;
221         }
222     }
…
```

    2123-2149：如果上述流程没有查询到，则遍历virtual\_names-&gt;regex（即addr-&gt;regex）进行查找。  
     将所有server name信息添加到addr-&gt;hash和addr-&gt;regex队列都是在ngx\_http\_server\_names\(\)函数中完成的，而将virtual\_names-&gt;names.hash与addr-&gt;hash关联、将virtual\_names-&gt;regex与addr-&gt;regex关联是在ngx\_http\_add\_addrs\(\)函数中完成的。  
     Nginx中server name与cscf以及CTX的关联、server name信息添加到addr hash表/队列、virtual server查找等整个过程真心太复杂了！

#### 4.3.2 Nginx作为client

     作为SSL client支持SNI功能，nginx的实现比较简单，就是调用SSL\_set\_tlsext\_host\_name\(\)函数设置host\_name扩展：

```text
1750 static ngx_int_t
1751 ngx_http_upstream_ssl_name(ngx_http_request_t *r, ngx_http_upstream_t *u,
1752     ngx_connection_t *c)
1753 {
1754     u_char     *p, *last;
1755     ngx_str_t   name;
1756
1757     if (u->conf->ssl_name) {
1758         if (ngx_http_complex_value(r, u->conf->ssl_name, &name) != NGX_OK) {
1759             return NGX_ERROR;
1760         }
1761
1762     } else {
1763         name = u->ssl_name;
1764     }
…
1825     if (SSL_set_tlsext_host_name(c->ssl->connection,
1826                                  (char *) name.data)
1827         == 0)
1828     {
1829         ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0,
1830                       "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
1831         return NGX_ERROR;
1832     }
…
```

    1757-1764：如果使用proxy\_ssl\_name命令设置了server name，则优先使用；否则使用host name作为server name；  
     1825-1832：将server name填入ClientHello的server\_name扩展中。

## 五、HAProxy与SNI

### 5.1 配置举例

#### 5.1.1 HAProxy作为server

     HAProxy有两种方式支持SNI：  
 1\)    根据证书的CN名进行匹配；配置如下：

```text
global
    maxconn 100

defaults
    mode http
    timeout connect 5s
    timeout client 5s
    timeout server 5s

frontend myfrontend
    # primary cert is /etc/cert/server.pem
    # /etc/cert/certdir/ contains additional certificates for SNI clients
    bind :446 ssl crt /etc/cert/server.pem crt /etc/cert/certdir/
    default_backend mybackend

backend mybackend
    # a http backend
    server s3 192.168.135.1:80
```

    使用这种方式不需要特殊配置，只要载入证书，HAProxy就会根据证书中的CN名去匹配ClientHello中的server\_name扩展。  
 2\)    为每个证书指定匹配的域名：

```text
global
    maxconn 100

defaults
    mode http
    timeout connect 5s
    timeout client 5s
    timeout server 5s

frontend myfrontend
    bind :446 ssl crt-list /root/cert.list
    default_backend mybackend

backend mybackend
    # a http backend
    server s3 192.168.135.1:80
```

    其中cert.list的格式如下：

```text
/path/to/cert1.pem domain1.com
/path/to/cert2.pem domain2.com
```

    这种方式在需要支持通配符或排除一些域名的情况下比较有用。

#### 5.1.2 HAProxy作为client

     HAProxy可以连接后端的SSL服务器，这时它作为client可以使用sni命令设置SNI：

```text
global
    maxconn 100

defaults
    mode http
    timeout connect 5s
    timeout client 5s
    timeout server 5s

frontend myfrontend
    bind :808
    default_backend mybackend

backend mybackend
    # a https backend
    server s4 192.168.135.128:446 ssl verify none sni str(domain1.com)
```

### 5.2 代码分析

#### 5.2.1 HAProxy作为server

**5.2.1.1 基于证书的CN名**

     HAProxy在解析crt命令时会调用bind\_parse\_crt\(\)函数：

```text
5207 /* parse the "crt" bind keyword */
5208 static int bind_parse_crt(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
5209 {
…
5217     if ((*args[cur_arg + 1] != '/' ) && global.crt_base) {
5218         if ((strlen(global.crt_base) + 1 + strlen(args[cur_arg + 1]) + 1) > MAXPATHLEN) {
5219             memprintf(err, "'%s' : path too long", args[cur_arg]);
5220             return ERR_ALERT | ERR_FATAL;
5221         }
5222         snprintf(path, sizeof(path), "%s/%s",  global.crt_base, args[cur_arg + 1]);
5223         if (ssl_sock_load_cert(path, conf, px, err) > 0)
5224             return ERR_ALERT | ERR_FATAL;
5225
5226         return 0;
5227     }
5228
5229     if (ssl_sock_load_cert(args[cur_arg + 1], conf, px, err) > 0)
5230         return ERR_ALERT | ERR_FATAL;
5231
5232     return 0;
5233 }
```

    其中的关键函数是ssl\_sock\_load\_cert\(\)函数：

```text
2452 int ssl_sock_load_cert(char *path, struct bind_conf *bind_conf, struct proxy *curproxy, char **err)
2453 {
…
2466     if (stat(path, &buf) == 0) {
2467         dir = opendir(path);
2468         if (!dir)
2469             return ssl_sock_load_cert_file(path, bind_conf, curproxy, NULL, 0, err);
…
2475         n = scandir(path, &de_list, 0, alphasort);
2476         if (n < 0) {
2477             memprintf(err, "%sunable to scan directory '%s' : %s.\n",
2478                       err && *err ? *err : "", path, strerror(errno));
2479             cfgerr++;
2480         }
2481         else {
2482             for (i = 0; i < n; i++) {
2483                 struct dirent *de = de_list[i];
2484
2485                 end = strrchr(de->d_name, '.');
2486               if (end && (!strcmp(end, ".issuer") || !strcmp(end, ".ocsp") || !strcmp(end, ".sctl")))
2487                     goto ignore_entry;
2488                     
2489                 snprintf(fp, sizeof(fp), "%s/%s", path, de->d_name);
…
2499 #if OPENSSL_VERSION_NUMBER >= 0x1000200fL
2500                 is_bundle = 0;
2501                 /* Check if current entry in directory is part of a multi-cert bundle */
2502                 
2503                 if (end) {
2504                     for (j = 0; j < SSL_SOCK_NUM_KEYTYPES; j++) {
2505                         if (!strcmp(end + 1, SSL_SOCK_KEYTYPE_NAMES[j])) {
2506                             is_bundle = 1;
2507                             break;
2508                         }   
2509                     }   
2510                     
2511                     if (is_bundle) {
2512                         char dp[MAXPATHLEN+1] = {0}; /* this will be the filename w/o the keytype */
2513                         int dp_len;
2514
2515                         dp_len = end - de->d_name;
2516                         snprintf(dp, dp_len + 1, "%s", de->d_name);
2517
2518                         /* increment i and free de until we get to a non-bundle cert
2519                          * Note here that we look at de_list[i + 1] before freeing de
2520                          * this is important since ignore_entry will free de
2521                          */
2522                         while (i + 1 < n && !strncmp(de_list[i + 1]->d_name, dp, dp_len)) {
2523                             free(de);
2524                             i++;
2525                             de = de_list[i];
2526                         }
2527
2528                         snprintf(fp, sizeof(fp), "%s/%s", path, dp);
2529                         ssl_sock_load_multi_cert(fp, bind_conf, curproxy, NULL, 0, err);
2530
2531                         /* Successfully processed the bundle */
2532                         goto ignore_entry;
2533                     }
2534                 }
2535
2536 #endif
2537                 cfgerr += ssl_sock_load_cert_file(fp, bind_conf, curproxy, NULL, 0, err);
…
```

    2466-2469：如果路径可访问，且指定的是文件而非目录，则调用ssl\_sock\_load\_cert\_file\(\)函数加载证书；  
     2500-2534：如果文件的后缀名为.dsa，.ecdsa，.rsa，则调用ssl\_sock\_load\_multi\_cert\(\)函数将这些文件批量载入；  
     2537: 如果文件无上述后缀，则调用ssl\_sock\_load\_cert\_file\(\)逐个加载目录中所有的证书文件。  
     2547：如果路径不能正常访问，则调用ssl\_sock\_load\_multi\_cert \(\)函数将以这个路径名为名、以.dsa，.ecdsa，.rsa为后缀的所有文件批量载入。

```text
2364 static int ssl_sock_load_cert_file(const char *path, struct bind_conf *bind_conf, struct proxy *curproxy, char **sni_filter, int fcount, char **err)
2365 {
2366     int ret;
2367     SSL_CTX *ctx;
2368
2369     ctx = SSL_CTX_new(SSLv23_server_method());
…
2376     if (SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM) <= 0) {
2377         memprintf(err, "%sunable to load SSL private key from PEM file '%s'.\n",
2378                   err && *err ? *err : "", path);
2379         SSL_CTX_free(ctx);
2380         return 1;
2381     }
2382
2383     ret = ssl_sock_load_cert_chain_file(ctx, path, bind_conf, sni_filter, fcount);
…
```

    此函数为每个证书文件创建一个CTX，加载私钥文件，再调用ssl\_sock\_load\_cert\_chain\_file\(\)函数加载证书：

```text
2262 static int ssl_sock_load_cert_chain_file(SSL_CTX *ctx, const char *file, struct bind_conf *s, char **sni_filter, int fcount)
2263 {
…
2289     x = PEM_read_bio_X509_AUX(in, NULL, passwd_cb, passwd_cb_userdata);
2290     if (x == NULL)
2291         goto end;
2292
2293     if (fcount) {
2294         while (fcount--)
2295             order = ssl_sock_add_cert_sni(ctx, s, sni_filter[fcount], order);
2296     }
2297     else {
2298 #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
2299         names = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
2300         if (names) {
2301             for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
2302                 GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
2303                 if (name->type == GEN_DNS) {
2304                     if (ASN1_STRING_to_UTF8((unsigned char **)&str, name->d.dNSName) >= 0) {
2305                         order = ssl_sock_add_cert_sni(ctx, s, str, order);
2306                         OPENSSL_free(str);
2307                     }
2308                 }
2309             }
2310             sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
2311         }
2312 #endif /* SSL_CTRL_SET_TLSEXT_HOSTNAME */
2313         xname = X509_get_subject_name(x);
2314         i = -1;
2315         while ((i = X509_NAME_get_index_by_NID(xname, NID_commonName, i)) != -1) {
2316             X509_NAME_ENTRY *entry = X509_NAME_get_entry(xname, i);
2317             ASN1_STRING *value;
2318
2319             value = X509_NAME_ENTRY_get_data(entry);
2320             if (ASN1_STRING_to_UTF8((unsigned char **)&str, value) >= 0) {
2321                 order = ssl_sock_add_cert_sni(ctx, s, str, order);
2322                 OPENSSL_free(str);
2323             }
2324         }
2325     }
2326
2327     ret = 0; /* the caller must not free the SSL_CTX argument anymore */
2328     if (!SSL_CTX_use_certificate(ctx, x))
2329         goto end;
…
```

    2289：读取证书文件；  
     2293-2295：根据证书列表加载证书；对于crt命令这个逻辑不会执行；  
     2299-2310：根据证书中的Subject Alternative Name \(SAN\)设置SNI；SAN允许一个证书关联多个域名；  
     2313-2325：根据证书中的CN设置SNI；设置SNI的功能由ssl\_sock\_add\_cert\_sni\(\)函数完成：

```text
1746 static int ssl_sock_add_cert_sni(SSL_CTX *ctx, struct bind_conf *s, char *name, int order)
1747 {   
1748     struct sni_ctx *sc;
1749     int wild = 0, neg = 0;
1750     struct ebmb_node *node;
1751     
1752     if (*name == '!') {
1753         neg = 1;
1754         name++;
1755     }
1756     if (*name == '*') {
1757         wild = 1;
1758         name++;
1759     }
1760     /* !* filter is a nop */
1761     if (neg && wild)
1762         return order;
1763     if (*name) {
1764         int j, len;
1765         len = strlen(name);
1766         for (j = 0; j < len && j < trash.size; j++)
1767             trash.str[j] = tolower(name[j]);
1768         if (j >= trash.size)
1769             return order;
1770         trash.str[j] = 0;
1771         
1772         /* Check for duplicates. */
1773         if (wild)
1774             node = ebst_lookup(&s->sni_w_ctx, trash.str);
1775         else
1776             node = ebst_lookup(&s->sni_ctx, trash.str);
1777         for (; node; node = ebmb_next_dup(node)) {
1778             sc = ebmb_entry(node, struct sni_ctx, name);
1779             if (sc->ctx == ctx && sc->neg == neg)
1780                 return order;
1781         }
1782
1783         sc = malloc(sizeof(struct sni_ctx) + len + 1);
1784         if (!sc)
1785             return order;
1786         memcpy(sc->name.key, trash.str, len + 1);
1787         sc->ctx = ctx;
1788         sc->order = order++;
1789         sc->neg = neg;
1790         if (wild)
1791             ebst_insert(&s->sni_w_ctx, &sc->name);
1792         else
1793             ebst_insert(&s->sni_ctx, &sc->name);
1794     }
1795     return order;
1796 }
```

    这个函数的功能是将与域名关联的sni\_ctx结构加入到一棵以s-&gt;sni\_ctx（域名不包含通配符）或s-&gt;sni\_w\_ctx（域名包含通配符）的Elastic Binary树中。由于s是全局的，故树也是全局的。  
     在后续流程中检查配置的合法性时，HAProxy会调用ssl\_sock\_prepare\_all\_ctx\(\)函数初始化证书相关的配置：

```text
3192 /* Walks down the two trees in bind_conf and prepares all certs. The pointer may
3193  * be NULL, in which case nothing is done. Returns the number of errors
3194  * encountered.
3195  */
3196 int ssl_sock_prepare_all_ctx(struct bind_conf *bind_conf, struct proxy *px)
3197 {
3198     struct ebmb_node *node;
3199     struct sni_ctx *sni;
3200     int err = 0;
3201
3202     if (!bind_conf || !bind_conf->is_ssl)
3203         return 0;
3204
3205     /* Automatic memory computations need to know we use SSL there */
3206     global.ssl_used_frontend = 1;
3207
3208     if (bind_conf->default_ctx)
3209         err += ssl_sock_prepare_ctx(bind_conf, bind_conf->default_ctx, px);
3210
3211     node = ebmb_first(&bind_conf->sni_ctx);
3212     while (node) {
3213         sni = ebmb_entry(node, struct sni_ctx, name);
3214         if (!sni->order && sni->ctx != bind_conf->default_ctx)
3215             /* only initialize the CTX on its first occurrence and
3216                if it is not the default_ctx */
3217             err += ssl_sock_prepare_ctx(bind_conf, sni->ctx, px);
3218         node = ebmb_next(node);
3219     }
3220
3221     node = ebmb_first(&bind_conf->sni_w_ctx);
3222     while (node) {
3223         sni = ebmb_entry(node, struct sni_ctx, name);
3224         if (!sni->order && sni->ctx != bind_conf->default_ctx)
3225             /* only initialize the CTX on its first occurrence and
3226                if it is not the default_ctx */
3227             err += ssl_sock_prepare_ctx(bind_conf, sni->ctx, px);
3228         node = ebmb_next(node);
3229     }
3230     return err;
3231 }
```

    这个函数会遍历conf-&gt;sni\_ctx和bind\_conf-&gt;sni\_w\_ctx这两棵树，并调用ssl\_sock\_prepare\_ctx\(\)初始化其中的所有节点：

```text
2682 int ssl_sock_prepare_ctx(struct bind_conf *bind_conf, SSL_CTX *ctx, struct proxy *curproxy)
2683 {
…
2882 #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
2883     SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
…
```

    SSL\_CTX\_set\_tlsext\_servername\_callback\(\)函数所设置的回调函数ssl\_sock\_switchctx\_cbk\(\)用于处理ClientHello中的server\_name扩展：

```text
1405 static int ssl_sock_switchctx_cbk(SSL *ssl, int *al, struct bind_conf *s)
1406 {
1407     const char *servername;
1408     const char *wildp = NULL;
1409     struct ebmb_node *node, *n;
1410     int i;
1411     (void)al; /* shut gcc stupid warning */
1412
1413     servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
…
1446     /* lookup in full qualified names */
1447     node = ebst_lookup(&s->sni_ctx, trash.str);
1448
1449     /* lookup a not neg filter */
1450     for (n = node; n; n = ebmb_next_dup(n)) {
1451         if (!container_of(n, struct sni_ctx, name)->neg) {
1452             node = n;
1453             break;
1454         }
1455     }
1456     if (!node && wildp) {
1457         /* lookup in wildcards names */
1458         node = ebst_lookup(&s->sni_w_ctx, wildp);
1459     }
…
1472     /* switch ctx */
1473     SSL_set_SSL_CTX(ssl, container_of(node, struct sni_ctx, name)->ctx);
1474     return SSL_TLSEXT_ERR_OK;
1475 }
```

    1413：从ClientHello中获取server name；  
     1447-1458：先从s-&gt;sni\_ctx查找加载证书时保存的节点，如果查不到则在s-&gt;sni\_w\_ctx中查找；  
     1473：将当前ssl结构与加载了和server name对应的证书的CTX结构相关联，以实现后续功能（发送对应的证书等）。

**5.2.1.2 基于配置文件指定的域名**

     HAProxy解析crt\_list命令的函数是ssl\_sock\_load\_cert\_list\_file\(\)：

```text
2568 int ssl_sock_load_cert_list_file(char *file, struct bind_conf *bind_conf, struct proxy *curproxy, char **err)
2569 {
2570     char thisline[LINESIZE*CRTLIST_FACTOR];
2571     FILE *f;
2572     struct stat buf;
2573     int linenum = 0;
2574     int cfgerr = 0;
2575
2576     if ((f = fopen(file, "r")) == NULL) {
2577         memprintf(err, "cannot open file '%s' : %s", file, strerror(errno));
2578         return 1;
2579     }
2580
2581     while (fgets(thisline, sizeof(thisline), f) != NULL) {
2582         int arg;
2583         int newarg;
2584         char *end;
2585         char *args[MAX_LINE_ARGS*CRTLIST_FACTOR + 1];
2586         char *line = thisline;
…
2601         newarg = 1;
2602         while (*line) {
2603             if (*line == '#' || *line == '\n' || *line == '\r') {
2604                 /* end of string, end of loop */
2605                 *line = 0;
2606                 break;
2607             }
2608             else if (isspace(*line)) {
2609                 newarg = 1;
2610                 *line = 0;
2611             }
2612             else if (newarg) {
2613                 if (arg == MAX_LINE_ARGS*CRTLIST_FACTOR) {
2614                     memprintf(err, "too many args on line %d in file '%s'.",
2615                           linenum, file);
2616                     cfgerr = 1;
2617                     break;
2618                 }
2619                 newarg = 0;
2620                 args[arg++] = line;
2621             }
2622             line++;
2623         }
…
2631         if (stat(args[0], &buf) == 0) {
2632             cfgerr = ssl_sock_load_cert_file(args[0], bind_conf, curproxy, &args[1], arg-1, err);
2633         } else {
2634             cfgerr = ssl_sock_load_multi_cert(args[0], bind_conf, curproxy, &args[1], arg-1, err);
2635         }
…
```

    2581-2623：逐行解析list文件，将每行的参数放置在args数组中；  
     2631-2632：如果路径名可以访问，则调用ssl\_sock\_load\_cert\_file\(\)函数解析证书文件，并传入server name及其数量。这样当ssl\_sock\_load\_cert\_file\(\)函数调到ssl\_sock\_load\_cert\_chain\_file\(\)函数时就会执行如下语句：

```text
2262 static int ssl_sock_load_cert_chain_file(SSL_CTX *ctx, const char *file, struct bind_conf *s, char **sni_filter, int fcount)
2263 {
…
2293     if (fcount) {
2294         while (fcount--)
2295             order = ssl_sock_add_cert_sni(ctx, s, sni_filter[fcount], order);
2296     }
…
```

    2293-2295：将所有的server name（域名）与证书（及其CTX）的关联关系加入到全局Elastic Binary树中，这样就允许一个证书与多个域名相关联。  
     2634：如果路径名不能访问，则调用ssl\_sock\_load\_multi\_cert \(\)函数将以这个路径名为名、以.dsa，.ecdsa，.rsa为后缀的所有文件批量载入。

```text
2032 /* Given a path that does not exist, try to check for path.rsa, path.dsa and path.ecdsa files.
2033  * If any are found, group these files into a set of SSL_CTX*
2034  * based on shared and unique CN and SAN entries. Add these SSL_CTX* to the SNI tree.
2035  *
2036  * This will allow the user to explictly group multiple cert/keys for a single purpose
2037  *
2038  * Returns
2039  *     0 on success
2040  *     1 on failure
2041  */
2042 static int ssl_sock_load_multi_cert(const char *path, struct bind_conf *bind_conf, struct proxy *curproxy, char **sni_filter, int fcount, char **err)
2043 {
2044     char fp[MAXPATHLEN+1] = {0};
2045     int n = 0;
2046     int i = 0;
2047     struct cert_key_and_chain certs_and_keys[SSL_SOCK_NUM_KEYTYPES] = { {0} };
2048     struct eb_root sni_keytypes_map = { {0} };
2049     struct ebmb_node *node;
2050     struct ebmb_node *next;
2051     /* Array of SSL_CTX pointers corresponding to each possible combo
2052      * of keytypes
2053      */
2054     struct key_combo_ctx key_combos[SSL_SOCK_POSSIBLE_KT_COMBOS] = { {0} };
2055     int rv = 0;
2056     X509_NAME *xname = NULL;
2057     char *str = NULL;
2058 #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
2059     STACK_OF(GENERAL_NAME) *names = NULL;
2060 #endif
2061
2062     /* Load all possible certs and keys */
2063     for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++) {
2064         struct stat buf;
2065
2066         snprintf(fp, sizeof(fp), "%s.%s", path, SSL_SOCK_KEYTYPE_NAMES[n]);
2067         if (stat(fp, &buf) == 0) {
2068             if (ssl_sock_load_crt_file_into_ckch(fp, &certs_and_keys[n], err) == 1) {
2069                 rv = 1;
2070                 goto end;
2071             }
2072         }
2073     }
…
2081     for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++) {
2082
2083         if (!ssl_sock_is_ckch_valid(&certs_and_keys[n]))
2084             continue;
2085
2086         if (fcount) {
2087             for (i = 0; i < fcount; i++)
2088                 ssl_sock_populate_sni_keytypes_hplr(sni_filter[i], &sni_keytypes_map, n);
2089         } else {
2090             /* A lot of the following code is OpenSSL boilerplate for processing CN's and SAN's,
2091              * so the line that contains logic is marked via comments
2092              */
2093             xname = X509_get_subject_name(certs_and_keys[n].cert);
2094             i = -1;
2095             while ((i = X509_NAME_get_index_by_NID(xname, NID_commonName, i)) != -1) {
2096                 X509_NAME_ENTRY *entry = X509_NAME_get_entry(xname, i);
2097                 ASN1_STRING *value;
2098                 value = X509_NAME_ENTRY_get_data(entry);
2099                 if (ASN1_STRING_to_UTF8((unsigned char **)&str, value) >= 0) {
2100                     /* Important line is here */
2101                     ssl_sock_populate_sni_keytypes_hplr(str, &sni_keytypes_map, n);
2102
2103                     OPENSSL_free(str);
2104                     str = NULL;
2105                 }
2106             }
2107
2108             /* Do the above logic for each SAN */
2109 #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
2110             names = X509_get_ext_d2i(certs_and_keys[n].cert, NID_subject_alt_name, NULL, NULL);
2111             if (names) {
2112                 for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
2113                     GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
2114
2115                     if (name->type == GEN_DNS) {
2116                         if (ASN1_STRING_to_UTF8((unsigned char **)&str, name->d.dNSName) >= 0) {
2117                             /* Important line is here */
2118                             ssl_sock_populate_sni_keytypes_hplr(str, &sni_keytypes_map, n);
2119
2120                             OPENSSL_free(str);
2121                             str = NULL;
2122                         }
2123                     }
2124                 }
2125             }
2126         }
2127 #endif /* SSL_CTRL_SET_TLSEXT_HOSTNAME */
2128     }
…
2152     node = ebmb_first(&sni_keytypes_map);
2153     while (node) {
2154         SSL_CTX *cur_ctx;
2155         char cur_file[MAXPATHLEN+1];
2156
2157         str = (char *)container_of(node, struct sni_keytype, name)->name.key;
2158         i = container_of(node, struct sni_keytype, name)->keytypes;
2159         cur_ctx = key_combos[i-1].ctx;
2160
2161         if (cur_ctx == NULL) {
2162             /* need to create SSL_CTX */
2163             cur_ctx = SSL_CTX_new(SSLv23_server_method());
2164             if (cur_ctx == NULL) {
2165                 memprintf(err, "%sunable to allocate SSL context.\n",
2166                           err && *err ? *err : "");
2167                 rv = 1;
2168                 goto end;
2169             }
…
2170
2171             /* Load all required certs/keys/chains/OCSPs info into SSL_CTX */
2172             for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++) {
2173                 if (i & (1<<n)) {
2174                     /* Key combo contains ckch[n] */
2175                     snprintf(cur_file, MAXPATHLEN+1, "%s.%s", path, SSL_SOCK_KEYTYPE_NAMES[n]);
2176                     if (ssl_sock_put_ckch_into_ctx(cur_file, &certs_and_keys[n], cur_ctx, err) != 0) {
2177                         SSL_CTX_free(cur_ctx);
2178                         rv = 1;
2179                         goto end;
2180                     }
2181
2182 #if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
2183                     /* Load OCSP Info into context */
2184                     if (ssl_sock_load_ocsp(cur_ctx, cur_file) < 0) {
2185                         if (err)
2186                             memprintf(err, "%s '%s.ocsp' is present and activates OCSP but it is impossible to compute the OCSP certificate ID (maybe the issuer could not be found)'.\n",
2187                                       *err ? *err : "", cur_file);
2188                         SSL_CTX_free(cur_ctx);
2189                         rv = 1;
2190                         goto end;
2191                     }
2192 #endif
2193                 }
2194             }
…
2211             /* Update key_combos */
2212             key_combos[i-1].ctx = cur_ctx;
2213         }
2214
2215         /* Update SNI Tree */
2216         key_combos[i-1].order = ssl_sock_add_cert_sni(cur_ctx, bind_conf, str, key_combos[i-1].order);
2217         node = ebmb_next(node);
2218     }
…
```

    2063-2073：将所有证书\|私钥载入到certs\_and\_keys数组中；  
     2081-2127：遍历所有类型的证书\(.rsa，.dsa，.ecdsa\)，将其所有的域名加入到入到sni\_keytypes\_map结构中。其中2087-2088行是将证书列表文件指定的域名加入到sni\_keytypes\_map结构中，2093-2126是将证书中的CN名和SAN名入到sni\_keytypes\_map结构中。相同的名称会拥有相同的节点，每个节点都会有自己的keytypes数值（即证书类型组合）。多个域名可能会拥有相同的keytpes值。  
     2152-2218：遍历sni\_keytypes\_map的所有节点，根据节点中的keytypes数值（即证书类型组合）查找或创建CTX，将拥有相同类型组合的证书和私钥载入到CTX中（2172-2194），最后调用ssl\_sock\_add\_cert\_sni\(\)将域名与CTX绑定关系加入到全局Elastic Binary树中。  
     ssl\_sock\_load\_multi\_cert\(\)函数可以将拥有相同CN名或SAN名的证书加载到同一个CTX中，这样就能支持client端在访问同一个域名时通过不同的cipher suite来选择不同类型的证书（RSA，ECDSA）。但当前版本的HAProxy（haproxy-1.7.9）尚不支持多类型证书的证书链模式。

#### 5.2.2 HAProxy作为client

     HAProxy通过backend指令中的sni指令来实现作为client时对SNI的设置，这个指令的解析函数为：

```text
5831 /* parse the "sni" server keyword */
5832 static int srv_parse_sni(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
5833 {
5834 #ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
5835     memprintf(err, "'%s' : the current SSL library doesn't support the SNI TLS extension", args[*cur_arg]);                                                                                            
5836     return ERR_ALERT | ERR_FATAL;
5837 #else
5838     int idx;
5839     struct sample_expr *expr;
5840
5841     if (!*args[*cur_arg + 1]) {        
5842         memprintf(err, "'%s' : missing sni expression", args[*cur_arg]);                                                                                                                               
5843         return ERR_ALERT | ERR_FATAL;      
5844     }
5845
5846     idx = (*cur_arg) + 1;
5847     px->conf.args.ctx = ARGC_SRV;      
5848
5849     expr = sample_parse_expr((char **)args, &idx, px->conf.file, px->conf.line, err, &px->conf.args);                                                                                                  
5850     if (!expr) {
5851         memprintf(err, "error detected while parsing sni expression : %s", *err);
5852         return ERR_ALERT | ERR_FATAL;
5853     }
5854
5855     if (!(expr->fetch->val & SMP_VAL_BE_SRV_CON)) {
5856         memprintf(err, "error detected while parsing sni expression : "
5857                   " fetch method '%s' extracts information from '%s', none of which is available here.\n",                                                                                             
5858                   args[idx-1], sample_src_names(expr->fetch->use));
5859         return ERR_ALERT | ERR_FATAL;  
5860     }
5861
5862     px->http_needed |= !!(expr->fetch->use & SMP_USE_HTTP_ANY);
5863     newsrv->ssl_ctx.sni = expr;    
5864     return 0;
5865 #endif
5866 }
```

    解析的结果转换为表达式保存在struct server结果的ssl\_ctx.sni成员中。在连接sever时使用：

```text
1029 int connect_server(struct stream *s)
1030 {
1031     struct connection *cli_conn;   
1032     struct connection *srv_conn;   
1033     struct connection *old_conn;   
1034     struct server *srv;
1035     int reuse = 0;
1036     int err;
…
1207 #ifdef USE_OPENSSL
1208         if (srv->ssl_ctx.sni) {
1209             struct sample *smp;
1210             int rewind;
1211
1212             /* Tricky case : we have already scheduled the pending
1213              * HTTP request or TCP data for leaving. So in HTTP we
1214              * rewind exactly the headers, otherwise we rewind the
1215              * output data.
1216              */
1217             rewind = s->txn ? http_hdr_rewind(&s->txn->req) : s->req.buf->o;
1218             b_rew(s->req.buf, rewind);
1219
1220             smp = sample_fetch_as_type(s->be, s->sess, s, SMP_OPT_DIR_REQ | SMP_OPT_FINAL, srv->ssl_ctx.sni, SMP_T_STR);
1221
1222             /* restore the pointers */
1223             b_adv(s->req.buf, rewind);
1224
1225             if (smp_make_safe(smp)) {
1226                 ssl_sock_set_servername(srv_conn, smp->data.u.str.str);
1227                 srv_conn->flags |= CO_FL_PRIVATE;
1228             }
1229         }
1230 #endif /* USE_OPENSSL */
…
```

    1208-1229：将srv-&gt;ssl\_ctx.sni中的表达式转换为字符串保存在smp-&gt;data.u.str.str中，然后调用ssl\_sock\_set\_servername\(\)函数设置server name：

```text
4158 void ssl_sock_set_servername(struct connection *conn, const char *hostname)
4159 {
4160 #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
4161     char *prev_name;
4162     
4163     if (!ssl_sock_is_ssl(conn))
4164         return;
4165                 
4166     /* if the SNI changes, we must destroy the reusable context so that a
4167      * new connection will present a new SNI. As an optimization we could
4168      * later imagine having a small cache of ssl_ctx to hold a few SNI per
4169      * server.
4170      */
4171     prev_name = (char *)SSL_get_servername(conn->xprt_ctx, TLSEXT_NAMETYPE_host_name);
4172     if ((!prev_name && hostname) ||
4173         (prev_name && (!hostname || strcmp(hostname, prev_name) != 0)))
4174         SSL_set_session(conn->xprt_ctx, NULL);
4175
4176     SSL_set_tlsext_host_name(conn->xprt_ctx, hostname);
4177 #endif
4178 }
```

    4176：将hostname设置到ClientHello的server\_name扩展中。  

