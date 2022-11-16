# Chapter 8 Session reuse

## 8.1 Sample Code

TLS1.3 session reuse:

```c
    len = SSL_read(ssl, buffer, sizeof(buffer));
    if (len > 0 && strcmp(buffer, DV_TEST_RESP) == 0) {
        printf("Client接收消息成功:'%s',共%d 个字节的数据\n",
                buffer, len);
    } else {
        printf("Client消息接收失败!错误代码是%d,错误信息是'%s', len = %d\n",
                errno, strerror(errno), len);
        ret = DV_ERROR;
        goto out;
    }

    sess = SSL_get1_session(ssl);
    if (sess == NULL) {
        ERR_print_errors_fp(stderr);
	goto out;
    }
    SSL_SESSION_get0_ticket(sess, &tick, &tick_len);
    printf("tick len = %d\n", (int)tick_len);
    printf("ticket = %d\n", SSL_SESSION_has_ticket(sess));

    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");
    printf("address created\n");
    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)dest, sizeof(*dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");
    ssl = SSL_new(ctx);
    SSL_set_session(ssl, sess);

    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

```

Client使用session reuse的方法是把Session结构体保存下来，设置到下一次的SSL连接上。

## 8.2 Client Side

### 8.2.1 Session初始化

```c
1093 int tls_construct_client_hello(SSL *s, WPACKET *pkt)
1094 {
1095     unsigned char *p;
1096     size_t sess_id_len;
1097     int i, protverr;
1098 #ifndef OPENSSL_NO_COMP
1099     SSL_COMP *comp;
1100 #endif
1101     SSL_SESSION *sess = s->session;
1102     unsigned char *session_id;
...
1110 
1111     if (sess == NULL
1112             || !ssl_version_supported(s, sess->ssl_version, NULL)
1113             || !SSL_SESSION_is_resumable(sess)) {
1114         if (s->hello_retry_request == SSL_HRR_NONE
1115                 && !ssl_get_new_session(s, 0)) {
1116             /* SSLfatal() already called */
1117             return 0;
1118         }
1119     }
...
1186     /* Session ID */
1187     session_id = s->session->session_id;
1188     if (s->new_session || s->session->ssl_version == TLS1_3_VERSION) {
1189         if (s->version == TLS1_3_VERSION
1190                 && (s->options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0) {
1191             sess_id_len = sizeof(s->tmp_session_id);
1192             s->tmp_session_id_len = sess_id_len;
1193             session_id = s->tmp_session_id;
1194             if (s->hello_retry_request == SSL_HRR_NONE
1195                     && RAND_bytes_ex(s->ctx->libctx, s->tmp_session_id,
1196                                      sess_id_len, 0) <= 0) {
1197                 SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
1198                 return 0;
1199             }
1200         } else {
1201             sess_id_len = 0;
1202         }
1203     } else {
1204         assert(s->session->session_id_length <= sizeof(s->session->session_id));
1205         sess_id_len = s->session->session_id_length;
1206         if (s->version == TLS1_3_VERSION) {
1207             s->tmp_session_id_len = sess_id_len;
1208             memcpy(s->tmp_session_id, s->session->session_id, sess_id_len);
1209         }
1210     }
1211     if (!WPACKET_start_sub_packet_u8(pkt)
1212             || (sess_id_len != 0 && !WPACKET_memcpy(pkt, session_id,
1213                                                     sess_id_len))
1214             || !WPACKET_close(pkt)) {
1215         SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
1216         return 0;
1217     }
...
```

1111-1117: 如果没有设置session或session不能重用，则调用ssl\_get\_new\_session()申请一个;

1187-1218: 在ClientHello中写入Session ID字段.

```c
 424 int ssl_get_new_session(SSL *s, int session)
 425 {
 426     /* This gets used by clients and servers. */
 427             
 428     SSL_SESSION *ss = NULL;
 429         
 430     if ((ss = SSL_SESSION_new()) == NULL) {
 431         SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
 432         return 0;
 433     } 
 434 
 435     /* If the context has a default timeout, use it */
 436     if (s->session_ctx->session_timeout == 0)
 437         ss->timeout = SSL_get_default_timeout(s);
 438     else
 439         ss->timeout = s->session_ctx->session_timeout;
 440     ssl_session_calculate_timeout(ss);
 441         
 442     SSL_SESSION_free(s->session);
 443     s->session = NULL;
 444 
 445     if (session) {
 446         if (SSL_IS_TLS13(s)) {
 447             /*
 448              * We generate the session id while constructing the
 449              * NewSessionTicket in TLSv1.3.
 450              */
 451             ss->session_id_length = 0;
 452         } else if (!ssl_generate_session_id(s, ss)) {
 453             /* SSLfatal() already called */
 454             SSL_SESSION_free(ss);
 455             return 0;
 456         }
 457 
 458     } else {
 459         ss->session_id_length = 0;
 460     }
 461 
 462     if (s->sid_ctx_length > sizeof(ss->sid_ctx)) {
 463         SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
 464         SSL_SESSION_free(ss);
 465         return 0;
 466     }
 467     memcpy(ss->sid_ctx, s->sid_ctx, s->sid_ctx_length);
 468     ss->sid_ctx_length = s->sid_ctx_length;
 469     s->session = ss;
 470     ss->ssl_version = s->version;
 471     ss->verify_result = X509_V_OK;
 472 
 473     /* If client supports extended master secret set it in session */
 474     if (s->s3.flags & TLS1_FLAGS_RECEIVED_EXTMS)
 475         ss->flags |= SSL_SESS_FLAG_EXTMS;
 476 
 477     return 1;
 478 }
```

436-439: 设置session timeout值；如果s->session\_ctx->session\_timeout为0则调用SSL\_get\_default\_timeout()来设置;

```c
1762 long SSL_get_default_timeout(const SSL *s)
1763 {
1764     return s->method->get_timeout();
1765 }
```

s->session\_ctx实际上指向的是ctx, 在ctx里面session\_timeout的值也是有初始化的：

```c
3201 SSL_CTX *SSL_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq,
3202                         const SSL_METHOD *meth)
3203 {
...
3246     ret->method = meth;
...
3250     ret->session_cache_mode = SSL_SESS_CACHE_SERVER;
3251     ret->session_cache_size = SSL_SESSION_CACHE_MAX_SIZE_DEFAULT;
3252     /* We take the system default. */
3253     ret->session_timeout = meth->get_timeout();
```

meth->get\_timeout指向tls1\_default\_timeout:

```c
2240 # define IMPLEMENT_tls_meth_func(version, flags, mask, func_name, s_accept, \
2241                                  s_connect, enc_data) \
2242 const SSL_METHOD *func_name(void)  \
2243         { \
2244         static const SSL_METHOD func_name##_data= { \
2245                 version, \
2246                 flags, \
2247                 mask, \
2248                 tls1_new, \
2249                 tls1_clear, \
2250                 tls1_free, \
2251                 s_accept, \
2252                 s_connect, \
2253                 ssl3_read, \
2254                 ssl3_peek, \
2255                 ssl3_write, \
2256                 ssl3_shutdown, \
2257                 ssl3_renegotiate, \
2258                 ssl3_renegotiate_check, \
2259                 ssl3_read_bytes, \
2260                 ssl3_write_bytes, \
2261                 ssl3_dispatch_alert, \
2262                 ssl3_ctrl, \
2263                 ssl3_ctx_ctrl, \
2264                 ssl3_get_cipher_by_char, \
2265                 ssl3_put_cipher_by_char, \
2266                 ssl3_pending, \
2267                 ssl3_num_ciphers, \
2268                 ssl3_get_cipher, \
2269                 tls1_default_timeout, \
2270                 &enc_data, \
2271                 ssl_undefined_void_function, \
2272                 ssl3_callback_ctrl, \
2273                 ssl3_ctx_callback_ctrl, \
2274         }; \
2275         return &func_name##_data; \
2276         }
```

tls1\_default\_timeout()定义：

```c
 101 long tls1_default_timeout(void)
 102 {
 103     /*
 104      * 2 hours, the 24 hours mentioned in the TLSv1 spec is way too long for
 105      * http, the cache would over fill
 106      */
 107     return (60 * 60 * 2);
 108 }
```

可以看出session的默认timeout值是2 hours.

### 8.2.2 Session Ticket

如果使用session ticket, client需要在ClientHello的Extension中写入session中的ticket:

```c
 254 EXT_RETURN tls_construct_ctos_session_ticket(SSL *s, WPACKET *pkt,          
 255                                              unsigned int context, X509 *x, 
 256                                              size_t chainidx)                                                                                                                                          
 257 {
 258     size_t ticklen;
 259 
 260     if (!tls_use_ticket(s))
 261         return EXT_RETURN_NOT_SENT;                                                                                                                                                                    
 262 
 263     if (!s->new_session && s->session != NULL 
 264             && s->session->ext.tick != NULL
 265             && s->session->ssl_version != TLS1_3_VERSION) {
 266         ticklen = s->session->ext.ticklen;
 267     } else if (s->session && s->ext.session_ticket != NULL
 268                && s->ext.session_ticket->data != NULL) {
 269         ticklen = s->ext.session_ticket->length;
 270         s->session->ext.tick = OPENSSL_malloc(ticklen);
 271         if (s->session->ext.tick == NULL) {
 272             SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);                                                                                                                                  
 273             return EXT_RETURN_FAIL;    
 274         }
 275         memcpy(s->session->ext.tick,          
 276                s->ext.session_ticket->data, ticklen);
 277         s->session->ext.ticklen = ticklen;
 278     } else {
 279         ticklen = 0;
 280     }
 281 
 282     if (ticklen == 0 && s->ext.session_ticket != NULL &&
 283             s->ext.session_ticket->data == NULL)
 284         return EXT_RETURN_NOT_SENT;                                                                                                                                                                    
 285 
 286     if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_session_ticket)
 287             || !WPACKET_sub_memcpy_u16(pkt, s->session->ext.tick, ticklen)) {
 288         SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
 289         return EXT_RETURN_FAIL;
 290     }
 291 
 292     return EXT_RETURN_SENT;
 293 }
```

如果session中有ticket，就需要将它写入到extension中。这个ticket是上次handshake结束后server发过来的.

## 8.3 Server Side

