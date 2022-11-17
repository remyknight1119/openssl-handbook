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

## 8.2 Session初始化

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

## 8.3 Session Ticket

Client和Server可以使用Session ticket来恢复session, TLSv1.3可以使用NEW SESSION TICKET+PSK Extension来发送ticket, 其它版本则只能通过NEW SESSION TICKET消息来传递ticket.

Session Ticket消息是由Server端在handshake完成之后发送的:



如果是TLSv1.3 client需要在ClientHello的Extension中写入session中的ticket:

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

```c
2453 MSG_PROCESS_RETURN tls_process_new_session_ticket(SSL *s, PACKET *pkt)                                                                                                                                 
2454 {
2455     unsigned int ticklen;
2456     unsigned long ticket_lifetime_hint, age_add = 0;
2457     unsigned int sess_len;
2458     RAW_EXTENSION *exts = NULL;    
2459     PACKET nonce;
2460     EVP_MD *sha256 = NULL;
2461 
2462     PACKET_null_init(&nonce);
2463 
2464     if (!PACKET_get_net_4(pkt, &ticket_lifetime_hint)
2465         || (SSL_IS_TLS13(s)
2466             && (!PACKET_get_net_4(pkt, &age_add)
2467                 || !PACKET_get_length_prefixed_1(pkt, &nonce)))
2468         || !PACKET_get_net_2(pkt, &ticklen)
2469         || (SSL_IS_TLS13(s) ? (ticklen == 0 || PACKET_remaining(pkt) < ticklen)
2470                             : PACKET_remaining(pkt) != ticklen)) {
2471         SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);                                                                                                                                       
2472         goto err;
2473     }
2474 
2475     /*
2476      * Server is allowed to change its mind (in <=TLSv1.2) and send an empty
2477      * ticket. We already checked this TLSv1.3 case above, so it should never                                                                                                                          
2478      * be 0 here in that instance
2479      */
2480     if (ticklen == 0)
2481         return MSG_PROCESS_CONTINUE_READING;                                                                                                                                                           
2482 
2483     /*
2484      * Sessions must be immutable once they go into the session cache. Otherwise
2485      * we can get multi-thread problems. Therefore we don't "update" sessions,
2486      * we replace them with a duplicate. In TLSv1.3 we need to do this every
2487      * time a NewSessionTicket arrives because those messages arrive
2488      * post-handshake and the session may have already gone into the session
2489      * cache.
2490      */
2491     if (SSL_IS_TLS13(s) || s->session->session_id_length > 0) {
2492         SSL_SESSION *new_sess;
2493 
2494         /*
2495          * We reused an existing session, so we need to replace it with a new
2496          * one
2497          */
2498         if ((new_sess = ssl_session_dup(s->session, 0)) == 0) {
2499             SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
2500             goto err;
2501         }
2502 
2503         if ((s->session_ctx->session_cache_mode & SSL_SESS_CACHE_CLIENT) != 0
2504                 && !SSL_IS_TLS13(s)) {
2505             /*
2506              * In TLSv1.2 and below the arrival of a new tickets signals that
2507              * any old ticket we were using is now out of date, so we remove the
2508              * old session from the cache. We carry on if this fails
2509              */
2510             SSL_CTX_remove_session(s->session_ctx, s->session);
2511         }
2512 
2513         SSL_SESSION_free(s->session);
2514         s->session = new_sess;
2515     }
2516 
2517     s->session->time = time(NULL);
2518     ssl_session_calculate_timeout(s->session);
2519 
2520     OPENSSL_free(s->session->ext.tick);
2521     s->session->ext.tick = NULL;
2522     s->session->ext.ticklen = 0;
2523 
2524     s->session->ext.tick = OPENSSL_malloc(ticklen);
2525     if (s->session->ext.tick == NULL) {
2526         SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
2527         goto err;
2528     }
2529     if (!PACKET_copy_bytes(pkt, s->session->ext.tick, ticklen)) {
2530         SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
2531         goto err;
2532     }
2533 
2534     s->session->ext.tick_lifetime_hint = ticket_lifetime_hint;
2535     s->session->ext.tick_age_add = age_add;
2536     s->session->ext.ticklen = ticklen;
2537 
2538     if (SSL_IS_TLS13(s)) {
2539         PACKET extpkt;
2540 
2541         if (!PACKET_as_length_prefixed_2(pkt, &extpkt)
2542                 || PACKET_remaining(pkt) != 0) {
2543             SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
2544             goto err;
2545         }
2546 
2547         if (!tls_collect_extensions(s, &extpkt,
2548                                     SSL_EXT_TLS1_3_NEW_SESSION_TICKET, &exts,
2549                                     NULL, 1)
2550                 || !tls_parse_all_extensions(s,
2551                                              SSL_EXT_TLS1_3_NEW_SESSION_TICKET,
2552                                              exts, NULL, 0, 1)) {
2553             /* SSLfatal() already called */
2554             goto err;
2555         }
2556     }
2557 
2558     /*
2559      * There are two ways to detect a resumed ticket session. One is to set
2560      * an appropriate session ID and then the server must return a match in
2561      * ServerHello. This allows the normal client session ID matching to work
2562      * and we know much earlier that the ticket has been accepted. The
2563      * other way is to set zero length session ID when the ticket is
2564      * presented and rely on the handshake to determine session resumption.
2565      * We choose the former approach because this fits in with assumptions
2566      * elsewhere in OpenSSL. The session ID is set to the SHA256 hash of the
2567      * ticket.
2568      */
2569     sha256 = EVP_MD_fetch(s->ctx->libctx, "SHA2-256", s->ctx->propq);
2570     if (sha256 == NULL) {
2571         /* Error is already recorded */
2572         SSLfatal_alert(s, SSL_AD_INTERNAL_ERROR);
2573         goto err;
2574     }
2575     /*
2576      * We use sess_len here because EVP_Digest expects an int
2577      * but s->session->session_id_length is a size_t
2578      */
2579     if (!EVP_Digest(s->session->ext.tick, ticklen,
2580                     s->session->session_id, &sess_len,
2581                     sha256, NULL)) {
2582         SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
2583         goto err;
2584     }
2585     EVP_MD_free(sha256);
2586     sha256 = NULL;
2587     s->session->session_id_length = sess_len;
2588     s->session->not_resumable = 0;
2589 
2590     /* This is a standalone message in TLSv1.3, so there is no more to read */
2591     if (SSL_IS_TLS13(s)) {
2592         const EVP_MD *md = ssl_handshake_md(s);
2593         int hashleni = EVP_MD_get_size(md);
2594         size_t hashlen;
2595         static const unsigned char nonce_label[] = "resumption";
2596 
2597         /* Ensure cast to size_t is safe */
2598         if (!ossl_assert(hashleni >= 0)) {
2599             SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
2600             goto err;
2601         }
2602         hashlen = (size_t)hashleni;
2603 
2604         if (!tls13_hkdf_expand(s, md, s->resumption_master_secret,
2605                                nonce_label,
2606                                sizeof(nonce_label) - 1,
2607                                PACKET_data(&nonce),
2608                                PACKET_remaining(&nonce),
2609                                s->session->master_key,
2610                                hashlen, 1)) {
2611             /* SSLfatal() already called */
2612             goto err;
2613         }
2614         s->session->master_key_length = hashlen;
2615 
2616         OPENSSL_free(exts);
2617         ssl_update_cache(s, SSL_SESS_CACHE_CLIENT);
2618         return MSG_PROCESS_FINISHED_READING;
2619     }
2620 
2621     return MSG_PROCESS_CONTINUE_READING;
2622  err:
2623     EVP_MD_free(sha256);
2624     OPENSSL_free(exts);
2625     return MSG_PROCESS_ERROR;
2626 }
```

2464-2473: 解析NEW\_SESSION\_TICKET消息的各个字段;&#x20;

2491-2515: 如果是TLSv1.3或已经有session在重用，则复制当前的session(除了ticket的部分)到new\_sess, 并用其取代当前session; 如果是TLSv1.2或者更低版本且是CLIENT CACHE模式，则将旧的session移出cache;

2517: 更新session时间，以便检查超时;

2524-2537: 将当前ticket记录到session中;

2538-2556: 如果是TLSv1.3则处理下Early Data Extension;

2526-2584: 使用ticket生成Session ID以便在session resume的过程中让server回应相同的Session ID来表示ticket已经被接受;

2591-2614: 如果是TLSv1.3, 则更新master key;

2617: 更新client cache.



## 8.4 Session Cache

## 8.5 Session Resumption

对于SSL Server来说，TLSv1.3只能用session ticket实现session resume; TLSv1.2及其以下版本则会优先选择ticket, 没有ticket时会使用session cache:

```c
 546 /*-
 547  * ssl_get_prev attempts to find an SSL_SESSION to be used to resume this
 548  * connection. It is only called by servers.
 549  *
 550  *   hello: The parsed ClientHello data
 551  *
 552  * Returns:
 553  *   -1: fatal error
 554  *    0: no session found
 555  *    1: a session may have been found.
 556  *
 557  * Side effects:
 558  *   - If a session is found then s->session is pointed at it (after freeing an
 559  *     existing session if need be) and s->verify_result is set from the session.
 560  *   - Both for new and resumed sessions, s->ext.ticket_expected is set to 1
 561  *     if the server should issue a new session ticket (to 0 otherwise).
 562  */
 563 int ssl_get_prev_session(SSL *s, CLIENTHELLO_MSG *hello)
 564 {
 565     /* This is used only by servers. */
 566
 567     SSL_SESSION *ret = NULL;
 568     int fatal = 0;
 569     int try_session_cache = 0;
 570     SSL_TICKET_STATUS r;
 571
 572     if (SSL_IS_TLS13(s)) {
 573         /*
 574          * By default we will send a new ticket. This can be overridden in the
 575          * ticket processing.
 576          */
 577         s->ext.ticket_expected = 1;
 578         if (!tls_parse_extension(s, TLSEXT_IDX_psk_kex_modes,
 579                                  SSL_EXT_CLIENT_HELLO, hello->pre_proc_exts,
 580                                  NULL, 0)
 581                 || !tls_parse_extension(s, TLSEXT_IDX_psk, SSL_EXT_CLIENT_HELLO,
 582                                         hello->pre_proc_exts, NULL, 0))
 583             return -1;
 584
 585         ret = s->session;
 586     } else {
 587         /* sets s->ext.ticket_expected */
 588         r = tls_get_ticket_from_client(s, hello, &ret);
 589         switch (r) {
 590         case SSL_TICKET_FATAL_ERR_MALLOC:
 591         case SSL_TICKET_FATAL_ERR_OTHER:
 592             fatal = 1;
 593             SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
 594             goto err;
 595         case SSL_TICKET_NONE:
 596         case SSL_TICKET_EMPTY:
 597             if (hello->session_id_len > 0) {
 598                 try_session_cache = 1;
 599                 ret = lookup_sess_in_cache(s, hello->session_id,
 600                                            hello->session_id_len);
 601             }
 602             break;
 603         case SSL_TICKET_NO_DECRYPT:
 604         case SSL_TICKET_SUCCESS:
 605         case SSL_TICKET_SUCCESS_RENEW:
 606             break;
 607         }
 608     }
 609
 610     if (ret == NULL)
 611         goto err;
 612
 613     /* Now ret is non-NULL and we own one of its reference counts. */
 614
 615     /* Check TLS version consistency */
 616     if (ret->ssl_version != s->version)
 617         goto err;
 618
 619     if (ret->sid_ctx_length != s->sid_ctx_length
 620         || memcmp(ret->sid_ctx, s->sid_ctx, ret->sid_ctx_length)) {
 621         /*
 622          * We have the session requested by the client, but we don't want to
 623          * use it in this context.
 624          */
 625         goto err;               /* treat like cache miss */
 626     }
 627
 628     if ((s->verify_mode & SSL_VERIFY_PEER) && s->sid_ctx_length == 0) {
 629         /*
 630          * We can't be sure if this session is being used out of context,
 631          * which is especially important for SSL_VERIFY_PEER. The application
 632          * should have used SSL[_CTX]_set_session_id_context. For this error
 633          * case, we generate an error instead of treating the event like a
 634          * cache miss (otherwise it would be easy for applications to
 635          * effectively disable the session cache by accident without anyone
 636          * noticing).
 637          */
 638
 639         SSLfatal(s, SSL_AD_INTERNAL_ERROR,
 640                  SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED);
 641         fatal = 1;
 642         goto err;
 643     }
 644
 645     if (sess_timedout(time(NULL), ret)) {
 646         ssl_tsan_counter(s->session_ctx, &s->session_ctx->stats.sess_timeout);
 647         if (try_session_cache) {
 648             /* session was from the cache, so remove it */
 649             SSL_CTX_remove_session(s->session_ctx, ret);
 650         }
 651         goto err;
 652     }
 653
 654     /* Check extended master secret extension consistency */
 655     if (ret->flags & SSL_SESS_FLAG_EXTMS) {
 656         /* If old session includes extms, but new does not: abort handshake */
 657         if (!(s->s3.flags & TLS1_FLAGS_RECEIVED_EXTMS)) {
 658             SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_INCONSISTENT_EXTMS);
 659             fatal = 1;
 660             goto err;
 661         }
 662     } else if (s->s3.flags & TLS1_FLAGS_RECEIVED_EXTMS) {
 663         /* If new session includes extms, but old does not: do not resume */
 664         goto err;
 665     }
 666
 667     if (!SSL_IS_TLS13(s)) {
 668         /* We already did this for TLS1.3 */
 669         SSL_SESSION_free(s->session);
 670         s->session = ret;
 671     }
 672
 673     ssl_tsan_counter(s->session_ctx, &s->session_ctx->stats.sess_hit);
 674     s->verify_result = s->session->verify_result;
 675     return 1;
 676
 677  err:
 678     if (ret != NULL) {
 679         SSL_SESSION_free(ret);
 680         /* In TLSv1.3 s->session was already set to ret, so we NULL it out */
 681         if (SSL_IS_TLS13(s))
 682             s->session = NULL;
 683
 684         if (!try_session_cache) {
 685             /*
 686              * The session was from a ticket, so we should issue a ticket for
 687              * the new session
 688              */
 689             s->ext.ticket_expected = 1;
 690         }
 691     }
 692     if (fatal)
 693         return -1;
 694
 695     return 0;
 696 }
```

572-585: TLSv1.3通过解析PSK Extension中的ticket来恢复session;

