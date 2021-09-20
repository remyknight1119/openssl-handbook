# Chapter 3 DTLS API

## 3.1 Client

```c
static int
dv_openssl_ctx_set_ciphers(void *ctx, char *ciphers)
{
    int      nid = 0;
    EC_KEY  *ecdh = NULL;
    char    *name = "prime256v1";

    if (SSL_CTX_set_cipher_list(ctx, ciphers) == 0) {
        printf("Set cipher %s\n", DV_DEF_SERVER_CIPHERS);
        return DV_ERROR;
    }

    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields. OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */

    nid = OBJ_sn2nid((const char *)name);
    if (nid == 0) {
        printf("Nid error!\n");
        return DV_ERROR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL) {
        printf("Unable to create curve \"%s\"", name);
        return DV_ERROR;
    }

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

    SSL_CTX_set_tmp_ecdh(ctx, ecdh);

    EC_KEY_free(ecdh);

    return DV_OK;
}

static int
dv_openssl_callback(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}

static void
dv_openssl_set_verify(void *ctx, int mode, char *peer_cf)
{
    STACK_OF(X509_NAME)  *list = NULL;

    SSL_CTX_set_verify(ctx, mode, dv_openssl_callback);
    SSL_CTX_set_verify_depth(ctx, 3);

    if (SSL_CTX_load_verify_locations(ctx, peer_cf, NULL) == 0) {
        fprintf(stderr, "Load verify locations %s failed\n", peer_cf);
        exit(1);
    }

    list = SSL_load_client_CA_file(peer_cf);
    if (list == NULL) {
        fprintf(stderr, "Load client ca file %s failed\n", peer_cf);
        exit(1);
    }

    SSL_CTX_set_client_CA_list(ctx, list);
}

static int
dv_ssl_client_main(struct sockaddr_in *dest, char *cf, char *key,
        char *peer_cf)
{
    int         sockfd = 0;
    int         len = 0;
    char        buffer[DV_BUF_MAX_LEN] = {};
    SSL_CTX     *ctx = NULL;
    SSL         *ssl = NULL;
    int         ret = DV_OK;

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        fprintf(stderr, "OpenSSL init failed!\n");
        exit(1);
    }
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    ctx = SSL_CTX_new(DTLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        return DV_ERROR;
    }

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)dest, sizeof(*dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }

    printf("server connected\n");
    dv_openssl_set_verify(ctx, SSL_VERIFY_PEER, peer_cf);
    if (dv_openssl_ctx_set_ciphers(ctx, dv_client_ciphers) != DV_OK) {
        fprintf(stderr, "Set cipher failed!\n");
        exit(1);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */

    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
    }

    if ((ret = dv_openssl_get_verify_result(ssl)) != DV_OK) {
        printf("Server cert verify failed(%d)!\n", ret);
        exit(1);
    }

    /* 发消息给服务器 */
    len = SSL_write(ssl, DV_TEST_REQ, sizeof(DV_TEST_REQ));
    if (len < 0) {
        printf("Client消息'%s'发送失败!错误代码是%d,错误信息是'%s'\n",
                buffer, errno, strerror(errno));
        exit(1);
    } else {
        printf("Client消息'%s'发送成功,共发送了%d 个字节!\n",
                DV_TEST_REQ, len);
    }

    /* 接收服务器来的消息 */
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

out:
    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return ret;
}

```

## 3.2 Server

