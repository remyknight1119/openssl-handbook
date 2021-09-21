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

```c
#include "list.h"

typedef union _dv_udp_conn_key_t {
        struct sockaddr                 addr;
        struct sockaddr_in      addr4;
        struct sockaddr_in6     addr6;
} dv_udp_conn_key_t;

typedef struct _dv_udp_conn_t {
        struct list_head list;
        dv_udp_conn_key_t key;
        void *ssl;
        void *rbio;
        void *wbio;
} dv_udp_conn_t;

static int
dv_ssl_certificate(void *ctx, char *cert, char *key)
{
    BIO             *bio = NULL;
    X509            *x509 = NULL;
    unsigned long   n = 0;
    unsigned int    tries = 3;

    bio = BIO_new_file(cert, "r");
    if (bio == NULL) {
        fprintf(stderr, "New file from %s failed!\n", cert);
        return -1;
    }

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        BIO_free(bio);
        fprintf(stderr, "PEM read bio failed!\n");
        return -1;
    }

    if (SSL_CTX_use_certificate(ctx, x509) == 0) {
        fprintf(stderr, "SSL_CTX_use_certificate(%s) failed", cert);
        X509_free(x509);
        BIO_free(bio);
        return -1;
    }

    for ( ;; ) {
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();
            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                    && ERR_GET_REASON(n) == PEM_R_NO_START_LINE) {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            fprintf(stderr, "PEM_read_bio_X509(%s) failed", cert);
            BIO_free(bio);
            return -1;
        }

        if (SSL_CTX_add0_chain_cert(ctx, x509) == 0) {
            fprintf(stderr, "SSL_CTX_add0_chain_cert(%s) failed", cert);
            X509_free(x509);
            BIO_free(bio);
            return -1;
        }
    }

    BIO_free(bio);
    for ( ;; ) {
        if (SSL_CTX_use_PrivateKey_file(ctx, (char *)key, SSL_FILETYPE_PEM)
                != 0) {
            break;
        }

        if (--tries) {
            ERR_clear_error();
            //SSL_CTX_set_default_passwd_cb_userdata(ssl->ctx, ++pwd);
            continue;
        }

        fprintf(stderr, "SSL_CTX_use_PrivateKey_file(%s) failed", key);
        return -1;
    }
    return 0;
}

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
dv_openssl_get_verify_result(void *s)
{
    long    ret = 0;

    ret = SSL_get_verify_result(s);
    if (ret != X509_V_OK) {
        fprintf(stderr, "Verify ret is %ld\n", ret);
        return DV_ERROR;
    }

    return DV_OK;
}

static void
dv_add_epoll_event(int epfd, struct epoll_event *ev, int fd)
{
    ev->data.fd = fd;
    ev->events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}

#define DTLS_UDP_CONN_HASHTB_SIZE       65535
#define DTLS_RECORD_MAX_LEN     (65535 - 8)

static struct list_head dtls_udp_conn[DTLS_UDP_CONN_HASHTB_SIZE];

static void dv_dtls_conn_table_init(void)
{
    int     i = 0;

    for (i = 0; i < DV_ARRAY_SIZE(dtls_udp_conn); i++) {
            INIT_LIST_HEAD(&dtls_udp_conn[i]);
    }
}

static unsigned int dv_dtls_conn_hash(dv_udp_conn_key_t *key)
{
    unsigned char   md5[MD5_DIGEST_LENGTH];
    unsigned int    hash = 0;
    int                     i = 0;

    MD5((void *)key, sizeof(*key), md5);

    for (i = 0; i < sizeof(md5); i += sizeof(hash)) {
            hash ^= *((unsigned int *)&md5[i]);
    }

    return hash % DTLS_UDP_CONN_HASHTB_SIZE;
}

static void dv_dtls_conn_add(dv_udp_conn_t *conn)
{
    struct list_head *head = NULL;
    unsigned int hash = 0;

    hash = dv_dtls_conn_hash(&conn->key);
    head = &dtls_udp_conn[hash];
    list_add_tail(&conn->list, head);
}

static void dv_dtls_conn_del(dv_udp_conn_t *conn)
{
    list_del(&conn->list);
}

static dv_udp_conn_t *dv_dtls_conn_find(dv_udp_conn_key_t *key)
{
    struct list_head        *head = NULL;
    struct list_head        *pos = NULL;
    dv_udp_conn_t           *conn = NULL;
    unsigned int            hash = 0;

    hash = dv_dtls_conn_hash(key);
    head = &dtls_udp_conn[hash];

    list_for_each(pos, head) {
            conn = list_entry(pos, dv_udp_conn_t, list);
            if (memcmp(key, &conn->key, sizeof(*key)) == 0) {
                    return conn;
            }
    }

    return NULL;
}

static int
dv_dtls_msg_send(BIO *wbio, int fd, dv_udp_conn_key_t *key, socklen_t addrlen)
{
    char                dtls_data[DTLS_RECORD_MAX_LEN] = {};
    int                 rlen = 0;
    int                 wlen = 0;

    rlen = BIO_read(wbio, dtls_data, sizeof(dtls_data));
    if (rlen <= 0) {
            return -1;
    }

    wlen = sendto(fd, dtls_data, rlen, 0, (const struct sockaddr *)&key->addr, addrlen);
    if (wlen <= 0) {
            return -1;
    }

    return 0;
}

static dv_udp_conn_t *
dv_dtls_conn_new(void *ctx, char *buf, size_t len, int fd,
                dv_udp_conn_key_t *key, socklen_t addrlen)
{
    dv_udp_conn_t       *conn = NULL;
    BIO                 *rbio = NULL;
    BIO                 *wbio = NULL;
    SSL                 *ssl = NULL;

    rbio = BIO_new(BIO_s_mem());
    if (rbio == NULL) {
        return NULL;
    }

    wbio = BIO_new(BIO_s_mem());
    if (wbio == NULL) {
        goto free_bio;
    }

    BIO_write(rbio, buf, len);

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto free_bio;
    }

    SSL_set_accept_state(ssl);
    SSL_set_bio(ssl, rbio, wbio);

    SSL_do_handshake(ssl);

    if (dv_dtls_msg_send(wbio, fd, key, addrlen) < 0) {
            goto out;
    }

    conn = calloc(1, sizeof(*conn));
    if (conn == NULL) {
            goto out;
    }
    conn->ssl = ssl;
    conn->rbio = rbio;
    conn->wbio = wbio;
    conn->key = *key;
    dv_dtls_conn_add(conn);

    return conn;
free_bio:
    BIO_free(rbio);
    BIO_free(wbio);
out:
    SSL_free(ssl);
    return NULL;
}

static void
dv_dtls_conn_free(dv_udp_conn_t *conn)
{
    SSL_free(conn->ssl);
    dv_dtls_conn_del(conn);
    free(conn);
}

static int
dv_dtls_read(dv_udp_conn_t *conn, char *in_buf, size_t in_len,
        int fd, char *out_buf, size_t out_len, socklen_t addrlen)
{
    int     rlen = 0;
    int     ret = 0;

    BIO_write(conn->rbio, in_buf, in_len);

    rlen = SSL_read(conn->ssl, out_buf, out_len);
    if (rlen > 0) {
            return rlen;
    }

    if (rlen == 0) {
            return -2;
    }
    ret = SSL_get_error(conn->ssl, rlen);
    if (ret == SSL_ERROR_WANT_READ) {
            dv_dtls_msg_send(conn->wbio, fd, &conn->key, addrlen);
            return 0;
    }

    return -1;
}

static int
dv_dtls_write(dv_udp_conn_t *conn, char *in_buf, size_t in_len,
        int fd, char *out_buf, size_t out_len, socklen_t addrlen)
{
    int     wlen = 0;

    wlen = SSL_write(conn->ssl, in_buf, in_len);
    if (wlen <= 0) {
        return -1;
    }

    if (dv_dtls_msg_send(conn->wbio, fd, &conn->key, addrlen) < 0) {
            return -1;
    }

    return wlen;
}

static void
dv_dtls_shutdown(dv_udp_conn_t *conn, int fd, socklen_t addrlen)
{
    SSL_shutdown(conn->ssl);
    dv_dtls_msg_send(conn->wbio, fd, &conn->key, addrlen);
}

#define COOKIE_SECRET_LENGTH    16

static int
dv_dtls_generate_cookie_callback(SSL *ssl, unsigned char *cookie, 
        unsigned int *cookie_len)
{
    static unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
    unsigned char buffer[16] = {};

    HMAC(EVP_sha1(), cookie_secret, COOKIE_SECRET_LENGTH,
                buffer, sizeof(buffer), cookie, cookie_len);

    printf("generate cookie\n");
    return 1;
}

static int
dv_dtls_verify_cookie_callback(SSL *ssl, const unsigned char *cookie,
                unsigned int cookie_len)
{
    printf("verify cookie\n");
    return 1;
}

static int
dv_ssl_server_main(struct sockaddr_in *my_addr,struct sockaddr_in6 *my_addr6,
            char *cf, char *key, char *peer_cf)
{
    dv_udp_conn_key_t   udp_key = {};
    socklen_t           addrlen = sizeof(udp_key);
    struct epoll_event  ev = {};
    struct epoll_event  events[DV_TEST_EVENT_MAX_NUM] = {};
    int                 sockfd = 0;
    int                 sockfd6 = -1;
    int                 efd = 0;
    int                 new_fd = 0;
    int                 epfd = 0;
    int                 nfds = 0;
    int                 reuse = 1;
    int                 i = 0;
    int                 len = 0;
    ssize_t             rlen = 0;
    ssize_t             wlen = 0;
    struct sockaddr_in  their_addr = {};
    char                dtls_data[DTLS_RECORD_MAX_LEN] = {};
    char                buf[DV_BUF_MAX_LEN] = {};
    void                *ctx = NULL;
    void                *ssl = NULL;
    dv_udp_conn_t       *conn = NULL;

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        fprintf(stderr, "OpenSSL init failed!\n");
        exit(1);
    }
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(DTLS_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "CTX new failed!\n");
        exit(1);
    }
    if (dv_ssl_certificate(ctx, cf, key) != 0) {
        fprintf(stderr, "Load private key failed!\n");
        exit(1);
    }

    /* 检查用户私钥是否正确 */
    if (SSL_CTX_check_private_key(ctx) < 0) {
        fprintf(stderr, "Check private key failed!\n");
        exit(1);
    }

    /* Set Verify and Cookie */
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, dv_openssl_callback);
    SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_cookie_generate_cb(ctx, dv_dtls_generate_cookie_callback);
    SSL_CTX_set_cookie_verify_cb(ctx, dv_dtls_verify_cookie_callback);

    if (dv_openssl_ctx_set_ciphers(ctx, DV_DEF_SERVER_CIPHERS) != DV_OK) {
        fprintf(stderr, "Set cipher failed!\n");
        exit(1);
    }

    /* 开启一个 socket 监听 */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(sockfd, (struct sockaddr *)my_addr, sizeof(*my_addr)) == -1) {
        perror("bind");
        exit(1);
    }

    if (my_addr6 != NULL) {
        if ((sockfd6 = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
            perror("socket");
            exit(1);
        }

        setsockopt(sockfd6, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        if (bind(sockfd6, (struct sockaddr *)my_addr6, sizeof(*my_addr6)) == -1) {
            perror("bind");
            exit(1);
        }
    }

    epfd = epoll_create(1);
    if (epfd < 0) {
        exit(1);
    }
    dv_add_epoll_event(epfd, &ev, sockfd);
        if (sockfd6 >= 0) {
        dv_add_epoll_event(epfd, &ev, sockfd6);
        }

    while (1) {
        nfds = epoll_wait(epfd, events, DV_TEST_EVENT_MAX_NUM, -1);
        for (i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN) {
                if ((efd = events[i].data.fd) < 0) {
                    continue;
                }

                memset(&udp_key, 0, sizeof(udp_key));
                if (efd == sockfd || efd == sockfd6) {
                    fprintf(stdout, "UDP msg!\n");
                    rlen = recvfrom(efd, dtls_data, sizeof(dtls_data), 0,
                                (struct sockaddr *)&udp_key, &addrlen);
                    if (rlen <= 0) {
                        continue;
                    }

                    conn = dv_dtls_conn_find(&udp_key);
                    if (conn == NULL) {
                        printf("new conn, sport = %d, saddr = %u\n", 
                            ntohs(udp_key.addr4.sin_port), 
                            (unsigned int)udp_key.addr4.sin_addr.s_addr);
                        conn = dv_dtls_conn_new(ctx, dtls_data, rlen, 
                                    efd, &udp_key, addrlen);
                        if (conn == NULL) {
                            printf("new conn, failed\n");
                        }
                        continue;
                    }

                    printf("conn found, sport = %d\n",
                            ntohs(udp_key.addr4.sin_port));
                    bzero(buf, sizeof(buf));
                    /* 接收客户端的消息 */
                    len = dv_dtls_read(conn, dtls_data, rlen, efd, buf,
                                sizeof(buf), addrlen);
                    if (len > 0) {
                        printf("Server接收消息成功:'%s',共%d 个字节的数据\n", buf, len);
                    } else if (len == 0) {
                        printf("Handshaking\n");
                        continue;
                    } else if (len == -2) {
                        printf("DTLS peer  connection closed\n");
                        dv_dtls_shutdown(conn, efd, addrlen);
                        dv_dtls_conn_free(conn);
                        continue;
                    } else {
                        printf("Server消息接收失败!错误代码是%d,错误信息是'%s'\n", 
                                errno, strerror(errno));
                        dv_dtls_shutdown(conn, efd, addrlen);
                        dv_dtls_conn_free(conn);
                        continue;
                    }

                    /* 发消息给客户端 */
                    len = dv_dtls_write(conn, DV_TEST_RESP, sizeof(DV_TEST_RESP), 
                                efd, dtls_data, sizeof(dtls_data), addrlen);
                    if (len <= 0) {
                        printf("Server消息'%s'发送失败!错误信息是'%s'\n",
                             buf, strerror(errno));
                        dv_dtls_conn_free(conn);
                        continue;
                    }

                    dv_add_epoll_event(epfd, &ev, sockfd);
                    continue;
                }
            }
        }
    }

    close(epfd);
    /* 关闭监听的 socket */
    close(sockfd);
    /* 释放 CTX */
    SSL_CTX_free(ctx);
    fprintf(stdout, "Server exit!\n");
    exit(0);
}

```

452: 必须设置SSL\_OP\_COOKIE\_EXCHANGE option才能开启Cookie Verify功能;

