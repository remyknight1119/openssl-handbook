# Chapter 10 ALPN



```c
#define SSL_EXT_ALPN_ACME_TLS_01 "acme-tls/1"

static int ssl_sock_alpn_acme_cb(SSL *ssl, const unsigned char **out,
                                 unsigned char *outlen, const unsigned char *in,
                                 unsigned int inlen, void *arg) 
 {  
     if (memcmp((void *)&in[1], SSL_EXT_ALPN_ACME_TLS_01, sizeof(SSL_EXT_ALPN_ACME_TLS_01) - 1) == 0) {
         *out = &in[1];
         *outlen = sizeof(SSL_EXT_ALPN_ACME_TLS_01) - 1;
     }
 
     return SSL_TLSEXT_ERR_OK;
}

...
SSL_CTX_set_alpn_select_cb(ctx, ssl_sock_alpn_acme_cb, NULL);
...
```

