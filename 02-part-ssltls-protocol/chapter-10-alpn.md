# Chapter 10 ALPN

C:

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

Golang:

```
// Some code
func TLSALPN01Challenge(challenge acme.Challenge, addr string) {
	cert, _, _, err := TLSALPN01ChallengeCertECDSA(challenge)
	if (err != nil) {
		acmeLib.LogPrint("Create challenge cert failed: %v", err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{ACMETLS1Protocol}}
	acmeLib.LogPrint("listen: %s", addr)
	ln, err := tls.Listen("tcp", addr, config)
	if err != nil {
		acmeLib.LogPrint("Listen failed: %v", err)
		return
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		acmeLib.LogPrint("Accept!")
		if err != nil {
			acmeLib.LogPrint("Accept failed: %v", err)
			continue
		}
		handleConnection(conn)
	}
}

// ACMETLS1Protocol is the ALPN value for the TLS-ALPN challenge
// handshake. See RFC 8737 §6.2.
const ACMETLS1Protocol = "acme-tls/1"
```
