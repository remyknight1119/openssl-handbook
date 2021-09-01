# Chapter 4 Certificate Chain

## 1.加载证书

SSL\_CTX\_use\_certificate\(\)可以用来加载证书：

```text
 301 int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
 302 {
 303     int rv;
 304     if (x == NULL) {
 305         SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
 306         return 0;
 307     }
 308     rv = ssl_security_cert(NULL, ctx, x, 0, 1);
 309     if (rv != 1) {
 310         SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, rv);
 311         return 0;
 312     }
 313     return ssl_set_cert(ctx->cert, x);
 314 }
 315 
 316 static int ssl_set_cert(CERT *c, X509 *x) 
 317 {                        
 318     EVP_PKEY *pkey;
 319     size_t i;
 320 
 321     pkey = X509_get0_pubkey(x);    
 322     if (pkey == NULL) {
 323         SSLerr(SSL_F_SSL_SET_CERT, SSL_R_X509_LIB);
 324         return 0;
 325     }
 326 
 327     if (ssl_cert_lookup_by_pkey(pkey, &i) == NULL) {
 328         SSLerr(SSL_F_SSL_SET_CERT, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
 329         return 0;
 330     }
 331 #ifndef OPENSSL_NO_EC
 332     if (i == SSL_PKEY_ECC && !EC_KEY_can_sign(EVP_PKEY_get0_EC_KEY(pkey))) {
 333         SSLerr(SSL_F_SSL_SET_CERT, SSL_R_ECC_CERT_NOT_FOR_SIGNING);
 334         return 0;
 335     }
 336 #endif
 337     if (c->pkeys[i].privatekey != NULL) {
 338         /*
 339          * The return code from EVP_PKEY_copy_parameters is deliberately
 340          * ignored. Some EVP_PKEY types cannot do this.
 341          */
 342         EVP_PKEY_copy_parameters(pkey, c->pkeys[i].privatekey);
 343         ERR_clear_error();
 344 
 345 #ifndef OPENSSL_NO_RSA
 346         /*
 347          * Don't check the public/private key, this is mostly for smart
 348          * cards.
 349          */
 350         if (EVP_PKEY_id(c->pkeys[i].privatekey) == EVP_PKEY_RSA
 351             && RSA_flags(EVP_PKEY_get0_RSA(c->pkeys[i].privatekey)) &
 352             RSA_METHOD_FLAG_NO_CHECK) ;
 353         else
 354 #endif                          /* OPENSSL_NO_RSA */
 355         if (!X509_check_private_key(x, c->pkeys[i].privatekey)) {
 356             /*
 357              * don't fail for a cert/key mismatch, just free current private
 358              * key (when switching to a different cert & key, first this
 359              * function should be used, then ssl_set_pkey
 360              */
 361             EVP_PKEY_free(c->pkeys[i].privatekey);
 362             c->pkeys[i].privatekey = NULL;
 363             /* clear error queue */
 364             ERR_clear_error();
 365         }
 366     }
 367 
 368     X509_free(c->pkeys[i].x509);
 369     X509_up_ref(x);
 370     c->pkeys[i].x509 = x;
 371     c->key = &(c->pkeys[i]);
 372 
 373     return 1;
 374 }
```

327: ssl\_cert\_lookup\_by\_pkey\(\)函数找出pkey所对应的类型，写入i中;

337-366: 如果已经加载的private key，检查cert与key是否匹配;

370: 将证书赋值到pkeys\[\]数组，不同类型的key由于i不同因而不会冲突;

371: 设置一个“快捷方式”。

## 2. 证书链\(Certificate Chain\)

### 2.1 Certificate Chain简介

    SSL的CA证书可分为两种：Root CA（根CA证书）和Intermediate CA（中间CA证书）。其中Root CA是信任锚点，一条证书链中只能有一个。Intermediate CA可以有多个。Root CA通常不直接签发用户证书，而是签发Intermediate CA，由Intermediate CA来签发终用户书。它们之间的关系如下图所示：

![](https://img-blog.csdn.net/20170728125047197?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMTEzMDU3OA==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)

    证书链就是Root CA签发二级Intermediate CA，二级Intermediate CA可以签发三级Intermediate CA，也可以直接签发用户证书。从Root CA到用户证书之间构成了一个信任链：信任Root CA，就应该信任它所信任的二级Intermediate CA，从而就应该信任三级Intermediate CA直至信任用户证书。

    客户的系统或浏览器上会默认安装多个知名的Root CA，在SSL Handshake过程中Server需要将证书链发送给Client（通常是浏览器），Client使用Root CA逐级对证书进行验证，直至验证Server的用户证书。

### 2.2 Load Certificate Chain

SSL\_CTX\_add0\_chain\_cert\(\)和SSL\_CTX\_add1\_chain\_cert\(\)函数用来加载证书链:

```text
1345 # define SSL_CTX_add0_chain_cert(ctx,x509) \
1346         SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))
1347 # define SSL_CTX_add1_chain_cert(ctx,x509) \
1348         SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)(x509))
```

```text
2270 long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
2271 {
2272     long l;
2273     /* For some cases with ctx == NULL perform syntax checks */
2274     if (ctx == NULL) {
2275         switch (cmd) {
2276 #ifndef OPENSSL_NO_EC
2277         case SSL_CTRL_SET_GROUPS_LIST:
2278             return tls1_set_groups_list(NULL, NULL, parg);
2279 #endif
2280         case SSL_CTRL_SET_SIGALGS_LIST:
2281         case SSL_CTRL_SET_CLIENT_SIGALGS_LIST:
2282             return tls1_set_sigalgs_list(NULL, parg, 0);
2283         default:
2284             return 0;
2285         }
2286     }
2287 
2288     switch (cmd) {
...
2385     default:
2386         return ctx->method->ssl_ctx_ctrl(ctx, cmd, larg, parg);
2387     }
2388 }
```

ctx-&gt;method-&gt;ssl\_ctx\_ctrl指向ssl3\_ctx\_ctrl\(\):

```text
3763 long ssl3_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
3764 {
3765     switch (cmd) {      
...
3984     case SSL_CTRL_CHAIN_CERT:
3985         if (larg)
3986             return ssl_cert_add1_chain_cert(NULL, ctx, (X509 *)parg);
3987         else
3988             return ssl_cert_add0_chain_cert(NULL, ctx, (X509 *)parg);
...
```

```text
 288 int ssl_cert_add0_chain_cert(SSL *s, SSL_CTX *ctx, X509 *x)
 289 {
 290     int r;
 291     CERT_PKEY *cpk = s ? s->cert->key : ctx->cert->key;
 292     if (!cpk)
 293         return 0;
 294     r = ssl_security_cert(s, ctx, x, 0, 0);
 295     if (r != 1) {
 296         SSLerr(SSL_F_SSL_CERT_ADD0_CHAIN_CERT, r);
 297         return 0;
 298     }
 299     if (!cpk->chain)
 300         cpk->chain = sk_X509_new_null();
 301     if (!cpk->chain || !sk_X509_push(cpk->chain, x))
 302         return 0;
 303     return 1;
 304 }
 305 
 306 int ssl_cert_add1_chain_cert(SSL *s, SSL_CTX *ctx, X509 *x)
 307 {
 308     if (!ssl_cert_add0_chain_cert(s, ctx, x))
 309         return 0;
 310     X509_up_ref(x);
 311     return 1;
 312 }
```

291: cpk指向ssl\_set\_cert\(\)中所设置的快捷方式;

294: 根据安全等级\(security level\)检查密钥强度等;

301: 将证书加入到与之前的终端证书\(server用户证书\)相同的数组中。

### 2.3 Server Certificate Chain

SSL Server收到ClientHello后，需要构建Server Ceritificate来回应:

```text
3774 int tls_construct_server_certificate(SSL *s, WPACKET *pkt)
3775 {
3776     CERT_PKEY *cpk = s->s3->tmp.cert;
3777 
3778     if (cpk == NULL) {
3779         SSLfatal(s, SSL_AD_INTERNAL_ERROR,
3780                  SSL_F_TLS_CONSTRUCT_SERVER_CERTIFICATE, ERR_R_INTERNAL_ERROR);
3781         return 0;
3782     }
3783 
3784     /*
3785      * In TLSv1.3 the certificate chain is always preceded by a 0 length context
3786      * for the server Certificate message
3787      */
3788     if (SSL_IS_TLS13(s) && !WPACKET_put_bytes_u8(pkt, 0)) {
3789         SSLfatal(s, SSL_AD_INTERNAL_ERROR,
3790                  SSL_F_TLS_CONSTRUCT_SERVER_CERTIFICATE, ERR_R_INTERNAL_ERROR);
3791         return 0;
3792     }
3793     if (!ssl3_output_cert_chain(s, pkt, cpk)) {
3794         /* SSLfatal() already called */
3795         return 0;
3796     }
3797 
3798     return 1;
3799 }
```

ssl3\_output\_cert\_chain\(\)将证书链制放入到Server Ceritificate消息中:

```text
 998 unsigned long ssl3_output_cert_chain(SSL *s, WPACKET *pkt, CERT_PKEY *cpk)
 999 {
1000     if (!WPACKET_start_sub_packet_u24(pkt)) {
1001         SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL3_OUTPUT_CERT_CHAIN,
1002                  ERR_R_INTERNAL_ERROR);
1003         return 0;
1004     }            
1005         
1006     if (!ssl_add_cert_chain(s, pkt, cpk))
1007         return 0;
1008     
1009     if (!WPACKET_close(pkt)) {
1010         SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL3_OUTPUT_CERT_CHAIN,
1011                  ERR_R_INTERNAL_ERROR);
1012         return 0;
1013     }   
1014                  
1015     return 1;
1016 }   
```

```text
 901 /* Add certificate chain to provided WPACKET */
 902 static int ssl_add_cert_chain(SSL *s, WPACKET *pkt, CERT_PKEY *cpk)
 903 {
 904     int i, chain_count;
 905     X509 *x;
 906     STACK_OF(X509) *extra_certs;
 907     STACK_OF(X509) *chain = NULL;
 908     X509_STORE *chain_store;
 909 
 910     if (cpk == NULL || cpk->x509 == NULL)
 911         return 1;
 912 
 913     x = cpk->x509;
 914 
 915     /*
 916      * If we have a certificate specific chain use it, else use parent ctx.
 917      */
 918     if (cpk->chain != NULL)
 919         extra_certs = cpk->chain;
 920     else
 921         extra_certs = s->ctx->extra_certs;
 922 
 923     if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || extra_certs)
 924         chain_store = NULL;
 925     else if (s->cert->chain_store)
 926         chain_store = s->cert->chain_store;
 927     else
 928         chain_store = s->ctx->cert_store;
 929 
 930     if (chain_store != NULL) {
 931         X509_STORE_CTX *xs_ctx = X509_STORE_CTX_new();
 932 
 933         if (xs_ctx == NULL) {
 934             SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_ADD_CERT_CHAIN,
 935                      ERR_R_MALLOC_FAILURE);
 936             return 0;
 937         }
 938         if (!X509_STORE_CTX_init(xs_ctx, chain_store, x, NULL)) {
 939             X509_STORE_CTX_free(xs_ctx);
 940             SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_ADD_CERT_CHAIN,
 941                      ERR_R_X509_LIB);
 942             return 0;
 943         }
 944         /*
 945          * It is valid for the chain not to be complete (because normally we
 946          * don't include the root cert in the chain). Therefore we deliberately
 947          * ignore the error return from this call. We're not actually verifying
 948          * the cert - we're just building as much of the chain as we can
 949          */
 950         (void)X509_verify_cert(xs_ctx);
 951         /* Don't leave errors in the queue */
 952         ERR_clear_error();
 953         chain = X509_STORE_CTX_get0_chain(xs_ctx);
 954         i = ssl_security_cert_chain(s, chain, NULL, 0);
 955         if (i != 1) {
 956 #if 0
 957             /* Dummy error calls so mkerr generates them */
 958             SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, SSL_R_EE_KEY_TOO_SMALL);
 959             SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, SSL_R_CA_KEY_TOO_SMALL);
 960             SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, SSL_R_CA_MD_TOO_WEAK);
 961 #endif
 962             X509_STORE_CTX_free(xs_ctx);
 963             SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_ADD_CERT_CHAIN, i);
 964             return 0;
 965         }
 966         chain_count = sk_X509_num(chain);
 967         for (i = 0; i < chain_count; i++) {
 968             x = sk_X509_value(chain, i);
 969 
 970             if (!ssl_add_cert_to_wpacket(s, pkt, x, i)) {
 971                 /* SSLfatal() already called */
 972                 X509_STORE_CTX_free(xs_ctx);
 973                 return 0;
 974             }
 975         }
 976         X509_STORE_CTX_free(xs_ctx);
 977     } else {
 978         i = ssl_security_cert_chain(s, extra_certs, x, 0);
 979         if (i != 1) {
 980             SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_ADD_CERT_CHAIN, i);
 981             return 0;
 982         }
 983         if (!ssl_add_cert_to_wpacket(s, pkt, x, 0)) {
 984             /* SSLfatal() already called */
 985             return 0;
 986         }
 987         for (i = 0; i < sk_X509_num(extra_certs); i++) {
 988             x = sk_X509_value(extra_certs, i);
 989             if (!ssl_add_cert_to_wpacket(s, pkt, x, i + 1)) {
 990                 /* SSLfatal() already called */
 991                 return 0;
 992             }
 993         }
 994     }
 995     return 1;
 996 }
```



## 3. Certificate Chain制作  

证书链的制作脚本如下：

```text
#!/bin/bash

set -e
dir=`dirname $0`
key_bits=2048
expire_days=3650
subj=/C="CN"/ST="Liaoning"/L="Shenyang"/O="Dove"/OU="dove"/CN="doveR"
subji=/C="CN"/ST="Liaoning"/L="Shenyang"/O="Dove"/OU="dove"/CN="doveI"
subjs=/C="CN"/ST="Liaoning"/L="Shenyang"/O="Dove"/OU="dove"/CN="doveS"
subj2=/C="CN"/ST="Liaoning"/L="Shenyang"/O="DoveCERT"/OU="dove"/CN="dove"
server="server-chain"
param=$server
if [ -d $param ]; then
    rm -r $param
fi
mkdir -p $param
cd $param
ca_name=ca-root-$param
root_cacer=$ca_name.cer
root_cakey=$ca_name.key
ca_name=ca-sub1-$param
sub1_cacer=$ca_name.cer
sub1_cakey=$ca_name.key
ca_name=ca-sub2-$param
cacer=$ca_name.cer
cakey=$ca_name.key
cer=$param.cer
csr=$param.csr
key=$param.key

mkdir -p $dir/demoCA/{private,newcerts}
touch $dir/demoCA/index.txt
echo 02 > $dir/demoCA/serial
cd demoCA
ln -sf ../$root_cacer cacert.pem
cd -
cd demoCA/private
ln -sf ../../$root_cakey cakey.pem
cd -
#Root CA
openssl genrsa -out $root_cakey $key_bits
openssl req -x509 -newkey rsa:$key_bits -keyout $root_cakey -nodes -out $root_cacer -subj $subj -days $expire_days
echo "===================Gen Root CA OK===================="

#Sub1 CA
openssl genrsa -out $sub1_cakey $key_bits
openssl req -new -key $sub1_cakey -sha256 -out $csr -subj $subji -days $expire_days
openssl ca -extensions v3_ca -batch -notext -in $csr -out $sub1_cacer
echo "===================Gen Sub1 CA OK===================="

#Sub2 CA
openssl genrsa -out $cakey $key_bits
openssl req -new -key $cakey -sha256 -out $csr -subj $subjs -days $expire_days
openssl ca -extensions v3_ca -batch -notext -in $csr -out $cacer -cert $sub1_cacer -keyfile $sub1_cakey

echo "===================Gen Sub2 CA OK===================="

#Server cert
openssl genrsa -out $key $key_bits
openssl req -new -key $key -sha256 -out $csr -subj $subj2 -days $expire_days
openssl x509 -req -in $csr -sha256 -out $cer -CA $cacer -CAkey $cakey -CAserial t_ssl_ca.srl -CAcreateserial -days $expire_days -extensions v3_req
#openssl pkcs12 -export -clcerts -in client.cer -inkey client.key -out client.p12
rm -f *.csr *.srl

cat $cer $cacer $sub1_cacer |tee $param.pem
echo "===================Gen All OK===================="
```

    在Handshake过程中Server会按照$param.pem文件中的顺序发送证书链。Client在收到证书链的时候会先验证用户证书，但无法找到发行者\(Issuer\)，然后会遍历证书链找到Issuer，再找到Issuer的Issuer，直到能用Root CA进行验证，从而完成了整个证书链的验证。

    【注1】：生成最后的证书（$param.pem）时一定要按照顺序先添加用户证书（$cer），再追加Intermediate CA证书（$cacer，$sub1\_cacer），否则在Server端（如：nginx）会载入失败，因为nginx会使用第一个证书与私钥进行匹配。  


     【注2】：如果Client用OpenSSL API验证Server的证书链，则需要通过SSL\_CTX\_set\_verify\_depth\(ctx, 3\)将验证深度设置为3（如果Root CA以下共有3级证书）。如果是Client是浏览器则只要安装了Root CA证书即可。

