# 七、Certificate Chain

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



### 2.3 Server Certificate Chain



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

