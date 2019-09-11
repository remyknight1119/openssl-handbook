# 七、Certificate Chain

    SSL的CA证书可分为两种：Root CA（根CA证书）和Intermediate CA（中间CA证书）。其中Root CA是信任锚点，一条证书链中只能有一个。Intermediate CA可以有多个。Root CA通常不直接签发用户证书，而是签发Intermediate CA，由Intermediate CA来签发终用户书。它们之间的关系如下图所示：

![](https://img-blog.csdn.net/20170728125047197?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMTEzMDU3OA==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)

    证书链就是Root CA签发二级Intermediate CA，二级Intermediate CA可以签发三级Intermediate CA，也可以直接签发用户证书。从Root CA到用户证书之间构成了一个信任链：信任Root CA，就应该信任它所信任的二级Intermediate CA，从而就应该信任三级Intermediate CA直至信任用户证书。  


    客户的系统或浏览器上会默认安装多个知名的Root CA，在SSL Handshake过程中Server需要将证书链发送给Client（通常是浏览器），Client使用Root CA逐级对证书进行验证，直至验证Server的用户证书。  


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

