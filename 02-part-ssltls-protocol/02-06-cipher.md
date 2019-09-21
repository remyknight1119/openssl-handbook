# 十、Cipher

## 1. Introduction

SSL Cipher suite是一组选定的加密设置和参数，它用于精确定义如何实现加密解密。Cipher stuie主要包括如下属性：

* 认证算法
* 密钥交换算法
* 加密算法
* 加密密钥长度
* 密码模式
* MAC算法

## 2. Create Cipher List

### 2.1 Cipher List影响因素

在生成SSL\_CTX时cipher list就会被创建：

```text
2899 SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth)
2900 {
2901     SSL_CTX *ret = NULL; 
...
2951     if (!SSL_CTX_set_ciphersuites(ret, TLS_DEFAULT_CIPHERSUITES))
2952         goto err;
2953 
2954     if (!ssl_create_cipher_list(ret->method,
2955                                 ret->tls13_ciphersuites,
2956                                 &ret->cipher_list, &ret->cipher_list_by_id,
2957                                 SSL_DEFAULT_CIPHER_LIST, ret->cert)
2958         || sk_SSL_CIPHER_num(ret->cipher_list) <= 0) {
2959         SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_LIBRARY_HAS_NO_CIPHERS);
2960         goto err2;
2961     }
...
```

在这之后，可以用其它方法影响SSL的cipher list：

1\) SSL version；

2\) API设置；

3\) Certificate类型。

### 2.2 Cipher list create

Cipher list的创建是由ssl\_create\_cipher\_list\(\)实现的：

```text
1402 STACK_OF(SSL_CIPHER) *ssl_create_cipher_list(const SSL_METHOD *ssl_method,  
1403                                              STACK_OF(SSL_CIPHER) *tls13_ciphersuites,
1404                                              STACK_OF(SSL_CIPHER) **cipher_list,
1405                                              STACK_OF(SSL_CIPHER) **cipher_list_by_id, 
1406                                              const char *rule_str,          
1407                                              CERT *c)                                                                                                                                                         
1408 {
1409     int ok, num_of_ciphers, num_of_alias_max, num_of_group_aliases
1410     uint32_t disabled_mkey, disabled_auth, disabled_enc, disabled_mac;                                                                                                                    
1411     STACK_OF(SSL_CIPHER) *cipherstack;
1412     const char *rule_p;
1413     CIPHER_ORDER *co_list = NULL, *head = NULL, *tail = NULL, *curr;
1414     const SSL_CIPHER **ca_list = NULL;                                              
```

cipher\_list和cipher\_list\_by\_id都保存着函数输出的cipher list，不同的是前者是原始的，后者是排过序的。而最终的结果在输出之前，会保存在1411行的cipherstack里。而1406行的入参rule\_str，则是生成cipher list的根据。

```text
ssl_create_cipher_list:
1436     /*
1437      * Now we have to collect the available ciphers from the compiled
1438      * in ciphers. We cannot get more than the number compiled in, so
1439      * it is used for allocation.
1440      */
1441     num_of_ciphers = ssl_method->num_ciphers();
1442 
1443     co_list = OPENSSL_malloc(sizeof(*co_list) * num_of_ciphers);
1444     if (co_list == NULL) {
1445         SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
1446         return NULL;          /* Failure */
1447     }
1448 
1449     ssl_cipher_collect_ciphers(ssl_method, num_of_ciphers,
1450                                disabled_mkey, disabled_auth, disabled_enc,
1451                                disabled_mac, co_list, &head, &tail);
```

1441: 通过ssl\_method-&gt;num\_cipher\(\)获取所有cipher的数量；实际上就是ssl3\_ciphers\[\]的数量。

1443: 申请一个co\_list数组把所有的cipher全部装进来。

1449-1451: ssl\_cipher\_collect\_ciphers负责收集cipher的全集：

```text
 641 static void ssl_cipher_collect_ciphers(const SSL_METHOD *ssl_method,  
 642                                        int num_of_ciphers,            
 643                                        uint32_t disabled_mkey,        
 644                                        uint32_t disabled_auth,        
 645                                        uint32_t disabled_enc,         
 646                                        uint32_t disabled_mac,         
 647                                        CIPHER_ORDER *co_list,         
 648                                        CIPHER_ORDER **head_p,         
 649                                        CIPHER_ORDER **tail_p)                                                                                                                                                 
 650 {
 651     int i, co_list_num;  
 652     const SSL_CIPHER *c; 
 653 
 654     /*
 655      * We have num_of_ciphers descriptions compiled in, depending on the
 656      * method selected (SSLv3, TLSv1 etc).
 657      * These will later be sorted in a linked list with at most num                                                                                                                                           
 658      * entries.        
 659      */
 660 
 661     /* Get the initial list of ciphers */
 662     co_list_num = 0;            /* actual count of ciphers */
 663     for (i = 0; i < num_of_ciphers; i++) { 
 664         c = ssl_method->get_cipher(i); 
 665         /* drop those that use any of that is not available */
 666         if (c == NULL || !c->valid)        
 667             continue;    
 668         if ((c->algorithm_mkey & disabled_mkey) ||
 669             (c->algorithm_auth & disabled_auth) ||
 670             (c->algorithm_enc & disabled_enc) ||
 671             (c->algorithm_mac & disabled_mac))
 672             continue;    
 673         if (((ssl_method->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS) == 0) &&                                                                                                                                   
 674             c->min_tls == 0)
 675             continue;    
 676         if (((ssl_method->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS) != 0) &&                                                                                                                                   
 677             c->min_dtls == 0)
 678             continue;
 679 
 680         co_list[co_list_num].cipher = c;
 681         co_list[co_list_num].next = NULL;
 682         co_list[co_list_num].prev = NULL;
 683         co_list[co_list_num].active = 0;
 684         co_list_num++;
 685     }
 686 
 687     /*
 688      * Prepare linked list from list entries
 689      */
 690     if (co_list_num > 0) {
 691         co_list[0].prev = NULL;
 692 
 693         if (co_list_num > 1) {
 694             co_list[0].next = &co_list[1];
 695 
 696             for (i = 1; i < co_list_num - 1; i++) {
 697                 co_list[i].prev = &co_list[i - 1];
 698                 co_list[i].next = &co_list[i + 1];
 699             }
 700 
 701             co_list[co_list_num - 1].prev = &co_list[co_list_num - 2];
 702         }
 703 
 704         co_list[co_list_num - 1].next = NULL;
 705 
 706         *head_p = &co_list[0];
 707         *tail_p = &co_list[co_list_num - 1];
 708     }
 709 }

```

663-664: 遍历ssl3\_ciphers\[\]的成员；

666-672: 过滤掉无效的和被屏蔽掉的所有cipher；

680-684: 将所有有效的cipher装入co\_list数组；

690-707: 设置co\_list链表，初始化head和tail。

接下来是调整这个链表：

```text
ssl_create_cipher_list:
1453     /* Now arrange all ciphers by preference. */
1454 
1455     /*
1456      * Everything else being equal, prefer ephemeral ECDH over other key
1457      * exchange mechanisms.
1458      * For consistency, prefer ECDSA over RSA (though this only matters if the
1459      * server has both certificates, and is using the DEFAULT, or a client
1460      * preference).
1461      */
1462     ssl_cipher_apply_rule(0, SSL_kECDHE, SSL_aECDSA, 0, 0, 0, 0, CIPHER_ADD,
1463                           -1, &head, &tail);
1464     ssl_cipher_apply_rule(0, SSL_kECDHE, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head,
1465                           &tail);
1466     ssl_cipher_apply_rule(0, SSL_kECDHE, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head,
1467                           &tail);
...
```

有必要仔细看下ssl\_cipher\_apply\_rule\(\)的代码：

```text
 773 static void ssl_cipher_apply_rule(uint32_t cipher_id, uint32_t alg_mkey,
 774                                   uint32_t alg_auth, uint32_t alg_enc,
 775                                   uint32_t alg_mac, int min_tls,
 776                                   uint32_t algo_strength, int rule,
 777                                   int32_t strength_bits, CIPHER_ORDER **head_p,
 778                                   CIPHER_ORDER **tail_p)
 779 {
 780     CIPHER_ORDER *head, *tail, *curr, *next, *last;
 781     const SSL_CIPHER *cp;
 782     int reverse = 0;
 783 
 784 #ifdef CIPHER_DEBUG
 785     fprintf(stderr,
 786             "Applying rule %d with %08x/%08x/%08x/%08x/%08x %08x (%d)\n",
 787             rule, alg_mkey, alg_auth, alg_enc, alg_mac, min_tls,
 788             algo_strength, strength_bits);
 789 #endif
 790 
 791     if (rule == CIPHER_DEL || rule == CIPHER_BUMP)
 792         reverse = 1;            /* needed to maintain sorting between currently
 793                                  * deleted ciphers */
 794 
 795     head = *head_p;
 796     tail = *tail_p;
 797 
 798     if (reverse) {
 799         next = tail;
 800         last = head;
 801     } else {
 802         next = head;
 803         last = tail;
 804     }
 805 
 806     curr = NULL;
```

795-806: 设置好链表head，tail和方向，准备遍历：

```text
 807     for (;;) {
 808         if (curr == last)
 809             break;
 810 
 811         curr = next;
 812 
 813         if (curr == NULL)
 814             break;
 815 
 816         next = reverse ? curr->prev : curr->next;
 817 
 818         cp = curr->cipher;
 819 
 820         /*
 821          * Selection criteria is either the value of strength_bits
 822          * or the algorithms used.
 823          */
 824         if (strength_bits >= 0) {
 825             if (strength_bits != cp->strength_bits)
 826                 continue;
 827         } else {
 828 #ifdef CIPHER_DEBUG
 829             fprintf(stderr,
 830                     "\nName: %s:\nAlgo = %08x/%08x/%08x/%08x/%08x Algo_strength = %08x\n",
 831                     cp->name, cp->algorithm_mkey, cp->algorithm_auth,
 832                     cp->algorithm_enc, cp->algorithm_mac, cp->min_tls,
 833                     cp->algo_strength);
 834 #endif
 835             if (cipher_id != 0 && (cipher_id != cp->id))
 836                 continue;
 837             if (alg_mkey && !(alg_mkey & cp->algorithm_mkey))
 838                 continue;
 839             if (alg_auth && !(alg_auth & cp->algorithm_auth))
 840                 continue;
 841             if (alg_enc && !(alg_enc & cp->algorithm_enc))
 842                 continue;
 843             if (alg_mac && !(alg_mac & cp->algorithm_mac))
 844                 continue;
 845             if (min_tls && (min_tls != cp->min_tls))
 846                 continue;
 847             if ((algo_strength & SSL_STRONG_MASK)
 848                 && !(algo_strength & SSL_STRONG_MASK & cp->algo_strength))
 849                 continue;
 850             if ((algo_strength & SSL_DEFAULT_MASK)
 851                 && !(algo_strength & SSL_DEFAULT_MASK & cp->algo_strength))
 852                 continue;
 853         }

```

824-853: 过滤掉不相关的cipher.

```text
 855 #ifdef CIPHER_DEBUG
 856         fprintf(stderr, "Action = %d\n", rule);
 857 #endif
 858 
 859         /* add the cipher if it has not been added yet. */
 860         if (rule == CIPHER_ADD) {
 861             /* reverse == 0 */
 862             if (!curr->active) {
 863                 ll_append_tail(&head, curr, &tail);
 864                 curr->active = 1;
 865             }
 866         }
 867         /* Move the added cipher to this location */
 868         else if (rule == CIPHER_ORD) {
 869             /* reverse == 0 */
 870             if (curr->active) {
 871                 ll_append_tail(&head, curr, &tail);
 872             }
 873         } else if (rule == CIPHER_DEL) {
 874             /* reverse == 1 */
 875             if (curr->active) {
 876                 /*
 877                  * most recently deleted ciphersuites get best positions for
 878                  * any future CIPHER_ADD (note that the CIPHER_DEL loop works
 879                  * in reverse to maintain the order)
 880                  */
 881                 ll_append_head(&head, curr, &tail);
 882                 curr->active = 0;
 883             }
 884         } else if (rule == CIPHER_BUMP) {
 885             if (curr->active)
 886                 ll_append_head(&head, curr, &tail);
 887         } else if (rule == CIPHER_KILL) {
 888             /* reverse == 0 */
 889             if (head == curr)
 890                 head = curr->next;
 891             else
 892                 curr->prev->next = curr->next;
 893             if (tail == curr)
 894                 tail = curr->prev;
 895             curr->active = 0;
 896             if (curr->next != NULL)
 897                 curr->next->prev = curr->prev;
 898             if (curr->prev != NULL)
 899                 curr->prev->next = curr->next;
 900             curr->next = NULL;
 901             curr->prev = NULL;
 902         }
 903     }
 904 
 905     *head_p = head;
 906     *tail_p = tail;
 907 }
```

860-866: 如果curr是未激活且rule == CIPHER\_ADD，就将其移动到队尾；

868-872: 如果curr是激活的且rule == CIPHER\_ORD，就将其移动到队尾；

873-883: 如果curr是未激活且rule == CIPHER\_DEL，就将其移动到队头；

884-886: 如果curr是激活的且rule == CIPHER\_BUMP，就将其移动到队头；

887-903: 如果rule == CIPHER\_KILL，从队列中删除curr。



### 2.3 SSL version的影响



### 2.4 API设置



### 2.5 Certificate load



### 



## 3. Client Cipher List



## 4. Server Cipher Selection



## 5. Sign Cipher



## 6. Key Exchange Cipher



## 7. Encryption/Decryption Cipher



## 8. Hash Cipher



