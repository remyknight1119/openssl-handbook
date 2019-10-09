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

```c
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

```c
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

```c
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

```c
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

```c
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

```c
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

```c
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

824-826: 如果设置了实际使用的密钥长度，则过滤掉密钥长度不一致的cipher.

835-853: 过滤掉不相关的cipher.

```c
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

回到ssl\_create\_cipher\_list\(\)函数，在调用了一堆ssl\_cipher\_apply\_rule\(\)函数来调整cipher list之后，

```c
1506 
1507     /*
1508      * Now sort by symmetric encryption strength.  The above ordering remains
1509      * in force within each class
1510      */
1511     if (!ssl_cipher_strength_sort(&head, &tail)) {
1512         OPENSSL_free(co_list);
1513         return NULL;
1514     }
1515 
1516     /*
1517      * Partially overrule strength sort to prefer TLS 1.2 ciphers/PRFs.
1518      * TODO(openssl-team): is there an easier way to accomplish all this?
1519      */
1520     ssl_cipher_apply_rule(0, 0, 0, 0, 0, TLS1_2_VERSION, 0, CIPHER_BUMP, -1,
1521                           &head, &tail);                 
1522 
1523     /*
1524      * Irrespective of strength, enforce the following order:
1525      * (EC)DHE + AEAD > (EC)DHE > rest of AEAD > rest.
1526      * Within each group, ciphers remain sorted by strength and previous
1527      * preference, i.e., 
1528      * 1) ECDHE > DHE    
1529      * 2) GCM > CHACHA
1530      * 3) AES > rest     
1531      * 4) TLS 1.2 > legacy
1532      *
1533      * Because we now bump ciphers to the top of the list, we proceed in
1534      * reverse order of preference.
1535      */                  
1536     ssl_cipher_apply_rule(0, 0, 0, 0, SSL_AEAD, 0, 0, CIPHER_BUMP, -1,
1537                           &head, &tail);                 
1538     ssl_cipher_apply_rule(0, SSL_kDHE | SSL_kECDHE, 0, 0, 0, 0, 0,
1539                           CIPHER_BUMP, -1, &head, &tail);
1540     ssl_cipher_apply_rule(0, SSL_kDHE | SSL_kECDHE, 0, 0, SSL_AEAD, 0, 0,
1541                           CIPHER_BUMP, -1, &head, &tail);
1542 
1543     /* Now disable everything (maintaining the ordering!) */
1544     ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail); 
1545 
```

1511: 根据对称加密算法的强度重新排序：

```c
 909 static int ssl_cipher_strength_sort(CIPHER_ORDER **head_p,
 910                                     CIPHER_ORDER **tail_p)
 911 {
 912     int32_t max_strength_bits;
 913     int i, *number_uses;
 914     CIPHER_ORDER *curr;
 915 
 916     /*
 917      * This routine sorts the ciphers with descending strength. The sorting
 918      * must keep the pre-sorted sequence, so we apply the normal sorting
 919      * routine as '+' movement to the end of the list.
 920      */
 921     max_strength_bits = 0;
 922     curr = *head_p;
 923     while (curr != NULL) {
 924         if (curr->active && (curr->cipher->strength_bits > max_strength_bits))
 925             max_strength_bits = curr->cipher->strength_bits;
 926         curr = curr->next;
 927     }
 928 
 929     number_uses = OPENSSL_zalloc(sizeof(int) * (max_strength_bits + 1));
 930     if (number_uses == NULL) {
 931         SSLerr(SSL_F_SSL_CIPHER_STRENGTH_SORT, ERR_R_MALLOC_FAILURE);
 932         return 0;
 933     }
 934 
 935     /*
 936      * Now find the strength_bits values actually used
 937      */
 938     curr = *head_p;
 939     while (curr != NULL) {
 940         if (curr->active)
 941             number_uses[curr->cipher->strength_bits]++;
 942         curr = curr->next;
 943     }
 944     /*
 945      * Go through the list of used strength_bits values in descending
 946      * order.
 947      */
 948     for (i = max_strength_bits; i >= 0; i--)
 949         if (number_uses[i] > 0)
 950             ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ORD, i, head_p,
 951                                   tail_p);
 952 
 953     OPENSSL_free(number_uses);
 954     return 1;
 955 }
```

923-927: 遍历链表找到各个算法所使用的最大密钥长度；

929-943: 将链表中所有cipher所使用不同密钥长度的数量记录在number\_uses\[\]数组中；

948-951: 倒序遍历number\_uses\[\]数组，按照密钥长度从大到小将链表重新排序。

再次回到ssl\_create\_cipher\_list\(\):

```c
1516     /*
1517      * Partially overrule strength sort to prefer TLS 1.2 ciphers/PRFs.
1518      * TODO(openssl-team): is there an easier way to accomplish all this?
1519      */
1520     ssl_cipher_apply_rule(0, 0, 0, 0, 0, TLS1_2_VERSION, 0, CIPHER_BUMP, -1,
1521                           &head, &tail);
1522 
1523     /*
1524      * Irrespective of strength, enforce the following order:
1525      * (EC)DHE + AEAD > (EC)DHE > rest of AEAD > rest.
1526      * Within each group, ciphers remain sorted by strength and previous
1527      * preference, i.e.,
1528      * 1) ECDHE > DHE
1529      * 2) GCM > CHACHA
1530      * 3) AES > rest
1531      * 4) TLS 1.2 > legacy
1532      *
1533      * Because we now bump ciphers to the top of the list, we proceed in
1534      * reverse order of preference.
1535      */
1536     ssl_cipher_apply_rule(0, 0, 0, 0, SSL_AEAD, 0, 0, CIPHER_BUMP, -1,
1537                           &head, &tail);
1538     ssl_cipher_apply_rule(0, SSL_kDHE | SSL_kECDHE, 0, 0, 0, 0, 0,
1539                           CIPHER_BUMP, -1, &head, &tail);
1540     ssl_cipher_apply_rule(0, SSL_kDHE | SSL_kECDHE, 0, 0, SSL_AEAD, 0, 0,
1541                           CIPHER_BUMP, -1, &head, &tail);
1542 
1543     /* Now disable everything (maintaining the ordering!) */
1544     ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail);
1545 
1546     /*
1547      * We also need cipher aliases for selecting based on the rule_str.
1548      * There might be two types of entries in the rule_str: 1) names
1549      * of ciphers themselves 2) aliases for groups of ciphers.
1550      * For 1) we need the available ciphers and for 2) the cipher
1551      * groups of cipher_aliases added together in one list (otherwise
1552      * we would be happy with just the cipher_aliases table).
1553      */
1554     num_of_group_aliases = OSSL_NELEM(cipher_aliases);
1555     num_of_alias_max = num_of_ciphers + num_of_group_aliases + 1;
1556     ca_list = OPENSSL_malloc(sizeof(*ca_list) * num_of_alias_max);
1557     if (ca_list == NULL) {
1558         OPENSSL_free(co_list);
1559         SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
1560         return NULL;          /* Failure */
1561     }
1562     ssl_cipher_collect_aliases(ca_list, num_of_group_aliases,
1563                                disabled_mkey, disabled_auth, disabled_enc,
1564                                disabled_mac, head);
```

1520-1521: 强行加入TLS 1.2的cipher;

1536-1541: 再加入几种与密钥长度无关的cipher;

1544: 至此构建完毕了一个cipher的全集，然后暂时disable链表中所有cipher，但保持链表的顺序;

```c
1546     /*
1547      * We also need cipher aliases for selecting based on the rule_str.
1548      * There might be two types of entries in the rule_str: 1) names
1549      * of ciphers themselves 2) aliases for groups of ciphers.
1550      * For 1) we need the available ciphers and for 2) the cipher
1551      * groups of cipher_aliases added together in one list (otherwise
1552      * we would be happy with just the cipher_aliases table).
1553      */
1554     num_of_group_aliases = OSSL_NELEM(cipher_aliases);
1555     num_of_alias_max = num_of_ciphers + num_of_group_aliases + 1;
1556     ca_list = OPENSSL_malloc(sizeof(*ca_list) * num_of_alias_max);
1557     if (ca_list == NULL) {
1558         OPENSSL_free(co_list);
1559         SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
1560         return NULL;          /* Failure */
1561     }
1562     ssl_cipher_collect_aliases(ca_list, num_of_group_aliases,
1563                                disabled_mkey, disabled_auth, disabled_enc,
1564                                disabled_mac, head);
```

1554-1561: 根据cipher\_aliases\[\]数组成员的数量建立一个ca\_list，用于根据规则字符串设置cipher list;

1562-1564: 将之前链表里面的cipher加入到ca\_list，并将cipher\_aliases\[\]数组中符合条件的cipher也加入进去；为什么要把cipher\_aliases\[\]也加进去？奇怪！

```c
1566     /*
1567      * If the rule_string begins with DEFAULT, apply the default rule
1568      * before using the (possibly available) additional rules.
1569      */
1570     ok = 1;
1571     rule_p = rule_str;
1572     if (strncmp(rule_str, "DEFAULT", 7) == 0) {
1573         ok = ssl_cipher_process_rulestr(SSL_DEFAULT_CIPHER_LIST,
1574                                         &head, &tail, ca_list, c);
1575         rule_p += 7;
1576         if (*rule_p == ':')
1577             rule_p++;
1578     }
1579 
1580     if (ok && (strlen(rule_p) > 0))
1581         ok = ssl_cipher_process_rulestr(rule_p, &head, &tail, ca_list, c);
1582 
1583     OPENSSL_free(ca_list);      /* Not needed anymore */
1584 
1585     if (!ok) {                  /* Rule processing failure */
1586         OPENSSL_free(co_list);
1587         return NULL;
1588     }
1589 
1590     /*
1591      * Allocate new "cipherstack" for the result, return with error
1592      * if we cannot get one.
1593      */
1594     if ((cipherstack = sk_SSL_CIPHER_new_null()) == NULL) {
1595         OPENSSL_free(co_list);
1596         return NULL;
1597     }
1598 
1599     /* Add TLSv1.3 ciphers first - we always prefer those if possible */
1600     for (i = 0; i < sk_SSL_CIPHER_num(tls13_ciphersuites); i++) {
1601         if (!sk_SSL_CIPHER_push(cipherstack,
1602                                 sk_SSL_CIPHER_value(tls13_ciphersuites, i))) {
1603             sk_SSL_CIPHER_free(cipherstack);
1604             return NULL;
1605         }
1606     }
1607 
1608     /*
1609      * The cipher selection for the list is done. The ciphers are added
1610      * to the resulting precedence to the STACK_OF(SSL_CIPHER).
1611      */
1612     for (curr = head; curr != NULL; curr = curr->next) {
1613         if (curr->active) {
1614             if (!sk_SSL_CIPHER_push(cipherstack, curr->cipher)) {
1615                 OPENSSL_free(co_list);
1616                 sk_SSL_CIPHER_free(cipherstack);
1617                 return NULL;
1618             }
1619 #ifdef CIPHER_DEBUG
1620             fprintf(stderr, "<%s>\n", curr->cipher->name);
1621 #endif
1622         }
1623     }
1624     OPENSSL_free(co_list);      /* Not needed any longer */
1625 
1626     if (!update_cipher_list_by_id(cipher_list_by_id, cipherstack)) {
1627         sk_SSL_CIPHER_free(cipherstack);
1628         return NULL;
1629     }
1630     sk_SSL_CIPHER_free(*cipher_list);
1631     *cipher_list = cipherstack;
1632 
1633     return cipherstack;
1634 }

```

1570-1588: 根据输入的rule\_str设置cipher list\(CIPHER\_DEL，CIPHER\_ORD，CIPHER\_KILL。CIPHER\_ADD\);

1594-1597: 申请一个cipherstack，将结果填进去;

1600-1606: 先填tls13\_ciphersuites\[\]数组的cipher，无论什么情况都是优先使用这些cipher的;

1612-1624: 将cipher list中的成员压入cipherstack\[\]中;

1626-1629: 将cipherstack复制一份给cipher\_list\_by\_id，并按照id顺序排序;

1630-1631: 释放之前的cipher\_list，将cipherstack赋给cipher\_list。

### 2.3 SSL API对ssl\_create\_cipher\_list\(\)的调用

ssl\_create\_cipher\_list\(\)共有4处调用:

#### 2.3.1 SSL\_CTX\_set\_ssl\_version\(\)

```c
 650 /** Used to change an SSL_CTXs default SSL method type */
 651 int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth)
 652 {   
 653     STACK_OF(SSL_CIPHER) *sk;
 654     
 655     ctx->method = meth;
 656 
 657     if (!SSL_CTX_set_ciphersuites(ctx, TLS_DEFAULT_CIPHERSUITES)) {
 658         SSLerr(SSL_F_SSL_CTX_SET_SSL_VERSION, SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS);
 659         return 0;
 660     }
 661     sk = ssl_create_cipher_list(ctx->method,
 662                                 ctx->tls13_ciphersuites,
 663                                 &(ctx->cipher_list),
 664                                 &(ctx->cipher_list_by_id),
 665                                 SSL_DEFAULT_CIPHER_LIST, ctx->cert);
 666     if ((sk == NULL) || (sk_SSL_CIPHER_num(sk) <= 0)) {
 667         SSLerr(SSL_F_SSL_CTX_SET_SSL_VERSION, SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS);
 668         return 0;
 669     }
 670     return 1;
 671 }   
```

这个函数的作用是：用TLS\_DEFAULT\_CIPHERSUITES设置ctx-&gt;tls13\_ciphersuites，再调用ssl\_create\_cipher\_list\(\)重新生成cipher list。这样就可以把TLS\_DEFAULT\_CIPHERSUITES对应的cipher list加进去了。

#### 2.3.2 SSL\_CTX\_set\_cipher\_list\(\)和SSL\_set\_cipher\_list\(\)

```c
2531 /** specify the ciphers to be used by default by the SSL_CTX */
2532 int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
2533 {
2534     STACK_OF(SSL_CIPHER) *sk;
2535 
2536     sk = ssl_create_cipher_list(ctx->method, ctx->tls13_ciphersuites,
2537                                 &ctx->cipher_list, &ctx->cipher_list_by_id, str,
2538                                 ctx->cert);
2539     /*
2540      * ssl_create_cipher_list may return an empty stack if it was unable to
2541      * find a cipher matching the given rule string (for example if the rule
2542      * string specifies a cipher which has been disabled). This is not an
2543      * error as far as ssl_create_cipher_list is concerned, and hence
2544      * ctx->cipher_list and ctx->cipher_list_by_id has been updated.
2545      */
2546     if (sk == NULL)
2547         return 0;
2548     else if (cipher_list_tls12_num(sk) == 0) {
2549         SSLerr(SSL_F_SSL_CTX_SET_CIPHER_LIST, SSL_R_NO_CIPHER_MATCH);
2550         return 0;
2551     }
2552     return 1;
2553 }
2554 
2555 /** specify the ciphers to be used by the SSL */
2556 int SSL_set_cipher_list(SSL *s, const char *str)
2557 {
2558     STACK_OF(SSL_CIPHER) *sk;
2559 
2560     sk = ssl_create_cipher_list(s->ctx->method, s->tls13_ciphersuites,
2561                                 &s->cipher_list, &s->cipher_list_by_id, str,
2562                                 s->cert);
2563     /* see comment in SSL_CTX_set_cipher_list */
2564     if (sk == NULL)
2565         return 0;
2566     else if (cipher_list_tls12_num(sk) == 0) {
2567         SSLerr(SSL_F_SSL_SET_CIPHER_LIST, SSL_R_NO_CIPHER_MATCH);
2568         return 0;
2569     }
2570     return 1;
2571 }
```

这两个函数的功能都是直接用str设置cipher list。

#### 2.3.3 SSL\_CTX\_new\(\)

```c
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
```

这是在SSL CTX初始化时设置cipher list，效果与SSL\_CTX\_set\_ssl\_version\(\)一致。

## 3. Cipher List in SSL handshake

### 3.1 ClientHello

ClientHello中会列出所有支持的Cipher, 这个功能是由tls\_construct\_client\_hello\(\)实现的：

```c
1104 int tls_construct_client_hello(SSL *s, WPACKET *pkt)
1105 {
1106     unsigned char *p;
...
1253     if (!ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), pkt)) {
1254         /* SSLfatal() already called */
1255         return 0;
1256     }
...
```

ssl\_cipher\_list\_to\_bytes\(\)将在ssl创建时就已经初始化好的cipher list转换成字符串：

```c
3729 int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk, WPACKET *pkt)
3730 {
3731     int i;
3732     size_t totlen = 0, len, maxlen, maxverok = 0;
3733     int empty_reneg_info_scsv = !s->renegotiate;
3734 
3735     /* Set disabled masks for this session */
3736     if (!ssl_set_client_disabled(s)) {
3737         SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CIPHER_LIST_TO_BYTES,
3738                  SSL_R_NO_PROTOCOLS_AVAILABLE);
3739         return 0;
3740     }
3741 
3742     if (sk == NULL) {
3743         SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CIPHER_LIST_TO_BYTES,
3744                  ERR_R_INTERNAL_ERROR);
3745         return 0;
3746     }
3747 
3748 #ifdef OPENSSL_MAX_TLS1_2_CIPHER_LENGTH
3749 # if OPENSSL_MAX_TLS1_2_CIPHER_LENGTH < 6
3750 #  error Max cipher length too short
3751 # endif
3752     /*
3753      * Some servers hang if client hello > 256 bytes as hack workaround
3754      * chop number of supported ciphers to keep it well below this if we
3755      * use TLS v1.2
3756      */
3757     if (TLS1_get_version(s) >= TLS1_2_VERSION)
3758         maxlen = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;
3759     else
3760 #endif
3761         /* Maximum length that can be stored in 2 bytes. Length must be even */
3762         maxlen = 0xfffe;
3763 
3764     if (empty_reneg_info_scsv)
3765         maxlen -= 2;
3766     if (s->mode & SSL_MODE_SEND_FALLBACK_SCSV)
3767         maxlen -= 2;
3768 
3769     for (i = 0; i < sk_SSL_CIPHER_num(sk) && totlen < maxlen; i++) {
3770         const SSL_CIPHER *c;
3771 
3772         c = sk_SSL_CIPHER_value(sk, i);
3773         /* Skip disabled ciphers */
3774         if (ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_SUPPORTED, 0))
3775             continue;
3776 
3777         if (!s->method->put_cipher_by_char(c, pkt, &len)) {
3778             SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CIPHER_LIST_TO_BYTES,
3779                      ERR_R_INTERNAL_ERROR);
3780             return 0;
3781         }
3782 
3783         /* Sanity check that the maximum version we offer has ciphers enabled */
3784         if (!maxverok) {
3785             if (SSL_IS_DTLS(s)) {
3786                 if (DTLS_VERSION_GE(c->max_dtls, s->s3->tmp.max_ver)
3787                         && DTLS_VERSION_LE(c->min_dtls, s->s3->tmp.max_ver))
3788                     maxverok = 1;
3789             } else {
3790                 if (c->max_tls >= s->s3->tmp.max_ver
3791                         && c->min_tls <= s->s3->tmp.max_ver)
3792                     maxverok = 1;
3793             }
3794         }
3795 
3796         totlen += len;
3797     }
3798 
3799     if (totlen == 0 || !maxverok) {
3800         SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CIPHER_LIST_TO_BYTES,
3801                  SSL_R_NO_CIPHERS_AVAILABLE);
3802 
3803         if (!maxverok)
3804             ERR_add_error_data(1, "No ciphers enabled for max supported "
3805                                   "SSL/TLS version");
3806 
3807         return 0;
3808     }
3809 
3810     if (totlen != 0) {
3811         if (empty_reneg_info_scsv) {
3812             static SSL_CIPHER scsv = {
3813                 0, NULL, NULL, SSL3_CK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
3814             };
3815             if (!s->method->put_cipher_by_char(&scsv, pkt, &len)) {
3816                 SSLfatal(s, SSL_AD_INTERNAL_ERROR,
3817                          SSL_F_SSL_CIPHER_LIST_TO_BYTES, ERR_R_INTERNAL_ERROR);
3818                 return 0;
3819             }
3820         }
3821         if (s->mode & SSL_MODE_SEND_FALLBACK_SCSV) {
3822             static SSL_CIPHER scsv = {
3823                 0, NULL, NULL, SSL3_CK_FALLBACK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
3824             };
3825             if (!s->method->put_cipher_by_char(&scsv, pkt, &len)) {
3826                 SSLfatal(s, SSL_AD_INTERNAL_ERROR,
3827                          SSL_F_SSL_CIPHER_LIST_TO_BYTES, ERR_R_INTERNAL_ERROR);
3828                 return 0;
3829             }
3830         }
3831     }
3832 
3833     return 1;
3834 }
```

3769-3681: 遍历所有cipher，将其转换成字符串后输出到ClientHello消息体中;

3784-3807: 如果没有一个cipher满足版本要求，则返回错误;

3811-3828: 添加特殊cipher.

ClientHello中会包含所有的cipher，并不受版本的限制；唯一一个与版本有关的限制是至少有一个cipher是版本范围\(min-max\)所支持的。

### 3.2 Server process ClientHello

#### 3.2.1 tls\_process\_client\_hello

```c
1364 MSG_PROCESS_RETURN tls_process_client_hello(SSL *s, PACKET *pkt)                                                                                                                                              
1365 {
1366     /* |cookie| will only be initialized for DTLS. */ 
1367     PACKET session_id, compression, extensions, cookie;
1368     static const unsigned char null_compression = 0;
1369     CLIENTHELLO_MSG *clienthello = NULL;            
...
1539         if (!PACKET_get_length_prefixed_2(pkt, &clienthello->ciphersuites)) {
1540             SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CLIENT_HELLO,
1541                      SSL_R_LENGTH_MISMATCH);
1542             goto err;
1543         }
1544 
...
1580     s->clienthello = clienthello;
1581 
1582     return MSG_PROCESS_CONTINUE_PROCESSING;
1583 
1584  err:
1585     if (clienthello != NULL)
1586         OPENSSL_free(clienthello->pre_proc_exts);
1587     OPENSSL_free(clienthello);
1588 
1589     return MSG_PROCESS_ERROR;
1590 }
```

这里只是把cipher suites的信息放到clienthello-&gt;ciphersuites里面，通过tls\_post\_process\_client\_hello\(\)调用tls\_early\_post\_process\_client\_hello\(\)来解析.

#### 3.2.2 tls\_early\_post\_process\_client\_hello

```c
1592 static int tls_early_post_process_client_hello(SSL *s)
1593 {
1594     unsigned int j;      
1595     int i, al = SSL_AD_INTERNAL_ERROR; 
1596     int protverr;
1597     size_t loop;
1598     unsigned long id;
1599 #ifndef OPENSSL_NO_COMP
1600     SSL_COMP *comp = NULL;
1601 #endif
1602     const SSL_CIPHER *c; 
1603     STACK_OF(SSL_CIPHER) *ciphers = NULL;
1604     STACK_OF(SSL_CIPHER) *scsvs = NULL;
1605     CLIENTHELLO_MSG *clienthello = s->clienthello;
...
1715     if (!ssl_cache_cipherlist(s, &clienthello->ciphersuites,
1716                               clienthello->isv2) ||
1717         !bytes_to_cipher_list(s, &clienthello->ciphersuites, &ciphers, &scsvs,
1718                               clienthello->isv2, 1)) {
1719         /* SSLfatal() already called */
1720         goto err;
1721     }
...
1754     /* For TLSv1.3 we must select the ciphersuite *before* session resumption */
1755     if (SSL_IS_TLS13(s)) {
1756         const SSL_CIPHER *cipher =
1757             ssl3_choose_cipher(s, ciphers, SSL_get_ciphers(s));
1758 
1759         if (cipher == NULL) {
1760             SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE,
1761                      SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
1762                      SSL_R_NO_SHARED_CIPHER);
1763             goto err;
1764         }
1765         if (s->hello_retry_request == SSL_HRR_PENDING
1766                 && (s->s3->tmp.new_cipher == NULL
1767                     || s->s3->tmp.new_cipher->id != cipher->id)) {
1768             /*
1769              * A previous HRR picked a different ciphersuite to the one we
1770              * just selected. Something must have changed.
1771              */
1772             SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
1773                      SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
1774                      SSL_R_BAD_CIPHER);
1775             goto err;
1776         }
1777         s->s3->tmp.new_cipher = cipher;
1778     }
...
1834     /*
1835      * If it is a hit, check that the cipher is in the list. In TLSv1.3 we check
1836      * ciphersuite compatibility with the session as part of resumption.
1837      */
1838     if (!SSL_IS_TLS13(s) && s->hit) {
1839         j = 0;
1840         id = s->session->cipher->id;
1841 
1842 #ifdef CIPHER_DEBUG
1843         fprintf(stderr, "client sent %d ciphers\n", sk_SSL_CIPHER_num(ciphers));
1844 #endif
1845         for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
1846             c = sk_SSL_CIPHER_value(ciphers, i);
1847 #ifdef CIPHER_DEBUG
1848             fprintf(stderr, "client [%2d of %2d]:%s\n",
1849                     i, sk_SSL_CIPHER_num(ciphers), SSL_CIPHER_get_name(c));
1850 #endif
1851             if (c->id == id) {
1852                 j = 1;
1853                 break;
1854             }
1855         }
1856         if (j == 0) {
1857             /*
1858              * we need to have the cipher in the cipher list if we are asked
1859              * to reuse it
1860              */
1861             SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
1862                      SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
1863                      SSL_R_REQUIRED_CIPHER_MISSING);
1864             goto err;
1865         }
1866     }
...
1910     if (!s->hit          
1911             && s->version >= TLS1_VERSION  
1912             && !SSL_IS_TLS13(s)            
1913             && !SSL_IS_DTLS(s)
1914             && s->ext.session_secret_cb) { 
1915         const SSL_CIPHER *pref_cipher = NULL;
1916         /*
1917          * s->session->master_key_length is a size_t, but this is an int for
1918          * backwards compat reasons
1919          */
1920         int master_key_length;
1921 
1922         master_key_length = sizeof(s->session->master_key);
1923         if (s->ext.session_secret_cb(s, s->session->master_key,
1924                                      &master_key_length, ciphers,
1925                                      &pref_cipher,
1926                                      s->ext.session_secret_cb_arg)
1927                 && master_key_length > 0) {
1928             s->session->master_key_length = master_key_length;
1929             s->hit = 1;
1930             s->session->ciphers = ciphers;
1931             s->session->verify_result = X509_V_OK;
1932 
1933             ciphers = NULL;
1934 
1935             /* check if some cipher was preferred by call back */
1936             if (pref_cipher == NULL)
1937                 pref_cipher = ssl3_choose_cipher(s, s->session->ciphers,
1938                                                  SSL_get_ciphers(s));
1939             if (pref_cipher == NULL) {
1940                 SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE,
1941                          SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
1942                          SSL_R_NO_SHARED_CIPHER);
1943                 goto err;
1944             }
1945 
1946             s->session->cipher = pref_cipher;
1947             sk_SSL_CIPHER_free(s->cipher_list);
1948             s->cipher_list = sk_SSL_CIPHER_dup(s->session->ciphers);
1949             sk_SSL_CIPHER_free(s->cipher_list_by_id);
1950             s->cipher_list_by_id = sk_SSL_CIPHER_dup(s->session->ciphers);
1951         }
1952     }
...
2049     /*
2050      * Given s->session->ciphers and SSL_get_ciphers, we must pick a cipher
2051      */
2052 
2053     if (!s->hit || SSL_IS_TLS13(s)) {
2054         sk_SSL_CIPHER_free(s->session->ciphers);
2055         s->session->ciphers = ciphers;
2056         if (ciphers == NULL) {
2057             SSLfatal(s, SSL_AD_INTERNAL_ERROR,
2058                      SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
2059                      ERR_R_INTERNAL_ERROR);
2060             goto err;
2061         }
2062         ciphers = NULL;
2063     }
...
```

1715-1716: 将cipher list的data copy到s-&gt;s3-&gt;tmp.ciphers\_raw中;

1717-1718: 将二进制cipher list data解析完毕后将结果放入ciphers变量中;

1755-1777: 如果是TLSv3，调用ssl3\_choose\_cipher\(\)在client cipher list和server cipher list中选出一个cipher，记录到s-&gt;s3-&gt;tmp.new\_cipher中;

1838-1864: 如果不是TLSv1.3且处于session reuse过程中，则检查新匹配到的cipher与之前使用的是否一致;

1910-1914: 如果：

1\) 不是session reuse;

2\) TLS 1.0, TLS 1.1, TLS 1.2;

3\) 通过SSL\_set\_session\_secret\_cb\(\)设置了预共享密钥callback.

1923-1950: 用经过callback认可的ciphers来选择最终的cipher.

2053-2055: 如果不是session reuse或者是TLSv1.3, 将ciphers保存到s-&gt;session-&gt;ciphers中.

#### 3.2.3 tls\_post\_process\_client\_hello

tls\_post\_process\_client\_hello\(\)需要做后续处理:

```c
2221 WORK_STATE tls_post_process_client_hello(SSL *s, WORK_STATE wst)
2222 {
2223     const SSL_CIPHER *cipher;
2224 
2225     if (wst == WORK_MORE_A) {
2226         int rv = tls_early_post_process_client_hello(s);
2227         if (rv == 0) {
2228             /* SSLfatal() was already called */
2229             goto err;
2230         }
2231         if (rv < 0)
2232             return WORK_MORE_A;
2233         wst = WORK_MORE_B;
2234     }
2235     if (wst == WORK_MORE_B) {
2236         if (!s->hit || SSL_IS_TLS13(s)) {
...
2259             /* In TLSv1.3 we selected the ciphersuite before resumption */
2260             if (!SSL_IS_TLS13(s)) {
2261                 cipher =
2262                     ssl3_choose_cipher(s, s->session->ciphers, SSL_get_ciphers(s));
2263 
2264                 if (cipher == NULL) {
2265                     SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE,
2266                              SSL_F_TLS_POST_PROCESS_CLIENT_HELLO,
2267                              SSL_R_NO_SHARED_CIPHER);
2268                     goto err;
2269                 }
2270                 s->s3->tmp.new_cipher = cipher;
2271             }
2272             if (!s->hit) {
2273                 if (!tls_choose_sigalg(s, 1)) {
2274                     /* SSLfatal already called */
2275                     goto err;
2276                 }
2277                 /* check whether we should disable session resumption */
2278                 if (s->not_resumable_session_cb != NULL)
2279                     s->session->not_resumable =
2280                         s->not_resumable_session_cb(s,
2281                             ((s->s3->tmp.new_cipher->algorithm_mkey
2282                               & (SSL_kDHE | SSL_kECDHE)) != 0));
2283                 if (s->session->not_resumable)
2284                     /* do not send a session ticket */
2285                     s->ext.ticket_expected = 0;
2286             }
2287         } else {
2288             /* Session-id reuse */
2289             s->s3->tmp.new_cipher = s->session->cipher;
2290         }
...
```

2260-2270: 如果不是session reuse且不是TLSv1.3，使用ssl3\_choose\_cipher\(\)选择一个cipher保存到s-&gt;s3-&gt;tmp.new\_cipher中;

2272-2275: 如果不是session reuse，调用tls\_choose\_sigalg\(\)选择签名算法;

2287-2289: 如果是session reuse，直接使用s-&gt;session-&gt;cipher.

总结：

| **成员变量** | **功能描述** |
| :--- | :--- |
| s-&gt;session-&gt;ciphers | client提供的cipiher list |
| s-&gt;cipher\_list | server自己的ciphier list |
| s-&gt;session-&gt;cipher | session reuse或使用预共享密钥时选择的cipher |
| s-&gt;s3-&gt;tmp.new\_cipher | 确定要使用的cipher |

#### 3.2.4 ssl3\_choose\_cipher

```c
4135 const SSL_CIPHER *ssl3_choose_cipher(SSL *s, STACK_OF(SSL_CIPHER) *clnt,
4136                                      STACK_OF(SSL_CIPHER) *srvr)
4137 {
4138     const SSL_CIPHER *c, *ret = NULL;
4139     STACK_OF(SSL_CIPHER) *prio, *allow;
4140     int i, ii, ok, prefer_sha256 = 0;
4141     unsigned long alg_k = 0, alg_a = 0, mask_k = 0, mask_a = 0;
4142     const EVP_MD *mdsha256 = EVP_sha256();
4143 #ifndef OPENSSL_NO_CHACHA
4144     STACK_OF(SSL_CIPHER) *prio_chacha = NULL;
4145 #endif
...
4171     /* SUITE-B takes precedence over server preference and ChaCha priortiy */
4172     if (tls1_suiteb(s)) {
4173         prio = srvr;
4174         allow = clnt;
4175     } else if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) {
4176         prio = srvr;
4177         allow = clnt;
4178 #ifndef OPENSSL_NO_CHACHA
4179         /* If ChaCha20 is at the top of the client preference list,
4180            and there are ChaCha20 ciphers in the server list, then
4181            temporarily prioritize all ChaCha20 ciphers in the servers list. */
4182         if (s->options & SSL_OP_PRIORITIZE_CHACHA && sk_SSL_CIPHER_num(clnt) > 0) {
4183             c = sk_SSL_CIPHER_value(clnt, 0);
4184             if (c->algorithm_enc == SSL_CHACHA20POLY1305) {
4185                 /* ChaCha20 is client preferred, check server... */
4186                 int num = sk_SSL_CIPHER_num(srvr);
4187                 int found = 0;
4188                 for (i = 0; i < num; i++) {
4189                     c = sk_SSL_CIPHER_value(srvr, i);
4190                     if (c->algorithm_enc == SSL_CHACHA20POLY1305) {
4191                         found = 1;
4192                         break;
4193                     }
4194                 }
4195                 if (found) {
4196                     prio_chacha = sk_SSL_CIPHER_new_reserve(NULL, num);
4197                     /* if reserve fails, then there's likely a memory issue */
4198                     if (prio_chacha != NULL) {
4199                         /* Put all ChaCha20 at the top, starting with the one we just found */
4200                         sk_SSL_CIPHER_push(prio_chacha, c);
4201                         for (i++; i < num; i++) {
4202                             c = sk_SSL_CIPHER_value(srvr, i);
4203                             if (c->algorithm_enc == SSL_CHACHA20POLY1305)
4204                                 sk_SSL_CIPHER_push(prio_chacha, c);
4205                         }
4206                         /* Pull in the rest */
4207                         for (i = 0; i < num; i++) {
4208                             c = sk_SSL_CIPHER_value(srvr, i);
4209                             if (c->algorithm_enc != SSL_CHACHA20POLY1305)
4210                                 sk_SSL_CIPHER_push(prio_chacha, c);
4211                         }
4212                         prio = prio_chacha;
4213                     }
4214                 }
4215             }
4216         }
4217 # endif
4218     } else {
4219         prio = clnt;
4220         allow = srvr;
4221     }
4222 
4223     if (SSL_IS_TLS13(s)) {
4224 #ifndef OPENSSL_NO_PSK
4225         int j;
4226 
4227         /*
4228          * If we allow "old" style PSK callbacks, and we have no certificate (so
4229          * we're not going to succeed without a PSK anyway), and we're in
4230          * TLSv1.3 then the default hash for a PSK is SHA-256 (as per the
4231          * TLSv1.3 spec). Therefore we should prioritise ciphersuites using
4232          * that.
4233          */
4234         if (s->psk_server_callback != NULL) {
4235             for (j = 0; j < SSL_PKEY_NUM && !ssl_has_cert(s, j); j++);
4236             if (j == SSL_PKEY_NUM) {
4237                 /* There are no certificates */
4238                 prefer_sha256 = 1;
4239             }
4240         }
4241 #endif
4242     } else {
4243         tls1_set_cert_validity(s);
4244         ssl_set_masks(s);
4245     }
4246 
4247     for (i = 0; i < sk_SSL_CIPHER_num(prio); i++) {
4248         c = sk_SSL_CIPHER_value(prio, i);
4249 
4250         /* Skip ciphers not supported by the protocol version */
4251         if (!SSL_IS_DTLS(s) &&
4252             ((s->version < c->min_tls) || (s->version > c->max_tls)))
4253             continue;
4254         if (SSL_IS_DTLS(s) &&
4255             (DTLS_VERSION_LT(s->version, c->min_dtls) ||
4256              DTLS_VERSION_GT(s->version, c->max_dtls)))
4257             continue;
4258 
4259         /*
4260          * Since TLS 1.3 ciphersuites can be used with any auth or
4261          * key exchange scheme skip tests.
4262          */
4263         if (!SSL_IS_TLS13(s)) {
4264             mask_k = s->s3->tmp.mask_k;
4265             mask_a = s->s3->tmp.mask_a;
4266 #ifndef OPENSSL_NO_SRP
4267             if (s->srp_ctx.srp_Mask & SSL_kSRP) {
4268                 mask_k |= SSL_kSRP;
4269                 mask_a |= SSL_aSRP;
4270             }
4271 #endif
4272 
4273             alg_k = c->algorithm_mkey;
4274             alg_a = c->algorithm_auth;
4275 
4276 #ifndef OPENSSL_NO_PSK
4277             /* with PSK there must be server callback set */
4278             if ((alg_k & SSL_PSK) && s->psk_server_callback == NULL)
4279                 continue;
4280 #endif                          /* OPENSSL_NO_PSK */
4281 
4282             ok = (alg_k & mask_k) && (alg_a & mask_a);
4283 #ifdef CIPHER_DEBUG
4284             fprintf(stderr, "%d:[%08lX:%08lX:%08lX:%08lX]%p:%s\n", ok, alg_k,
4285                     alg_a, mask_k, mask_a, (void *)c, c->name);
4286 #endif
4287 
4288 #ifndef OPENSSL_NO_EC
4289             /*
4290              * if we are considering an ECC cipher suite that uses an ephemeral
4291              * EC key check it
4292              */
4293             if (alg_k & SSL_kECDHE)
4294                 ok = ok && tls1_check_ec_tmp_key(s, c->id);
4295 #endif                          /* OPENSSL_NO_EC */
4296 
4297             if (!ok)
4298                 continue;
4299         }
4300         ii = sk_SSL_CIPHER_find(allow, c);
4301         if (ii >= 0) {
4302             /* Check security callback permits this cipher */
4303             if (!ssl_security(s, SSL_SECOP_CIPHER_SHARED,
4304                               c->strength_bits, 0, (void *)c))
4305                 continue;
4306 #if !defined(OPENSSL_NO_EC)
4307             if ((alg_k & SSL_kECDHE) && (alg_a & SSL_aECDSA)
4308                 && s->s3->is_probably_safari) {
4309                 if (!ret)
4310                     ret = sk_SSL_CIPHER_value(allow, ii);
4311                 continue;
4312             }
4313 #endif
4314             if (prefer_sha256) {
4315                 const SSL_CIPHER *tmp = sk_SSL_CIPHER_value(allow, ii);
4316 
4317                 if (ssl_md(tmp->algorithm2) == mdsha256) {
4318                     ret = tmp;
4319                     break;
4320                 }
4321                 if (ret == NULL)
4322                     ret = tmp;
4323                 continue;
4324             }
4325             ret = sk_SSL_CIPHER_value(allow, ii);
4326             break;
4327         }
4328     }
4329 #ifndef OPENSSL_NO_CHACHA
4330     sk_SSL_CIPHER_free(prio_chacha);
4331 #endif
4332     return ret;
4333 }
```

4172-4174: 如果启用了SUITE-B\(这是个什么东东？以后再调查\)，设置server cipher list优先；

4175-4177: 如果设置了SSL\_OP\_CIPHER\_SERVER\_PREFERENCE，设置server cipher list优先；

4182-4212: 如果设置了SSL\_OP\_PRIORITIZE\_CHACHA且client的cipher数量大于0，则将server cipher list中所有的ChaCha20系列的cipher移动到cipher list最前面；

4218-4220: 如果没有启用SUITE-B也没有设置SSL\_OP\_CIPHER\_SERVER\_PREFERENCE，设置client cipher list优先；

4223-4238: 如果是TLSv1.3，如果设置了psk\_server\_callback且没有证书，设置默认hash为SHA256；

4242-4244: 如果不是TLSv1.3，调用tls1\_set\_cert\_validity\(\)设置s-&gt;s3-&gt;tmp.valid\_flags数组，调用ssl\_set\_masks\(s\)设置s-&gt;s3-&gt;tmp.mask\_k和s-&gt;s3-&gt;tmp.mask\_a；

4247-4248: 遍历所有优先的cipher list;

4251-4257: 过滤掉不符合版本要求的cipher list;

4263-4299: 根据 mask\_k和mask\_a过滤cipher;

4300: 在allow队列中查找c，c是符合过滤条件的cipher；

4301-4311: 如果找到了，根据security等条件再过滤一次；

4314-4323: 如果之前设置了默认hash是SHA256，并且查找到的cipher的hash算法也是SHA256，则使用；否则过滤；

4325: 将查找到的cipher返回.

### 3.3 Certificate and Cipher

SSL server所加载的证书类型会影响cipher的选择，这个是通过tls1\_set\_cert\_validity\(\)和ssl\_set\_masks\(\)函数实现的：

```c
2363 /* Set validity of certificates in an SSL structure */
2364 void tls1_set_cert_validity(SSL *s)
2365 {
2366     tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_RSA);
2367     tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_RSA_PSS_SIGN);
2368     tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_DSA_SIGN);
2369     tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_ECC);
2370     tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_GOST01);
2371     tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_GOST12_256);
2372     tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_GOST12_512);
2373     tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_ED25519);
2374     tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_ED448);
2375 }
```

tls1\_check\_chain\(\)函数会根据证书，ClientHello的扩展信息等设置s-&gt;s3-&gt;tmp.valid\_flags：

```c
2119 int tls1_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain,
2120                      int idx)
2121 {
2122     int i;
2123     int rv = 0;
2124     int check_flags = 0, strict_mode;
2125     CERT_PKEY *cpk = NULL;
2126     CERT *c = s->cert;
2127     uint32_t *pvalid;
2128     unsigned int suiteb_flags = tls1_suiteb(s);
2129     /* idx == -1 means checking server chains */
2130     if (idx != -1) {
2131         /* idx == -2 means checking client certificate chains */
2132         if (idx == -2) {
2133             cpk = c->key;
2134             idx = (int)(cpk - c->pkeys);
2135         } else
2136             cpk = c->pkeys + idx;
2137         pvalid = s->s3->tmp.valid_flags + idx;
2138         x = cpk->x509;
2139         pk = cpk->privatekey;
2140         chain = cpk->chain;
2141         strict_mode = c->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT;
2142         /* If no cert or key, forget it */
2143         if (!x || !pk)
2144             goto end;
2145     } else {
2146         size_t certidx;
2147 
2148         if (!x || !pk)
2149             return 0;
2150 
2151         if (ssl_cert_lookup_by_pkey(pk, &certidx) == NULL)
2152             return 0;
2153         idx = certidx;
2154         pvalid = s->s3->tmp.valid_flags + idx;
2155 
2156         if (c->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)
2157             check_flags = CERT_PKEY_STRICT_FLAGS;
2158         else
2159             check_flags = CERT_PKEY_VALID_FLAGS;
2160         strict_mode = 1;
2161     }
2162 
2163     if (suiteb_flags) {
2164         int ok;
2165         if (check_flags)
2166             check_flags |= CERT_PKEY_SUITEB;
2167         ok = X509_chain_check_suiteb(NULL, x, chain, suiteb_flags);
2168         if (ok == X509_V_OK)
2169             rv |= CERT_PKEY_SUITEB;
2170         else if (!check_flags)
2171             goto end;
2172     }
2173 
2174     /*
2175      * Check all signature algorithms are consistent with signature
2176      * algorithms extension if TLS 1.2 or later and strict mode.
2177      */
2178     if (TLS1_get_version(s) >= TLS1_2_VERSION && strict_mode) {
2179         int default_nid;
2180         int rsign = 0;
2181         if (s->s3->tmp.peer_cert_sigalgs != NULL
2182                 || s->s3->tmp.peer_sigalgs != NULL) {
2183             default_nid = 0;
2184         /* If no sigalgs extension use defaults from RFC5246 */
2185         } else {
2186             switch (idx) {
2187             case SSL_PKEY_RSA:
2188                 rsign = EVP_PKEY_RSA;
2189                 default_nid = NID_sha1WithRSAEncryption;
2190                 break;
2191 
2192             case SSL_PKEY_DSA_SIGN:
2193                 rsign = EVP_PKEY_DSA;
2194                 default_nid = NID_dsaWithSHA1;
2195                 break;
2196 
2197             case SSL_PKEY_ECC:
2198                 rsign = EVP_PKEY_EC;
2199                 default_nid = NID_ecdsa_with_SHA1;
2200                 break;
2201 
2202             case SSL_PKEY_GOST01:
2203                 rsign = NID_id_GostR3410_2001;
2204                 default_nid = NID_id_GostR3411_94_with_GostR3410_2001;
2205                 break;
2206 
2207             case SSL_PKEY_GOST12_256:
2208                 rsign = NID_id_GostR3410_2012_256;
2209                 default_nid = NID_id_tc26_signwithdigest_gost3410_2012_256;
2210                 break;
2211 
2212             case SSL_PKEY_GOST12_512:
2213                 rsign = NID_id_GostR3410_2012_512;
2214                 default_nid = NID_id_tc26_signwithdigest_gost3410_2012_512;
2215                 break;
2216 
2217             default:
2218                 default_nid = -1;
2219                 break;
2220             }
2221         }
2222         /*
2223          * If peer sent no signature algorithms extension and we have set
2224          * preferred signature algorithms check we support sha1.
2225          */
2226         if (default_nid > 0 && c->conf_sigalgs) {
2227             size_t j;
2228             const uint16_t *p = c->conf_sigalgs;
2229             for (j = 0; j < c->conf_sigalgslen; j++, p++) {
2230                 const SIGALG_LOOKUP *lu = tls1_lookup_sigalg(*p);
2231 
2232                 if (lu != NULL && lu->hash == NID_sha1 && lu->sig == rsign)
2233                     break;
2234             }
2235             if (j == c->conf_sigalgslen) {
2236                 if (check_flags)
2237                     goto skip_sigs;
2238                 else
2239                     goto end;
2240             }
2241         }
2242         /* Check signature algorithm of each cert in chain */
2243         if (!tls1_check_sig_alg(c, x, default_nid)) {
2244             if (!check_flags)
2245                 goto end;
2246         } else
2247             rv |= CERT_PKEY_EE_SIGNATURE;
2248         rv |= CERT_PKEY_CA_SIGNATURE;
2249         for (i = 0; i < sk_X509_num(chain); i++) {
2250             if (!tls1_check_sig_alg(c, sk_X509_value(chain, i), default_nid)) {
2251                 if (check_flags) {
2252                     rv &= ~CERT_PKEY_CA_SIGNATURE;
2253                     break;
2254                 } else
2255                     goto end;
2256             }
2257         }
2258     }
2259     /* Else not TLS 1.2, so mark EE and CA signing algorithms OK */
2260     else if (check_flags)
2261         rv |= CERT_PKEY_EE_SIGNATURE | CERT_PKEY_CA_SIGNATURE;
2262  skip_sigs:
2263     /* Check cert parameters are consistent */
2264     if (tls1_check_cert_param(s, x, 1))
2265         rv |= CERT_PKEY_EE_PARAM;
2266     else if (!check_flags)
2267         goto end;
2268     if (!s->server)
2269         rv |= CERT_PKEY_CA_PARAM;
2270     /* In strict mode check rest of chain too */
2271     else if (strict_mode) {
2272         rv |= CERT_PKEY_CA_PARAM;
2273         for (i = 0; i < sk_X509_num(chain); i++) {
2274             X509 *ca = sk_X509_value(chain, i);
2275             if (!tls1_check_cert_param(s, ca, 0)) {
2276                 if (check_flags) {
2277                     rv &= ~CERT_PKEY_CA_PARAM;
2278                     break;
2279                 } else
2280                     goto end;
2281             }
2282         }
2283     }
2284     if (!s->server && strict_mode) {
2285         STACK_OF(X509_NAME) *ca_dn;
2286         int check_type = 0;
2287         switch (EVP_PKEY_id(pk)) {
2288         case EVP_PKEY_RSA:
2289             check_type = TLS_CT_RSA_SIGN;
2290             break;
2291         case EVP_PKEY_DSA:
2292             check_type = TLS_CT_DSS_SIGN;
2293             break;
2294         case EVP_PKEY_EC:
2295             check_type = TLS_CT_ECDSA_SIGN;
2296             break;
2297         }
2298         if (check_type) {
2299             const uint8_t *ctypes = s->s3->tmp.ctype;
2300             size_t j;
2301 
2302             for (j = 0; j < s->s3->tmp.ctype_len; j++, ctypes++) {
2303                 if (*ctypes == check_type) {
2304                     rv |= CERT_PKEY_CERT_TYPE;
2305                     break;
2306                 }
2307             }
2308             if (!(rv & CERT_PKEY_CERT_TYPE) && !check_flags)
2309                 goto end;
2310         } else {
2311             rv |= CERT_PKEY_CERT_TYPE;
2312         }
2313 
2314         ca_dn = s->s3->tmp.peer_ca_names;
2315 
2316         if (!sk_X509_NAME_num(ca_dn))
2317             rv |= CERT_PKEY_ISSUER_NAME;
2318 
2319         if (!(rv & CERT_PKEY_ISSUER_NAME)) {
2320             if (ssl_check_ca_name(ca_dn, x))
2321                 rv |= CERT_PKEY_ISSUER_NAME;
2322         }
2323         if (!(rv & CERT_PKEY_ISSUER_NAME)) {
2324             for (i = 0; i < sk_X509_num(chain); i++) {
2325                 X509 *xtmp = sk_X509_value(chain, i);
2326                 if (ssl_check_ca_name(ca_dn, xtmp)) {
2327                     rv |= CERT_PKEY_ISSUER_NAME;
2328                     break;
2329                 }
2330             }
2331         }
2332         if (!check_flags && !(rv & CERT_PKEY_ISSUER_NAME))
2333             goto end;
2334     } else
2335         rv |= CERT_PKEY_ISSUER_NAME | CERT_PKEY_CERT_TYPE;
2336 
2337     if (!check_flags || (rv & check_flags) == check_flags)
2338         rv |= CERT_PKEY_VALID;
2339 
2340  end:
2341 
2342     if (TLS1_get_version(s) >= TLS1_2_VERSION)
2343         rv |= *pvalid & (CERT_PKEY_EXPLICIT_SIGN | CERT_PKEY_SIGN);
2344     else
2345         rv |= CERT_PKEY_SIGN | CERT_PKEY_EXPLICIT_SIGN;
2346 
2347     /*
2348      * When checking a CERT_PKEY structure all flags are irrelevant if the
2349      * chain is invalid.
2350      */
2351     if (!check_flags) {
2352         if (rv & CERT_PKEY_VALID) {
2353             *pvalid = rv;
2354         } else {
2355             /* Preserve sign and explicit sign flag, clear rest */
2356             *pvalid &= CERT_PKEY_EXPLICIT_SIGN | CERT_PKEY_SIGN;
2357             return 0;
2358         }
2359     }
2360     return rv;
2361 }
```

2130-2141: 如果idx不是-1， 则设置一些变量，其中最重要的是pvalid；

2143-2144: 如果ssl没有加载idx指定类型的证书，则退出；

2145-2160: 如果idx等于-1，意味着需要检查server证书链，需要通过ssl\_cert\_lookup\_by\_pkey\(\)查找pk对应ssl\_cert\_info\[\]数组成员的下标；在tls1\_set\_cert\_validity\(\)上下文中这个分支不会走到；

2163-3171:

2178: 如果是TLSv1.2和TLSv1.3且是严格模式；

2181-2183: 如果ClientHello带有TLSEXT\_TYPE\_signature\_algorithms扩展，则设置default\_nid为0；

2185-2219: 否则根据idx的类型设置rsign和default\_nid；

2226-2239:

2243-2247: 检查idx对应类型的证书中的签名算法是否与TLSEXT\_TYPE\_signature\_algorithms扩展与server自身的共享签名算法一致；如果一致则将CERT\_PKEY\_EE\_SIGNATURE设置在rv上;

2248: 设置CA签名算法标记在rv上;

2249-2255: 检查证书链里每个证书中的签名算法是否与TLSEXT\_TYPE\_signature\_algorithms扩展与server自身的共享签名算法一致；

2260-2261: 如果不是TLSv1.2和TLSv1.3，不是严格模式且需要检查server证书链，则将EE和CA签名算法标记设置在rv上；

2264-2267: 检查idx对应类型的证书的其它参数是否一致；

2271-2280: 如果是严格模式，检查证书链中证书的参数；

2284-2333: 如果不是server且是严格模式，设置rv;

2334-2335: 否则设置CERT\_PKEY\_ISSUER\_NAME和CERT\_PKEY\_CERT\_TYPE到rv上；

2337-2338: 如果没有设置check\_flags\(idx != -1\)或check\_flags的所有值都已经设置到rv上，则设置CERT\_PKEY\_VALID到rv上；

2342-2345: 根据TLS的版本设置rv；

2351-2359: 如果没有设置check\_flags\(idx != -1\)，设置s-&gt;s3-&gt;tmp.valid\_flags\[\]数组.

ssl\_set\_masks\(\)函数根据s-&gt;s3-&gt;tmp.valid\_flags\[\]数组的值来设置mask\_k和mask\_a：

```c
3234 void ssl_set_masks(SSL *s)
3235 {
3236     CERT *c = s->cert;
3237     uint32_t *pvalid = s->s3->tmp.valid_flags;
3238     int rsa_enc, rsa_sign, dh_tmp, dsa_sign;
3239     unsigned long mask_k, mask_a;  
3240 #ifndef OPENSSL_NO_EC
3241     int have_ecc_cert, ecdsa_ok;   
3242 #endif
3243     if (c == NULL)
3244         return;
3245 
3246 #ifndef OPENSSL_NO_DH    
3247     dh_tmp = (c->dh_tmp != NULL || c->dh_tmp_cb != NULL || c->dh_tmp_auto);
3248 #else
3249     dh_tmp = 0;
3250 #endif
3251 
3252     rsa_enc = pvalid[SSL_PKEY_RSA] & CERT_PKEY_VALID;
3253     rsa_sign = pvalid[SSL_PKEY_RSA] & CERT_PKEY_VALID;
3254     dsa_sign = pvalid[SSL_PKEY_DSA_SIGN] & CERT_PKEY_VALID;
3255 #ifndef OPENSSL_NO_EC    
3256     have_ecc_cert = pvalid[SSL_PKEY_ECC] & CERT_PKEY_VALID;
3257 #endif
3258     mask_k = 0;
3259     mask_a = 0;
3260 
3261 #ifdef CIPHER_DEBUG
3262     fprintf(stderr, "dht=%d re=%d rs=%d ds=%d\n",
3263             dh_tmp, rsa_enc, rsa_sign, dsa_sign);
3264 #endif
3265 
3266 #ifndef OPENSSL_NO_GOST  
3267     if (ssl_has_cert(s, SSL_PKEY_GOST12_512)) {
3268         mask_k |= SSL_kGOST;
3269         mask_a |= SSL_aGOST12;
3270     }
3271     if (ssl_has_cert(s, SSL_PKEY_GOST12_256)) {
3272         mask_k |= SSL_kGOST;
3273         mask_a |= SSL_aGOST12;
3274     }
3275     if (ssl_has_cert(s, SSL_PKEY_GOST01)) {
3276         mask_k |= SSL_kGOST;
3277         mask_a |= SSL_aGOST01;
3278     }
3279 #endif
3280 
3281     if (rsa_enc)
3282         mask_k |= SSL_kRSA;
3283 
3284     if (dh_tmp)
3285         mask_k |= SSL_kDHE;
3286 
3287     /*
3288      * If we only have an RSA-PSS certificate allow RSA authentication
3289      * if TLS 1.2 and peer supports it.
3290      */
3291 
3292     if (rsa_enc || rsa_sign || (ssl_has_cert(s, SSL_PKEY_RSA_PSS_SIGN)
3293                 && pvalid[SSL_PKEY_RSA_PSS_SIGN] & CERT_PKEY_EXPLICIT_SIGN
3294                 && TLS1_get_version(s) == TLS1_2_VERSION))
3295         mask_a |= SSL_aRSA;
3296 
3297     if (dsa_sign) {
3298         mask_a |= SSL_aDSS;
3299     }
3300 
3301     mask_a |= SSL_aNULL;
3302 
3303     /*
3304      * An ECC certificate may be usable for ECDH and/or ECDSA cipher suites
3305      * depending on the key usage extension.
3306      */
3307 #ifndef OPENSSL_NO_EC
3308     if (have_ecc_cert) {
3309         uint32_t ex_kusage;
3310         ex_kusage = X509_get_key_usage(c->pkeys[SSL_PKEY_ECC].x509);
3311         ecdsa_ok = ex_kusage & X509v3_KU_DIGITAL_SIGNATURE;
3312         if (!(pvalid[SSL_PKEY_ECC] & CERT_PKEY_SIGN))
3313             ecdsa_ok = 0;
3314         if (ecdsa_ok)
3315             mask_a |= SSL_aECDSA;
3316     }
3317     /* Allow Ed25519 for TLS 1.2 if peer supports it */
3318     if (!(mask_a & SSL_aECDSA) && ssl_has_cert(s, SSL_PKEY_ED25519)
3319             && pvalid[SSL_PKEY_ED25519] & CERT_PKEY_EXPLICIT_SIGN
3320             && TLS1_get_version(s) == TLS1_2_VERSION)
3321             mask_a |= SSL_aECDSA;
3322 
3323     /* Allow Ed448 for TLS 1.2 if peer supports it */
3324     if (!(mask_a & SSL_aECDSA) && ssl_has_cert(s, SSL_PKEY_ED448)
3325             && pvalid[SSL_PKEY_ED448] & CERT_PKEY_EXPLICIT_SIGN
3326             && TLS1_get_version(s) == TLS1_2_VERSION)
3327             mask_a |= SSL_aECDSA;
3328 #endif
3329 
3330 #ifndef OPENSSL_NO_EC
3331     mask_k |= SSL_kECDHE;
3332 #endif
3333 
3334 #ifndef OPENSSL_NO_PSK
3335     mask_k |= SSL_kPSK;
3336     mask_a |= SSL_aPSK;
3337     if (mask_k & SSL_kRSA)
3338         mask_k |= SSL_kRSAPSK;
3339     if (mask_k & SSL_kDHE)
3340         mask_k |= SSL_kDHEPSK;
3341     if (mask_k & SSL_kECDHE)
3342         mask_k |= SSL_kECDHEPSK;
3343 #endif
3344 
3345     s->s3->tmp.mask_k = mask_k;
3346     s->s3->tmp.mask_a = mask_a;
3347 }
```

3252-3256: 获取多个算法的标记；只有相应类型的证书支持这些标记才会存在；

3267-3277: 检查SSL是否上载了GOST系列证书，如果有则设置mask\_k和mask\_a标记；

3281-3282:

3284-3285: 

3292-3295:

3297-3298:

3301:

### 3.4 ServerHello

在使用tls\_construct\_server\_hello\(\)构建ServerHello时SSL server将确定要使用的cipher写入消息体:

```c
2347 int tls_construct_server_hello(SSL *s, WPACKET *pkt)
2348 {
2349     int compm;
2350     size_t sl, len;
2351     int version;
2352     unsigned char *session_id;
2353     int usetls13 = SSL_IS_TLS13(s) || s->hello_retry_request == SSL_HRR_PENDING;
...
2417     if (!WPACKET_sub_memcpy_u8(pkt, session_id, sl)
2418             || !s->method->put_cipher_by_char(s->s3->tmp.new_cipher, pkt, &len)
2419             || !WPACKET_put_bytes_u8(pkt, compm)) {
2420         SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_SERVER_HELLO,
2421                  ERR_R_INTERNAL_ERROR);
2422         return 0;
2423     }
...
```

### 3.5 Client process ServerHello





## 4. Signature Algorithm



## 5. Key Exchange Algorithm



## 6. Encryption/Decryption Algorighm



## 7. Hash Algorithm



