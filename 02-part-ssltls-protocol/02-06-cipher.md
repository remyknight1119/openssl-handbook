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

824-826: 如果设置了实际使用的密钥长度，则过滤掉密钥长度不一致的cipher.

835-853: 过滤掉不相关的cipher.

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

回到ssl\_create\_cipher\_list\(\)函数，在调用了一堆ssl\_cipher\_apply\_rule\(\)函数来调整cipher list之后，

```text
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

```text
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

```text
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

```text
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

```text
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

```text
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

```text
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
```

这是在SSL CTX初始化时设置cipher list，效果与SSL\_CTX\_set\_ssl\_version\(\)一致。

## 3. Client Cipher List



## 4. Server Cipher Selection



## 5. Sign Cipher



## 6. Key Exchange Cipher



## 7. Encryption/Decryption Cipher



## 8. Hash Cipher



