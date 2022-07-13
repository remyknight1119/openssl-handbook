# Chapter 2 QAT Engine

## 2.1 bind\_qat()

使用no-hack方式load QAT Engine，是从bind\_qat()函数开始执行的(详见[1.1 Load Engine](https://app.gitbook.com/@remyknight/s/workspace/\~/drafts/-MiMrUr8vQjV4arjHW\_r/part5-ssl-accelerate/chapter-1-intel-qat/1.1-load-engine)):

```c
 789 /******************************************************************************
 790  * function:
 791  *         bind_qat(ENGINE *e,
 792  *                  const char *id)
 793  *
 794  * @param e  [IN] - OpenSSL engine pointer
 795  * @param id [IN] - engine id
 796  *
 797  * description:
 798  *    Connect Qat engine to OpenSSL engine library
 799  ******************************************************************************/
 800 static int bind_qat(ENGINE *e, const char *id)
 801 {
 802     int ret = 0;
 803 
 804 #ifdef OPENSSL_QAT_OFFLOAD
 805     char *config_section = NULL;
 806 #endif
 807     QAT_DEBUG_LOG_INIT();
 808 
 809     WARN("QAT Warnings enabled.\n");
 810     DEBUG("QAT Debug enabled.\n");
 811     WARN("%s - %s \n", id, engine_qat_name);
 812 
 813 #if defined(OPENSSL_QAT_OFFLOAD) && !defined(QAT_DRIVER_INTREE)
 814     if (access(QAT_DEV, F_OK) != 0) {
 815         WARN("Qat memory driver not present\n");
 816         QATerr(QAT_F_BIND_QAT, QAT_R_MEM_DRV_NOT_PRESENT);
 817         goto end;
 818     }
 819 #endif
 820     
 821     if (id && (strcmp(id, engine_qat_id) != 0)) {
 822         WARN("ENGINE_id defined already! %s - %s\n", id, engine_qat_id);
 823         QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_ID_ALREADY_DEFINED);
 824         goto end;
 825     }
 826     
 827     if (!ENGINE_set_id(e, engine_qat_id)) {
 828         WARN("ENGINE_set_id failed\n");
 829         QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_ID_FAILURE);
 830         goto end;
 831     }
 832     
 833     if (!ENGINE_set_name(e, engine_qat_name)) {
 834         WARN("ENGINE_set_name failed\n");
 835         QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_NAME_FAILURE);
 836         goto end;
 837     }
 838 
 839     /* Ensure the QAT error handling is set up */
 840     ERR_load_QAT_strings();
 841 
 842 #ifdef OPENSSL_QAT_OFFLOAD
 843 
 844 # ifdef QAT_INTREE
 845     if (icp_sal_userIsQatAvailable() == CPA_TRUE) {
 846 # endif
 847         DEBUG("Registering QAT supported algorithms\n");
 848         qat_offload = 1;
 849 
 850         /* Create static structures for ciphers now
 851          * as this function will be called by a single thread. */
 852         qat_create_ciphers();
 853 
 854         if (!ENGINE_set_RSA(e, qat_get_RSA_methods())) {
 855             WARN("ENGINE_set_RSA failed\n");
 856             QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_RSA_FAILURE);
 857             goto end;
 858         }
 859 
 860         if (!ENGINE_set_DSA(e, qat_get_DSA_methods())) {
 861             WARN("ENGINE_set_DSA failed\n");
 862             QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_DSA_FAILURE);
 863             goto end;
 864         }
 865 
 866         if (!ENGINE_set_DH(e, qat_get_DH_methods())) {
 867             WARN("ENGINE_set_DH failed\n");
 868             QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_DH_FAILURE);
 869             goto end;
 870         }
 871 
 872         if (!ENGINE_set_EC(e, qat_get_EC_methods())) {
 873             WARN("ENGINE_set_EC failed\n");
 874             QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_EC_FAILURE);
 875             goto end;
 876         }
 877 
 878         if (!ENGINE_set_pkey_meths(e, qat_pkey_methods)) {
 879             WARN("ENGINE_set_pkey_meths failed\n");
 880             QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_PKEY_FAILURE);
 881             goto end;
 882         }
 883 # ifdef QAT_INTREE
 884     }
 885 # endif
 886 #endif
 887 
 888 #ifdef OPENSSL_MULTIBUFF_OFFLOAD
 889     if (!qat_offload) {
 890         if (mbx_get_algo_info(MBX_ALGO_RSA_2K)) {
 891             DEBUG("Multibuffer RSA Supported\n");
 892             if (!ENGINE_set_RSA(e, multibuff_get_RSA_methods())) {
 893                 WARN("ENGINE_set_RSA failed\n");
 894                 QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_RSA_FAILURE);
 895                 goto end;
 896             }
 897         }
 898         if (mbx_get_algo_info(MBX_ALGO_X25519)) {
 899             DEBUG("Multibuffer X25519 Supported\n");
 900             if (!ENGINE_set_pkey_meths(e, multibuff_x25519_pkey_methods)) {
 901                 WARN("ENGINE_set_pkey_meths failed\n");
 902                 QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_X25519_FAILURE);
 903                 goto end;
 904             }
 905         }
 906     }
 907 #endif
 908 
 909 #ifdef OPENSSL_IPSEC_OFFLOAD
 910     if (!hw_support()) {
 911         WARN("The Processor does not support the features needed for VAES.\n");
 912         QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_HW_NOT_SUPPORTED);
 913         goto end;
 914     }
 915 # ifndef OPENSSL_DISABLE_VAES_GCM
 916     if (!vaesgcm_init_ipsec_mb_mgr()) {
 917         WARN("IPSec Multi-Buffer Manager Initialization failed\n");
 918         QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_GCM_CIPHERS_FAILURE);
 919         goto end;
 920     }
 921 # endif
 922 #endif
 923 
 924 #if defined(OPENSSL_QAT_OFFLOAD) || defined(OPENSSL_IPSEC_OFFLOAD)
 925     if (!ENGINE_set_ciphers(e, qat_ciphers)) {
 926         WARN("ENGINE_set_ciphers failed\n");
 927         QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_SET_CIPHER_FAILURE);
 928         goto end;
 929     }
 930 #endif
 931 
 932     pthread_atfork(engine_finish_before_fork_handler, NULL,
 933                    engine_init_child_at_fork_handler);
 934 
 935     ret = 1;
 936     ret &= ENGINE_set_destroy_function(e, qat_engine_destroy);
 937     ret &= ENGINE_set_init_function(e, qat_engine_init);
 938     ret &= ENGINE_set_ctrl_function(e, qat_engine_ctrl);
 939     ret &= ENGINE_set_finish_function(e, qat_engine_finish);
 940     ret &= ENGINE_set_cmd_defns(e, qat_cmd_defns);
 941     if (ret == 0) {
 942         WARN("Engine failed to register init, finish or destroy functions\n");
 943         QATerr(QAT_F_BIND_QAT, QAT_R_ENGINE_REGISTER_FUNC_FAILURE);
 944     }
 945 
 946     /*
 947      * If the QAT_SECTION_NAME environment variable is set, use that.
 948      * Similar setting made through engine ctrl command takes precedence
 949      * over this environment variable. It makes sense to use the environment
 950      * variable because the container orchestrators pass down this
 951      * configuration as environment variables.
 952      */
 953 
 954 #ifdef OPENSSL_QAT_OFFLOAD
 955 # ifdef __GLIBC_PREREQ
 956 #  if __GLIBC_PREREQ(2, 17)
 957     config_section = secure_getenv("QAT_SECTION_NAME");
 958 #  else
 959     config_section = getenv("QAT_SECTION_NAME");
 960 #  endif
 961 # else
 962     config_section = getenv("QAT_SECTION_NAME");
 963 # endif
 964     if (validate_configuration_section_name(config_section)) {
 965         strncpy(qat_config_section_name, config_section, QAT_CONFIG_SECTION_NAME_SIZE - 1);
 966         qat_config_section_name[QAT_CONFIG_SECTION_NAME_SIZE - 1]   = '\0';
 967     }
 968 #endif
 969 
 970  end:
 971     return ret;
 972 
 973 }
```

854-878: 设置RSA, DSA, DH, EC, pKey的method, 这样当相关函数被调用时就会通过Engine框架调到这些method。

## 2.2 Engine Init

```c
352 int qat_init(ENGINE *e)
353 {
354     int instNum, err;
355     CpaStatus status = CPA_STATUS_SUCCESS;
356     int ret_pthread_sigmask;
357     Cpa32U package_id = 0;
...
370     qat_polling_thread = pthread_self();                                                                                                                                                                                                  
371 
372     if ((err = pthread_key_create(&thread_local_variables, qat_local_variable_destructor)) != 0) {                                                                                                                                        
373         WARN("pthread_key_create failed: %s\n", strerror(err));
374         QATerr(QAT_F_QAT_INIT, QAT_R_PTHREAD_CREATE_FAILURE);
375         qat_pthread_mutex_unlock();    
376         return 0;
377     }
378 
379     /* Initialise the QAT hardware */ 
380     if (CPA_STATUS_SUCCESS !=
381         icp_sal_userStart(ICPConfigSectionName_libcrypto)) {
382         WARN("icp_sal_userStart failed\n");
383         QATerr(QAT_F_QAT_INIT, QAT_R_ICP_SAL_USERSTART_FAIL);
384         pthread_key_delete(thread_local_variables);
385         qat_pthread_mutex_unlock();    
386         return 0;
387     }
388 
389     /* Get the number of available instances */
390     status = cpaCyGetNumInstances(&qat_num_instances);
391     if (CPA_STATUS_SUCCESS != status) {
392         WARN("cpaCyGetNumInstances failed, status=%d\n", status);
393         QATerr(QAT_F_QAT_INIT, QAT_R_GET_NUM_INSTANCE_FAILURE);
394         qat_pthread_mutex_unlock();
395         qat_engine_finish(e);
396         return 0;
397     }
398     if (!qat_num_instances) {
399         WARN("No crypto instances found\n");
400         QATerr(QAT_F_QAT_INIT, QAT_R_INSTANCE_UNAVAILABLE);
401         qat_pthread_mutex_unlock();
402         qat_engine_finish(e);
403         return 0;
404     }
405 
406     DEBUG("Found %d Cy instances\n", qat_num_instances);
407 
408     /* Allocate memory for the instance handle array */
409     qat_instance_handles =
410         (CpaInstanceHandle *) OPENSSL_zalloc(((int)qat_num_instances) *
411                                              sizeof(CpaInstanceHandle));
412     if (NULL == qat_instance_handles) {
413         WARN("OPENSSL_zalloc() failed for instance handles.\n");
414         QATerr(QAT_F_QAT_INIT, QAT_R_INSTANCE_HANDLE_MALLOC_FAILURE);
415         qat_pthread_mutex_unlock();
416         qat_engine_finish(e);
417         return 0;
418     }
419 
420     /* Get the Cy instances */
421     status = cpaCyGetInstances(qat_num_instances, qat_instance_handles);
422     if (CPA_STATUS_SUCCESS != status) {
423         WARN("cpaCyGetInstances failed, status=%d\n", status);
424         QATerr(QAT_F_QAT_INIT, QAT_R_GET_INSTANCE_FAILURE);
425         qat_pthread_mutex_unlock();
426         qat_engine_finish(e);
427         return 0;
428     }
429 
430     if (!enable_external_polling && !enable_inline_polling) {
431 #ifndef __FreeBSD__
432         if (qat_is_event_driven()) {
433             CpaStatus status;
434             int flags;
435             int engine_fd;
436 
437             /*   Add the file descriptor to an epoll event list */
438             internal_efd = epoll_create1(0);
439             if (-1 == internal_efd) {
440                 WARN("Error creating epoll fd\n");
441                 QATerr(QAT_F_QAT_INIT, QAT_R_EPOLL_CREATE_FAILURE);
442                 qat_pthread_mutex_unlock();
443                 qat_engine_finish(e);
444                 return 0;
445             }
446 
447             for (instNum = 0; instNum < qat_num_instances; instNum++) {
448                 /*   Get the file descriptor for the instance */
449                 status =
450                     icp_sal_CyGetFileDescriptor(qat_instance_handles[instNum],
451                                                 &engine_fd);
452                 if (CPA_STATUS_FAIL == status) {
453                     WARN("Error getting file descriptor for instance\n");
454                     QATerr(QAT_F_QAT_INIT, QAT_R_GET_FILE_DESCRIPTOR_FAILURE);
455                     qat_pthread_mutex_unlock();
456                     qat_engine_finish(e);
457                     return 0;
458                 }
459                 /*   Make the file descriptor non-blocking */
460                 eng_poll_st[instNum].eng_fd = engine_fd;
461                 eng_poll_st[instNum].inst_index = instNum;
462 
463                 flags = qat_fcntl(engine_fd, F_GETFL, 0);
464                 if (qat_fcntl(engine_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
465                     WARN("Failed to set engine_fd as NON BLOCKING\n");
466                     QATerr(QAT_F_QAT_INIT,
467                            QAT_R_SET_FILE_DESCRIPTOR_NONBLOCKING_FAILURE);
468                     qat_pthread_mutex_unlock();
469                     qat_engine_finish(e);
470                     return 0;
471                 }
472 
473                 eng_epoll_events[instNum].data.ptr = &eng_poll_st[instNum];
474                 eng_epoll_events[instNum].events = EPOLLIN | EPOLLET;
475                 if (-1 ==
476                     epoll_ctl(internal_efd, EPOLL_CTL_ADD, engine_fd,
477                               &eng_epoll_events[instNum])) {
478                     WARN("Error adding fd to epoll\n");
479                     QATerr(QAT_F_QAT_INIT, QAT_R_EPOLL_CTL_FAILURE);
480                     qat_pthread_mutex_unlock();
481                     qat_engine_finish(e);
482                     return 0;
483                 }
484             }
485         }
486 #endif
487     }
488 
489     /* Set translation function and start each instance */
490     for (instNum = 0; instNum < qat_num_instances; instNum++) {
491         /* Retrieve CpaInstanceInfo2 structure for that instance */
492         status = cpaCyInstanceGetInfo2(qat_instance_handles[instNum],
493                                        &qat_instance_details[instNum].qat_instance_info);
494         if (CPA_STATUS_SUCCESS != status ) {
495             WARN("cpaCyInstanceGetInfo2 failed. status = %d\n", status);
496             QATerr(QAT_F_QAT_INIT, QAT_R_GET_INSTANCE_INFO_FAILURE);
497             qat_pthread_mutex_unlock();
498             qat_engine_finish(e);
499             return 0;
500         }
501 
502         package_id = qat_instance_details[instNum].qat_instance_info.physInstId.packageId;
503         qat_accel_details[package_id].qat_accel_present = 1;
504         if (package_id >= qat_num_devices) {
505             qat_num_devices = package_id + 1;
506         }
507 
508         /* Set the address translation function */
509         status = cpaCySetAddressTranslation(qat_instance_handles[instNum],
510                                             virtualToPhysical);
511         if (CPA_STATUS_SUCCESS != status) {
512             WARN("cpaCySetAddressTranslation failed, status=%d\n", status);
513             QATerr(QAT_F_QAT_INIT, QAT_R_SET_ADDRESS_TRANSLATION_FAILURE);
514             qat_pthread_mutex_unlock();
515             qat_engine_finish(e);
516             return 0;
517         }
518 
519         /* Start the instances */
520         status = cpaCyStartInstance(qat_instance_handles[instNum]);
521         if (CPA_STATUS_SUCCESS != status) {
522             WARN("cpaCyStartInstance failed, status=%d\n", status);
523             QATerr(QAT_F_QAT_INIT, QAT_R_START_INSTANCE_FAILURE);
524             qat_pthread_mutex_unlock();
525             qat_engine_finish(e);
526             return 0;
527         }
528 
529         qat_instance_details[instNum].qat_instance_started = 1;
530         DEBUG("Started Instance No: %d Located on Device: %d\n", instNum, package_id);
531 
532 #if !defined(__FreeBSD__) && !defined(QAT_DRIVER_INTREE)
533         if (enable_sw_fallback) {
534             DEBUG("cpaCyInstanceSetNotificationCb instNum = %d\n", instNum);
535             status = cpaCyInstanceSetNotificationCb(qat_instance_handles[instNum],
536                                                     qat_instance_notification_callbackFn,
537                                                     (void *)(intptr_t)instNum);
538             if (CPA_STATUS_SUCCESS != status) {
539                 WARN("cpaCyInstanceSetNotificationCb failed, status=%d\n", status);
540                 QATerr(QAT_F_QAT_INIT, QAT_R_SET_NOTIFICATION_CALLBACK_FAILURE);
541                 qat_pthread_mutex_unlock();
542                 qat_engine_finish(e);
543                 return 0;
544             }
545         }
546 #endif
547     }
548 
549     if (!enable_external_polling && !enable_inline_polling) {
550         if (!qat_is_event_driven()) {
551             sigemptyset(&set);
552             sigaddset(&set, SIGUSR1);
553             ret_pthread_sigmask = pthread_sigmask(SIG_BLOCK, &set, NULL);
554             if (ret_pthread_sigmask != 0) {
555                 WARN("pthread_sigmask error\n");
556                 QATerr(QAT_F_QAT_INIT, QAT_R_POLLING_THREAD_SIGMASK_FAILURE);
557                 qat_pthread_mutex_unlock();
558                 qat_engine_finish(e);
559                 return 0;
560             }
561         }
562 #ifndef __FreeBSD__
563         if (qat_create_thread(&qat_polling_thread, NULL, qat_is_event_driven() ?
564                               event_poll_func : qat_timer_poll_func, NULL)) {
565 #else
566         if (qat_create_thread(&qat_polling_thread, NULL, qat_timer_poll_func, NULL)) {
567 #endif
568             WARN("Creation of polling thread failed\n");
569             QATerr(QAT_F_QAT_INIT, QAT_R_POLLING_THREAD_CREATE_FAILURE);
570             qat_polling_thread = pthread_self();
571             qat_pthread_mutex_unlock();
572             qat_engine_finish(e);
573             return 0;
574         }
575         if (qat_adjust_thread_affinity(qat_polling_thread) == 0) {
576             WARN("Setting polling thread affinity failed\n");
577             QATerr(QAT_F_QAT_INIT, QAT_R_SET_POLLING_THREAD_AFFINITY_FAILURE);
578             qat_pthread_mutex_unlock();
579             qat_engine_finish(e);
580             return 0;
581         }
582         if (!qat_is_event_driven()) {
583             while (!cleared_to_start)
584                 sleep(1);
585         }
586     }
587     return 1;
588 }
```

## 2.3 Work Flow



## 2.4 Engine Mode

