# Chapter 2 QAT Engine

## 2.1 Makefile

如果不使用QAT Engine自带的工具生成Makefile，可以使用下面这个Makefile:

```text
TOPDIR=../../..
OPENSSL_TOP_DIR=$(TOPDIR)/$(CONFIG_FORTIDEV)
QAT_ENGINE_DIR=$(TOPDIR)/migbase/ssl/qat
QAT_ROOT=$(abspath $(LINUX_EXTRA_MODULE_SOURCE_DIR)/quickassist)
QAT_USDM=$(QAT_ROOT)/utilities/libusdm_drv
QAT_ICP_API=$(QAT_ROOT)/include
QAT_ICP_LAC_API=$(QAT_ICP_API)/lac
QAT_ICP_SAL_API=$(QAT_ROOT)/lookaside/access_layer/include

QAT_SHARED_LIB_DEPS_DRIVER = -L$(QAT_ROOT)/build/ -lqat_s
QAT_SHARED_LIB_DEPS_QAE_MEM = -L$(QAT_USDM)/ -lusdm_drv_s
QAT_SHARED_LIB_DEPS_UDEV = -L$(CONFIG_FORTIDEV)/lib -ludev

#cflags_enable_upstream_driver = -DOPENSSL_ENABLE_QAT_UPSTREAM_DRIVER
#cflags_enable_usdm = -DUSE_QAE_MEM
#cflags_qat_debug_file = /var/log/qat.log
#enable_multi_thread =
#enable_openssl_install_build_arch_path =
#enable_qat_auto_engine_init_on_fork =
#enable_qat_ciphers = -DOPENSSL_ENABLE_QAT_CIPHERS
#enable_qat_debug = yes
#enable_qat_dh = -DOPENSSL_ENABLE_QAT_DH
#enable_qat_dsa = -DOPENSSL_ENABLE_QAT_DSA
#enable_qat_ecdh = -DOPENSSL_ENABLE_QAT_ECDH
#enable_qat_ecdsa = -DOPENSSL_ENABLE_QAT_ECDSA
#enable_qat_for_openssl_102 =
#enable_qat_for_openssl_110 = yes
#enable_qat_lenstra_protection =
#enable_qat_mem_debug =
#enable_qat_mem_warnings =
#enable_qat_mux =
#enable_qat_prf = -DOPENSSL_ENABLE_QAT_PRF
#enable_qat_rsa = -DOPENSSL_ENABLE_QAT_RSA
#enable_qat_small_pkt_offload =
#enable_qat_warnings =
#enable_upstream_driver = yes
#enable_usdm = yes
#enable_qat_for_openssl_110 = yes
#includes = -I$(with_openssl_dir)/include
#includes_enable_qat_mux =

#include_enable_usdm = -I$(with_usdm_dir)
#includes_driver = -I$(with_ICP_API_DIR) -I$(with_ICP_LAC_API_DIR) -I$(with_ICP_SAL_API_DIR)
#with_ICP_API_DIR = $(with_qat_dir)/include
#with_ICP_DC_DIR =
#with_ICP_LAC_API_DIR = $(with_ICP_API_DIR)/lac
#with_ICP_MUX_DIR =
#with_ICP_SAL_API_DIR = $(with_qat_dir)/lookaside/access_layer/include
#with_usdm_dir = $(with_qat_dir)/utilities/libusdm_drv
#with_qat_install_dir = $(with_qat_dir)/build



INCLUDES= -I. -I$(QAT)/include  -I$(OPENSSL_TOP_DIR) -I$(OPENSSL_TOP_DIR)/include \
		  -I$(OPENSSL_TOP_DIR)/crypto/include \
		  -I$(QAT_USDM) -I$(QAT_ICP_SAL_API) -I$(QAT_ICP_API) \
		  -I$(QAT_ICP_LAC_API) -I$(QAT_ENGINE_DIR)/qat_contig_mem
CFLAG	= -O3 -DOPENSSL_ENABLE_QAT_UPSTREAM_DRIVER -DUSE_QAE_MEM \
		  -DOPENSSL_ENABLE_QAT_CIPHERS -DOPENSSL_ENABLE_QAT_DH -DOPENSSL_ENABLE_QAT_DSA -DOPENSSL_ENABLE_QAT_ECDH \
		  -DOPENSSL_ENABLE_QAT_ECDSA -DOPENSSL_ENABLE_QAT_PRF -DOPENSSL_ENABLE_QAT_RSA -DQAT_HW \
		  -DOPENSSL_DISABLE_QAT_HKDF -DUSE_USDM_MEM -fPIC
		  #-DQAT_DEBUG -DQAT_DEBUG_FILE_PATH=/var/log/qat.log -DQAT_WARN -DOPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS

EXTRA_CFLAGS += $(INCLUDES) $(CFLAG)
EXTRA_LDFLAGS = $(QAT_SHARED_LIB_DEPS_DRIVER) $(QAT_SHARED_LIB_DEPS_QAE_MEM) $(QAT_SHARED_LIB_DEPS_UDEV)

TARGET_SO = libqat.so
OBJECTS_SO = e_qat.o \
			 e_qat_err.o \
			 qat_events.o \
			 qat_evp.o \
			 qat_fork.o \
			 qat_hw_asym_common.o \
			 qat_hw_callback.o \
			 qat_hw_ciphers.o \
			 qat_hw_dh.o \
			 qat_hw_dsa.o \
			 qat_hw_ec.o \
			 qat_hw_ecx.o \
			 qat_hw_gcm.o \
			 qat_hw_hkdf.o \
			 qat_hw_init.o \
			 qat_hw_polling.o \
			 qat_hw_prf.o \
			 qat_hw_rsa.o \
			 qat_hw_rsa_crt.o \
			 qat_hw_usdm_inf.o \
			 qat_sys_call.o \
			 qat_utils.o
#			 qat_sw_ec.o \
			 qat_sw_ecx.o \
			 qat_sw_freelist.o \
			 qat_sw_gcm.o \
			 qat_sw_init.o \
			 qat_sw_ipsec_inf.o \
			 qat_sw_polling.o \
			 qat_sw_queue.o \
			 qat_sw_rsa.o \
			 qat_prov_err.o \
			 qat_hw_multi_thread_inf.o \
			 qae_mem_utils.o \
	

TARGET_SO_LIBS = -lcrypto

CLEAN_RULE=1

include $(TOPDIR)/rules.Make

```

## 2.2 bind\_qat\(\)

使用no-hack方式load QAT Engine，是从bind\_qat\(\)函数开始执行的\(详见[1.1 Load Engine](https://app.gitbook.com/@remyknight/s/workspace/~/drafts/-MiMrUr8vQjV4arjHW_r/part5-ssl-accelerate/chapter-1-intel-qat/1.1-load-engine)\):

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

## 2.3 Engine Init



## 2.4 Work Flow



## 2.5 Engine Mode



