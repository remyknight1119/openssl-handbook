# Chapter 8 Session reuse

TLS1.3 session reuse:

```text
    len = SSL_read(ssl, buffer, sizeof(buffer));
    if (len > 0 && strcmp(buffer, DV_TEST_RESP) == 0) {
        printf("Client接收消息成功:'%s',共%d 个字节的数据\n",
                buffer, len);
    } else {
        printf("Client消息接收失败!错误代码是%d,错误信息是'%s', len = %d\n",
                errno, strerror(errno), len);
        ret = DV_ERROR;
        goto out;
    }

	  sess = SSL_get1_session(ssl);
	  if (sess == NULL) {
          ERR_print_errors_fp(stderr);
		      goto out;
	  }
	  SSL_SESSION_get0_ticket(sess, &tick, &tick_len);
	  printf("==================================================\n");
	  print_data((unsigned char *)tick, tick_len);
  	printf("==================================================\n");
  	printf("tick len = %d\n", (int)tick_len);
  	printf("ticket = %d\n", SSL_SESSION_has_ticket(sess));

    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");
    printf("address created\n");
    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)dest, sizeof(*dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");
    ssl = SSL_new(ctx);
  	SSL_set_session(ssl, sess);

    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
		    goto out;
    }

```

