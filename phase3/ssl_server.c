/************************************************************
 * ssl_server.c                                             *
 ************************************************************/
#include "ssl_server.h"

/*
 * OpenListener()
 * create server socket
 */
int
OpenListener(port)
	int port;
{
	int			sd;
	struct sockaddr_in 	addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family		= AF_INET;
	addr.sin_port		= htons(port);
	addr.sin_addr.s_addr	= INADDR_ANY;

	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		perror("can't bind port");
		exit(1);
	}
	if (listen(sd, 10) != 0) {
		perror("Can't configure listening port");
		exit(2);
	}
	return sd;
}

/*
 * serve_SSL_connection() - (contexts can be shared)
 * Serve the SSL connection.
 */
void
serve_SSL_connection(ssl)
	SSL* ssl;
{
	char		buf[BUF_LEN];
	char 		reply[BUF_LEN];
	int 		sd;
	int 		bytes;
	const char* 	SERV_REP="Welcome %s";

	if (SSL_accept(ssl) == -1) {				/* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	} else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);					/* get any certificates */
		check_cert_chain (ssl, CLIENT_HOST);
		bytes = SSL_read(ssl, buf, sizeof(buf));	/* get request */
		if (bytes > 0) {
			buf[bytes] = 0;
			printf("Client msg: \"%s\"\n", buf);
			sprintf(reply, SERV_REP, buf);		/* construct reply */
			SSL_write(ssl, reply, strlen(reply));	/* send reply */
		}
		else
			ERR_print_errors_fp(stderr);
	}
	sd = SSL_get_fd(ssl);					/* get socket connection */
	SSL_free(ssl);						/* release SSL state */
	close(sd);						/* close connection */
}

/*
 * main()
 * create SSL socket server.
 */
int
main(int argc, char *argv[])
{
	int 		server;
	char 		*portnum;
	SSL_CTX 	*ctx;

	if (argc != 2) {
		printf("Usage: %s <portnum>\n", argv[0]);
		exit(0);
	}
	portnum = argv[1];
	init_ssl_lib();						/* initialize SSL Lib*/
	ctx = init_SSL_ctx(SERVER_METHOD);			/* initialize Server context */
	LoadCertificates(ctx, SERVER_CERT, SERVER_KEY, ROOT_CALIST);/* load certs */
	server = OpenListener(atoi(portnum));			/* create server socket */
	while (1) {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;

		int client = accept(server, (struct sockaddr*)&addr, &len); /* accept connection as usual */
		printf("Connection: %s:%d\n",
				inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		ssl = SSL_new(ctx);				/* get new SSL state with context */
		SSL_set_fd(ssl, client);			/* set connection socket to SSL state */
		serve_SSL_connection(ssl);			/* service connection */
	}
	close(server);						/* close server socket */
	SSL_CTX_free(ctx);					/* release context */
	return 0;
}

