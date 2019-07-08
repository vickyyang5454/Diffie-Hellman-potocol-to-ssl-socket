/************************************************************
 * ssl_client.c                                             *
 ************************************************************/
#include "ssl_client.h"

/*
 * open_socket_connection()
 * create socket and connect to server.
 */
int
open_socket_connection(hostname, port)
	const char *hostname;
	int port;
{
	int			sd;
	struct hostent 		*host;
	struct sockaddr_in 	addr;

	if ((host = gethostbyname(hostname)) == NULL) {
		perror(hostname);
		exit(1);
	}

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family		= AF_INET;
	addr.sin_port		= htons(port);
	addr.sin_addr.s_addr	= *(long*)(host->h_addr);

	if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		close(sd);
		perror(hostname);
		exit(2);
	}
	return sd;
}

/*
 * init_client_ctx()
 * Initialize the SSL engine.
 */
SSL_CTX*
init_client_ctx(void)
{
	const SSL_METHOD	*method;
	SSL_CTX			*ctx;

	method = TLSv1_2_client_method();			/* Create new client-method instance */
	ctx = SSL_CTX_new(method);				/* Create new context */
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	return ctx;
}

/*
 * main()
 * create SSL context and connect
 */
int
main(int argc, char *argv[])
{
	int		server;
	int		bytes;
	char		*hostname;
	char		*portnum;
	char		buf[BUF_LEN];
	SSL_CTX		*ctx;
	SSL		*ssl;

	if (argc != 3) {
		printf("usage: %s <hostname> <portnum>\n", argv[0]);
		exit(0);
	}

	hostname = argv[1];
	portnum = argv[2];

	init_ssl_lib();						/* initialize SSL lib */
	ctx = init_SSL_ctx(CLIENT_METHOD);			/* initialize Client context*/
	LoadCertificates(ctx, CLIENT_CERT, CLIENT_KEY, ROOT_CALIST);/* load certs */
	server = open_socket_connection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);					/* create new SSL connection state */
	SSL_set_fd(ssl, server);				/* attach the socket descriptor */
	if (SSL_connect(ssl) == -1) {				/* perform the connection */
		ERR_print_errors_fp(stderr);
	} else {
		char *msg = "Client";

		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);					/* get any certs */
		check_cert_chain (ssl, SERVER_HOST);
		SSL_write(ssl, msg, strlen(msg));		/* encrypt & send message */
		bytes = SSL_read(ssl, buf, sizeof(buf));	/* get reply & decrypt */
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);
		SSL_free(ssl);					/* release connection state */
	}
	close(server);						/* close socket */
	SSL_CTX_free(ctx);					/* release context */
	return 0;
}

