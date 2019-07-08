/************************************************************
 * ssl_common.h                                             *
 ************************************************************/
#ifndef __SSL_COMMON_H_
#define __SSL_COMMON_H_

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <netinet/in.h>

#define BUF_LEN		1024
#define SERVER_METHOD 	1
#define CLIENT_METHOD	2
#define SERVER_HOST	"server"
#define CLIENT_HOST	"client"

int err_exit (char *string);
int berr_exit (char *string);
int verify_callback (int ok, X509_STORE_CTX *store);

void init_ssl_lib (void);
void LoadCertificates (SSL_CTX* ctx, char* CertFile, char* KeyFile, char* CA_LIST);
void ShowCerts (SSL* ssl);
void check_cert_chain (SSL *ssl, char *host);

SSL_CTX* init_SSL_ctx (int is_srv_cli_meth);

#endif
