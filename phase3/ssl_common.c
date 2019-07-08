#include "ssl_common.h"

BIO *bio_err = 0;

/*
 * A simple error and exit routine
 */
int
err_exit(string)
	char 			*string;
{
	fprintf(stderr, "%s\n", string);
	exit(0);
}

/*
 * Print SSL errors and exit
 */
int
berr_exit(string)
	char 			*string;
{
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(0);
}

/*
 * init_ssl_lib()
 * Inititalize SSL library
 */
void
init_ssl_lib(void)
{
	if (!bio_err) {
		SSL_library_init();				/* Load SSL Library*/
		OpenSSL_add_all_algorithms();			/* load & register all cryptos, etc. */
		SSL_load_error_strings();			/* load all error messages */
		/* An error write context */
		bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
	}
}

int
verify_callback(ok, store)
	int 			ok;
	X509_STORE_CTX 		*store;
{
	char data[256];
	/* if (ok) to debug */
	printf ("In verify_callback %d\n", ok);
	if (!ok)
	{
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int depth = X509_STORE_CTX_get_error_depth(store);
		int err = X509_STORE_CTX_get_error(store);
		fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
		X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
		fprintf(stderr, " issuer = %s\n", data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
		fprintf(stderr, " subject = %s\n", data);
		fprintf(stderr, " err %i:%s\n", err, X509_verify_cert_error_string(err));
	}
	return ok;
}

/*
 * LoadCertificates()
 * Load Certificates form files.
 */
void
LoadCertificates(ctx, CertFile, KeyFile, CA_LIST)
	SSL_CTX* 	ctx;
	char* 		CertFile;
	char* 		KeyFile;
	char*		CA_LIST;
{
	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(5);
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		exit(6);
	}

	/* Load the CAs we trust */
	SSL_CTX_load_verify_locations (ctx, CA_LIST, 0);
	SSL_CTX_set_verify_depth (ctx, 1);
	SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
}

/*
 * ShowCerts()
 * Show Certificates of peer (Slient)
 */
void
ShowCerts(ssl)
	SSL* ssl;
{
	X509 		*cert;
	char 		*line;

	cert = SSL_get_peer_certificate(ssl);			/* Get certificates (if available) */
	if (cert != NULL) {
		printf("Peer Certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	} else {
		printf("No certificates.\n");
	}
}

void
check_cert_chain (ssl, host)
	SSL 	*ssl;
	char 	*host;
{
	X509 *peer;
	char peer_CN[256];
	if ( SSL_get_verify_result (ssl) != X509_V_OK ) {
		err_exit ("Certificate doesn't verify");
	}

	/*Check the common name*/
	peer = SSL_get_peer_certificate (ssl);
	X509_NAME_get_text_by_NID (X509_get_subject_name (peer), NID_commonName, peer_CN, 256);
	printf("peer_CN :: %s\n", peer_CN);
	if (strcasecmp (peer_CN, host)) {
		err_exit ("Common name doesn't match host name");
	}
}

/*
 * init_SSL_ctx()
 * Initialize SSL server/client and create SSL context
 */
SSL_CTX*
init_SSL_ctx(is_srv_cli_meth)
        int is_srv_cli_meth;
{
        const SSL_METHOD        *method;
        SSL_CTX                 *ctx;

        if (is_srv_cli_meth == SERVER_METHOD) {
                method = TLSv1_2_server_method();                       /* create new server-method instance */
        } else if (is_srv_cli_meth == CLIENT_METHOD) {
                method = TLSv1_2_client_method();                       /* Create new client-method instance */
        } else {
                perror("Wrong Method");
                exit(3);
        }

        ctx = SSL_CTX_new(method);                              /* create new context from method */
        if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                exit(4);
        }
        return ctx;
}
