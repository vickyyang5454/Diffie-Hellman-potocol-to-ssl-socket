/* Author - @Nagaraj Poti
 * Roll no - 20162010
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <tomcrypt.h>

#define SERV_PORT 19000
#define MAX_LEN 1024
#define CAESAR_MOD 41	
#define LISTEN_Q 5

typedef struct GlobalInfo {
	int prime;
	int generator;
} GlobalInfo;

int compute_exp_modulo(int a, int b, int p) {
	long long x = 1, y = a;
	while (b > 0) {
		if (b % 2 == 1)
			x = (x * y) % p;
		y = (y * y) % p;
		b /= 2;
	}
	return (int)(x % p);
}

/* Convert encrypted character to plaintext character */
char caesar_decrypt(char c, int key) {
	char dict[] = {' ','A','B','C','D','E','F','G','H','I','J','K','L','M','N',
								'O','P','Q','R','S','T','U','V','W','X','Y','Z',',','.',
								'?','0','1','2','3','4','5','6','7','8','9','!'};
	for (int i = 0; i < CAESAR_MOD; i++) {
		if (dict[i] == c) 
			return dict[(CAESAR_MOD + i - key) % CAESAR_MOD];
	}
	return c;
}

void send_message(int sockfd, char message[MAX_LEN], int len) {
	int n_sent = 0;
	while (n_sent < len) {
		int temp;
		if ((temp = send(sockfd, message + n_sent, len - n_sent, 0)) <= 0) {
			perror("Error ");
			exit(-1);
		}
		n_sent += temp;
	}
}

int recv_message(int sockfd, char buffer[MAX_LEN], int recv_size) {
	int n_recv = 0;
	while (n_recv < recv_size) {
		int temp;
		if ((temp = recv(sockfd, buffer + n_recv, MAX_LEN - n_recv, 0)) <= 0) {
			if (temp == 0)
				break;
			perror("Error ");
			exit(-1);
		}
		n_recv += temp;
	}
	return n_recv;
}

int aes_256_gcm_decrypt(unsigned char* key, unsigned char* plain_text, int pt_len, unsigned char* enc_text, unsigned char* IV, int IV_len, unsigned char* tag, unsigned long tag_len)
{
	gcm_state gcm;
	register_cipher(&aes_desc);
//	unsigned char pass[32];
//	mp_to_unsigned_bin(key, pass);
	return gcm_memory(find_cipher("aes"), key, 32, IV, IV_len, NULL, 0, plain_text, pt_len, enc_text, tag, &tag_len, GCM_DECRYPT);
}
/* Server main program */
int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Please enter command line arguments [IP_ADDRESS]\n");
		exit(-1);
	}
	printf("----------------------------------------------------------------\n");
	printf("SERVER\n");	
	printf("----------------------------------------------------------------\n");
	printf("Server started! Waiting for connection from the client...\n\n");

	GlobalInfo g;

	/* Establish socket connection with the client */
	int server_sockfd, cli_sockfd;
	if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Error ");
		exit(-1);
	}
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERV_PORT);

	if (bind(server_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("Error ");
		exit(-1);
	}
	listen(server_sockfd, LISTEN_Q);

	while (1) {
		if ((cli_sockfd = accept(server_sockfd, NULL, NULL)) < 0) {
			perror("Error ");
			exit(-1);
		}
		printf("* Client connected!...\n\n");
		
		char buffer[MAX_LEN];
		memset(buffer, 0, sizeof(buffer));
		
		/* Receive key, generator and prime from client */
		int recv_size = sizeof(int) * 3 + sizeof(char) * 3;
		int n = recv_message(cli_sockfd, buffer, recv_size);
		int public_key_client = atoi(buffer);
		int i = 0;
		while (buffer[i] != '\n') 
			i++;
		g.prime = atoi(buffer + ++i);
		while (buffer[i] != '\n')
			i++;
		g.generator = atoi(buffer + ++i);
		printf("** Client public key : %d\n", public_key_client);
		printf("** Global prime : %d\n", g.prime);
		printf("** Global primitive root : %d\n\n", g.generator);

		/* Generate server private key and public key */
		int private_key = rand() % (g.prime - 1) + 1;
		int public_key = compute_exp_modulo(g.generator, private_key, g.prime);
		printf("*** Server private key : %d\n", private_key);
		printf("*** Server public key : %d\n\n", public_key);

		/* Send public_key to the client */
		n = sprintf(buffer, "%d\n", public_key);
		send_message(cli_sockfd, buffer, n); 
		char key[32];
		/* Compute shared key and caesar key */
		int shared_key = compute_exp_modulo(public_key_client, private_key, g.prime);
		//int caesar_key = shared_key % CAESAR_MOD;
		sprintf(key,"%d",shared_key);
		printf("**** Shared key : %d\n", shared_key);
		printf("**** AES key : %s\n\n", key);

		/* Receive encrypted text from client and write to output.txt file */
		printf("***** Receiving file from client...\n\n");
		FILE *output;
		if((output = fopen("output.txt","w")) < 0) {
			perror("Error ");
			exit(-1);
		}
		/*while ((n = recv_message(cli_sockfd, buffer, MAX_LEN)) > 0) {
			for (int i = 0; i < n; i++) {
				printf("%c", buffer[i]);
				buffer[i] = caesar_decrypt(buffer[i], caesar_key);
			}
			fwrite(buffer, sizeof(char), n, output);
		}*/
		n = recv_message(cli_sockfd, buffer, MAX_LEN);
		 unsigned char iv[32] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
      0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };

        	unsigned char tag[16] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
      0xde, 0xca, 0xf8, 0x88, 0x77, 0x74, 0x24,0x4b };
	        unsigned char *buff;
		buff = (unsigned char*)calloc(n, 1);
        	if (aes_256_gcm_decrypt(&key, buff, n, buffer, iv, 32, tag, 16) != CRYPT_OK)
        	{
                	printf("Error in encrypt!\n");
        	}
		fwrite(buffer, sizeof(char), n, output);



		fclose(output);
		printf("\n\n***** Finished receiving data from client!\n\n");
		printf("----------------------------------------------------------------\n");
		close(cli_sockfd);
	}
	return 0;
}

