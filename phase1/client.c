/* Author - @Nagaraj Poti
 * Roll no - 20162010
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <math.h>
#include <ctype.h>
#include <tomcrypt.h>

#define SERV_PORT 19000
#define MAX_LEN 1024
#define MAXSIZE 1000000
#define CAESAR_MOD 41
#define M_ITERATION 15

typedef struct GlobalInfo {
	int prime;
	int generator;
} GlobalInfo;

/* Function to compute (a ^ b) mod p */
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

/* Function to check primality of random generated numbers using Miller-Rabin Test */
int MillerRabinTest(int value, int iteration) {
	if (value < 2)
		return 0;
	int q = value - 1, k = 0;
	while (!(q % 2)) {
		q /= 2;
		k++;
	}
	for (int i = 0; i < iteration; i++) {
		int a = rand() % (value - 1) + 1;
		int current = q;
		int flag = 1;
		int mod_result = compute_exp_modulo(a, current, value);
		for (int i = 1; i <= k; i++) {
			if (mod_result == 1 || mod_result == value - 1) {
				flag = 0;
				break;
			}
			mod_result = (int)((long long)mod_result * mod_result % value);
		}
		if (flag)
			return 0;
	}
	return 1;
}

/* Generate a prime number that is going to be shared 
 * globally between client and server
 */
int GeneratePrime() {
	printf("* Running Miller-Rabin test to find a large prime number...\n\n");
	srand(time(NULL));
	while(1) {
		int current_value = rand() % INT_MAX;
		if (!(current_value % 2))
			current_value++;
		if (MillerRabinTest(current_value, M_ITERATION) == 1)
			return current_value;
	}
}

/* Generate the primitive root by checking for random numbers */
int GeneratePrimitiveRoot(int p) {
	/* Construct sieve of primes */
	int sieve[MAXSIZE];
	memset(sieve, 0, sizeof(sieve));
	sieve[0] = sieve[1] = 1;
	for (int i = 4; i < MAXSIZE; i += 2)
		sieve[i] = 1;
	for (int i = 3; i < MAXSIZE; i += 2) {
		if (!sieve[i]) {
			for (int j = 2 * i; j < MAXSIZE; j += i)
				sieve[j] = 1;
		}
	}
	while (1) {
		int a = rand() % (p - 2) + 2;
		int phi = p - 1, flag = 1, root = sqrt(phi);
		for (int i = 2; i <= root; i++) {
			if (!sieve[i] && !(phi % i)) {
				int mod_result = compute_exp_modulo(a, phi / i, p);
				if (mod_result == 1) {
					flag = 0;
					break;
				}
				if (MillerRabinTest(phi / i, M_ITERATION) && !(phi % (phi / i))) {
					int mod_result = compute_exp_modulo(a, phi / (phi / i), p);
					if (mod_result == 1) {
						flag = 0;
						break;
					}
				}
			}
		}
		if (flag) 
			return a;
	}
}

/* Convert character to encrypted character */
char caesar_encrypt(char c, int key) {
	char dict[] = {' ','A','B','C','D','E','F','G','H','I','J','K','L','M','N',
								'O','P','Q','R','S','T','U','V','W','X','Y','Z',',','.',
								'?','0','1','2','3','4','5','6','7','8','9','!'};
	for (int i = 0; i < CAESAR_MOD; i++) {
		if (dict[i] == c) 
			return dict[(i + key) % CAESAR_MOD];
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

int aes_256_gcm_encrypt(unsigned char* key, unsigned char* plain_text, int pt_len, unsigned char* enc_text, unsigned char* IV, int IV_len, unsigned char* tag, unsigned long tag_len)
{
	gcm_state gcm;
	unsigned char pass[32];
	register_cipher(&aes_desc);
	//mp_to_unsigned_bin(key, pass);
	return gcm_memory(find_cipher("aes"), key, 32, IV, IV_len, NULL, 0, plain_text, pt_len, enc_text, tag, &tag_len, GCM_ENCRYPT);
}
/* Client main program */
int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Please enter command line arguments [IP_ADDRESS] [FILENAME]\n");
		exit(-1);
	}
	printf("---------------------------------------------------------------\n");
	printf("CLIENT\n");
	printf("---------------------------------------------------------------\n");

	/* Generate a prime number and its primitive root (publicly known) */
	GlobalInfo g;	
	g.prime = GeneratePrime();
	printf("** Global prime - %d\n", g.prime);
	g.generator = GeneratePrimitiveRoot(g.prime);
	printf("** Global primitive root - %d\n\n", g.generator);

	/* Choose a private key or the client */
	int private_key = rand() % (g.prime - 1) + 1;
	int public_key = compute_exp_modulo(g.generator, private_key, g.prime);
	printf("*** Client private key : %d\n", private_key);
	printf("*** Client public key : %d\n\n", public_key);

	/* Establish socket connection with the server */
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Error ");
		exit(-1);
	}
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(SERV_PORT);
	
	/* Connect to the server */
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("Error ");
		exit(-1);
	}

	/* Send public_key, generator and prime to the server */
	char message[MAX_LEN];
	memset(message, 0, sizeof(message));	 
	int n = sprintf(message, "%d\n%d\n%d\n", public_key, g.prime, g.generator);
	send_message(sockfd, message, n);

	/* Receive server public key */ 
	n = recv_message(sockfd, message, sizeof(int) + sizeof(char));
	int public_key_server = atoi(message);
	printf("**** Server public key : %d\n\n", public_key_server);

	/* Compute shared key and caesar key */
	int shared_key = compute_exp_modulo(public_key_server, private_key, g.prime);
	char key[32];
	//itoa(shared_key,key,16);
 	sprintf(key,"%d",shared_key);
	printf("***** Shared key : %d\n", shared_key);
	printf("***** AES key : %s\n\n", key);
	/* Send file contents to server after encryption */
	FILE *input;
	if ((input = fopen(argv[2], "r")) == NULL) {
		perror("Error ");
		exit(-1);
	}
	printf("****** Sending file to server in encrypted format...\n");
	//while ((n = fread(message, sizeof(char), MAX_LEN, input)) > 0) {
	//	for (int i = 0; i < n; i++) 
	//		message[i] = caesar_encrypt(toupper(message[i]), caesar_key);
	//	send_message(sockfd, message, n);
	//}
	n = fread(message, sizeof(char), MAX_LEN, input);
	unsigned char iv[32] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
      0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };

	unsigned char tag[16] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
      0xde, 0xca, 0xf8, 0x88, 0x77, 0x74, 0x24,0x4b };
	unsigned char *output;
	int enc_len = n + 16; // Plain text + Tag length

	output = (unsigned char*)calloc(enc_len + 1, 1);
	if (aes_256_gcm_encrypt(key, message, n, output, iv, 32, tag, 16) != CRYPT_OK)
	{	
		printf("Error in encrypt!\n");
	}
	send_message(sockfd, message, enc_len);
	fclose(input);
	printf("****** Finished sending the data to server!\n\n"); 
	printf("---------------------------------------------------------------\n");
	close(sockfd);
	return 0;
}



