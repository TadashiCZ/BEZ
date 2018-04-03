/* Valenta Tadeas <valentad> */

#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>

#define MAX_LENGTH 1024

#define FILE_NAME "Mad_scientist"

#define INIT_SIZE 20

#define BUFFER_SIZE 512

int main(void) {
	unsigned char ot[MAX_LENGTH];  // otevreny text
	unsigned char st[MAX_LENGTH];  // sifrovany text
	unsigned char key[EVP_MAX_KEY_LENGTH] = "ToToNeNI TaJNY NE";  // klic pro sifrovani
	unsigned char iv[EVP_MAX_IV_LENGTH] = "123ciaL. VEktor";  // inicializacni vektor
	const EVP_CIPHER *cipher;

	OpenSSL_add_all_ciphers();
	/* sifry i hashe by se nahraly pomoci OpenSSL_add_all_algorithms() */
	cipher = EVP_des_ecb();
	//cipher = EVP_des_cbc();

	int stLength = 0;
	int otLength = 0;
	int i;
	int tmpLength = 0;
	EVP_CIPHER_CTX ctx; // struktura pro kontext

	FILE *fInput = fopen(FILE_NAME".bmp", "r");

	if ( !fInput ) {
		perror("Error when attempting to read file "FILE_NAME"./n");
		return 1;
	}

	unsigned char *head = (unsigned char *) malloc(sizeof(unsigned char) * INIT_SIZE);
	unsigned size = INIT_SIZE;
	unsigned count = 14;

	fread(head, sizeof(unsigned char), count, fInput);
	unsigned long zac = *(unsigned long *) (head + 10);
	unsigned long file_size = *(unsigned long *) (head + 2);

	printf("Zacatek dat v souboru: %lu\n", zac);
	printf("Delka celeho souboru: %lu\n", file_size);

	if ( zac > size )
		head = (unsigned char *) realloc(head, sizeof(unsigned char) * zac);
	fread(head + count, sizeof(unsigned char), zac - count, fInput);
	count = zac;

	//Sifrovani
	EVP_EncryptInit(&ctx, cipher, key, iv);  // nastaveni kontextu pro sifrovani

	unsigned char *buff = (unsigned char *) malloc(sizeof(unsigned char) * BUFFER_SIZE);
	unsigned long data_count = 0;
	size_t res;

	FILE *fOutput = fopen(FILE_NAME"_ecb.bmp", "w");
	fwrite(head, sizeof(unsigned char), zac, fOutput);;
	fseek(fInput, zac, SEEK_SET);
	while ((res = fread(buff, sizeof(unsigned char), BUFFER_SIZE, fInput))) {
		data_count += res;

		EVP_EncryptUpdate(&ctx, st, &stLength, buff, res);  // sifrovani ot
		fwrite(st, sizeof(unsigned char), stLength, fOutput);
	}
	EVP_EncryptFinal(&ctx, st, &stLength);  // dokonceni (ziskani zbytku z kontextu)
	fwrite(st, sizeof(unsigned char), stLength, fOutput);
	fclose(fOutput);
	fclose(fInput);
	printf("Nactena delka dat v souboru: %lu\n", data_count);



	
	printf("Nyni se soubor desifruje...\n");
	scanf("\n");
	fInput = fopen(FILE_NAME"_ecb.bmp", "r");
	fOutput = fopen(FILE_NAME"_dec.bmp", "w");
	fseek(fInput, zac, SEEK_SET);


	fwrite(head, sizeof(unsigned char), count, fOutput);

	// Desifrovani
	EVP_DecryptInit(&ctx, cipher, key, iv);  // nastaveni kontextu pro desifrovani
	data_count = 0;



	while ( (res = fread(buff, sizeof(unsigned char), BUFFER_SIZE, fInput))) {
		data_count += res;

		EVP_DecryptUpdate(&ctx, ot, &otLength, buff, res);  // desifrovani st
	}

	EVP_DecryptFinal(&ctx, ot + otLength, &tmpLength);  // dokonceni (ziskani zbytku z kontextu)



	free(head);
	free(buff);

	return 0;
}