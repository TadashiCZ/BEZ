#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <cctype>

void rand_str(char *dest, size_t length) {
	char charset[] = "0123456789"
	                 "abcdefghijklmnopqrstuvwxyz"
	                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	while ( length-- > 0 ) {
		size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
		*dest++ = charset[index];
	}
	*dest = '\0';
}

int main(int argc, char *argv[]) {

	int i, res;
	int cnt = 0;
	char hashFunction[] = "sha256";  // zvolena hashovaci funkce ("sha1", "md5" ...)

	EVP_MD_CTX *ctx;  // struktura kontextu
	const EVP_MD *type; // typ pouzite hashovaci funkce
	unsigned char hash[EVP_MAX_MD_SIZE]; // char pole pro hash - 64 bytu (max pro sha 512)
	int length;  // vysledna delka hashe

	char *text = (char *) malloc(6 * sizeof(char));

	while ( 1 ) {
		rand_str(text, 5);
		/* Inicializace OpenSSL hash funkci */
		/* Inicializace OpenSSL hash funkci */
		OpenSSL_add_all_digests();
		/* Zjisteni, jaka hashovaci funkce ma byt pouzita */
		type = EVP_get_digestbyname(hashFunction);

		/* Pokud predchozi prirazeni vratilo -1, tak nebyla zadana spravne hashovaci funkce */
		if ( !type ) {
			printf("Hash %s neexistuje.\n", hashFunction);
			exit(1);
		}

		ctx = EVP_MD_CTX_create(); // create context for hashing
		if ( ctx == NULL ) exit(2);

		/* Hash the text */
		res = EVP_DigestInit_ex(ctx, type, NULL); // context setup for our hash type
		if ( res != 1 ) exit(3);
		res = EVP_DigestUpdate(ctx, text, strlen(text)); // feed the message in
		if ( res != 1 ) exit(4);
		res = EVP_DigestFinal_ex(ctx, hash, (unsigned int *) &length); // get the hash
		if ( res != 1 ) exit(5);

		EVP_MD_CTX_destroy(ctx); // destroy the context


		if ( hash[0] == 0xAA && hash[1] == 0xBB ) {
			printf("Hash textu \"%s\" je: ", text);
			cnt++;
			for ( i = 0; i < length; i++ ) {
				printf("%02x", hash[i]);
			}
			printf("\n");
			if ( cnt >= 20 ) {
				break;
			}
		}

	}
	exit(0);
}