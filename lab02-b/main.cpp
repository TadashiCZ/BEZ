#include <iostream>
#include <openssl/evp.h>
#include <vector>
#include <sstream>
#include <string>
#include <cstring>
#include "stdint.h"

using namespace std;

int main(void) {
	string known_ot;
	vector<uint8_t> known_ct;
	vector<uint8_t> unknown_ct;
	vector<uint8_t> second_xor;

	string input1;
	string input2;

	cout << "Please, input known open text" << endl;
	cin >> known_ot;
	cout << "Please, input known cipher text" << endl;
	cin >> input1;
	cout << "Please, input unknown cipher text" << endl;
	cin >> input2;
	cout << known_ot << " --- " << input1 << " --- " << input2 << endl;

	for(size_t i = 0; i < input1.size(); i += 2) {
		istringstream str(input1.substr(i, 2));
		uint8_t x;
		str >> hex >> x;
		known_ct.push_back(x);
	}

	cin >> input2;
	for(size_t i = 0; i < input2.size(); i += 2) {
		istringstream str(input2.substr(i, 2));
		uint8_t x;
		str >> hex >> x;
		unknown_ct.push_back(x);
	}

	int res;
	//todo load
	unsigned char ot[1024] = "abcdefghijklmnopqrstuvwxyz0123";  // open text
	unsigned char ot2[1024] = "Naprosto tajny text, který je fakt hrozně úžasný, takže si ho musíte přečíst";
	unsigned char st[1024];  // sifrovany text
	unsigned char st2[1024];
	unsigned char newText[1024];
	unsigned char key[EVP_MAX_KEY_LENGTH] = "Supertajnyklic";  // klic pro sifrovani
	unsigned char iv[EVP_MAX_IV_LENGTH] = "inicial. vektor";  // inicializacni vektor
	const char cipherName[] = "RC4";
	const EVP_CIPHER *cipher;

	OpenSSL_add_all_ciphers();
	/* sifry i hashe by se nahraly pomoci OpenSSL_add_all_algorithms() */
	cipher = EVP_get_cipherbyname(cipherName);
	if ( !cipher ) {
		printf("Sifra %s neexistuje.\n", cipherName);
		exit(1);
	}

	int otLength = strlen((const char *) ot);
	int stLength = 0;
	int tmpLength = 0;

	EVP_CIPHER_CTX *ctx; // context structure
	ctx = EVP_CIPHER_CTX_new();
	if ( ctx == NULL ) exit(2);

	printf("OT: %s\n", ot);

	/* Sifrovani */
	res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);  // context init - set cipher, key, init vector
	if ( res != 1 ) exit(3);
	res = EVP_EncryptUpdate(ctx, st, &tmpLength, ot, otLength);  // encryption of pt
	if ( res != 1 ) exit(4);
	stLength += tmpLength;
	res = EVP_EncryptFinal_ex(ctx, st + stLength, &tmpLength);  // get the remaining ct
	if ( res != 1 ) exit(5);
	stLength += tmpLength;

	printf("Zasifrovano %d znaku.\n", stLength);
	ctx = EVP_CIPHER_CTX_new();
	otLength = strlen((const char *) ot2);
	tmpLength = 0;
	stLength = 0;

	res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);  // context init - set cipher, key, init vector
	if ( res != 1 ) exit(3);
	res = EVP_EncryptUpdate(ctx, st2, &tmpLength, ot2, otLength);  // encryption of pt
	if ( res != 1 ) exit(4);
	stLength += tmpLength;
	res = EVP_EncryptFinal_ex(ctx, st2 + stLength, &tmpLength);  // get the remaining ct
	if ( res != 1 ) exit(5);
	stLength += tmpLength;

	printf("Zasifrovano %d znaku.\n", stLength);

	/* Desifrovani */
	res = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);  // nastaveni kontextu pro desifrovani
	if ( res != 1 ) exit(6);
	res = EVP_DecryptUpdate(ctx, ot, &tmpLength, st, stLength);  // desifrovani st
	if ( res != 1 ) exit(7);
	otLength += tmpLength;
	res = EVP_DecryptFinal_ex(ctx, ot + otLength, &tmpLength);  // dokonceni (ziskani zbytku z kontextu)
	if ( res != 1 ) exit(8);
	otLength += tmpLength;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	printf("Zasifrovano %d znaku.\n", stLength);


	/* Vypsani zasifrovaneho a rozsifrovaneho textu. */
	printf("ST1: %s\nDecryptT1: %s\n, ST2: %s\n", st, ot, st2);

	for ( int i = 0; i < 30; i++ ) {
		newText[i] = st2[i] ^ ot[i] ^ st[i];
	}

	printf("DecryptT2: %s\n", newText);
	exit(0);
}