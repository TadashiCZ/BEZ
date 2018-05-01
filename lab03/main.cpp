/* Valenta Tadeas <valentad> */

#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <string>

#define MAX_LENGTH 1024

#define INIT_SIZE 20

#define BUFFER_SIZE 512

bool checkHeader(unsigned char * head, unsigned int filesize, int encrypt) {
	unsigned long zac = * (unsigned long *) (head + 10);
	unsigned long file_size = * (unsigned long *) (head + 2);

	if ( head[0] != 66 || head[1] != 77)
		return false;

	if (zac > file_size)
		return false;
	if (encrypt){
		if (filesize != file_size)
			return false;
	}
	return true;
}

int main(int argc, char * argv[] ) {
	unsigned char st[MAX_LENGTH];  // sifrovany text
	unsigned char key[EVP_MAX_KEY_LENGTH] = "MujDlouhySuperTajnyKlic";  // klic pro sifrovani
	unsigned char iv[EVP_MAX_IV_LENGTH] = "SuperIniVektor";  // inicializacni vektor
	const EVP_CIPHER * cipher;
	int encrypt;
	if ( argc != 4 ) {
		printf( "Use of application: -e|-d ecb|cbc var-filename\n" );
		return 1;
	}

	std::string mode = argv[1];
	std::string cipherToUse = argv[2];
	std::string fileName = argv[3];

	if ( cipherToUse == "cbc" ) {
		cipher = EVP_des_cbc(); // better one
	} else if ( cipherToUse == "ecb" ) {
		cipher = EVP_des_ecb(); // worse one
	} else {
		printf( "Use of application: -e|-d ecb|cbc var-filename\n" );
		return 1;
	}


	OpenSSL_add_all_ciphers();

	if ( mode == "-e" ) {
		encrypt = 1;
	} else if ( mode == "-d" ) {
		encrypt = 0;
	} else {
		printf( "Use of application: -e|-d ecb|cbc var-filename\n" );
		return 1;
	}

	FILE * fInput = fopen( fileName.c_str(), "r" );
	if ( !fInput ) {
		printf( "Unable to open file%s/n", fileName.c_str() );
		return 1;
	}

	fseek(fInput, 0L, SEEK_END);
	long int filesize = ftell(fInput);
	fseek(fInput, 0L, SEEK_SET);

	int stLength = 0;
	EVP_CIPHER_CTX ctx; // struktura pro kontext

	unsigned char * head = (unsigned char *) malloc( sizeof( unsigned char ) * INIT_SIZE );
	unsigned size = INIT_SIZE;
	unsigned long count = 14;

	fread( head, sizeof( unsigned char ), count, fInput );
	unsigned long zac = * (unsigned long *) (head + 10);
	unsigned long file_size = * (unsigned long *) (head + 2);

	if ( !checkHeader( head, filesize, encrypt ) ) {
		printf( "Error file\n" );
		return 1;
	}

	printf( "Zacatek dat v souboru: %lu\n", zac );
	printf( "Delka celeho souboru: %lu\n", file_size );


	if ( zac > size )
		head = (unsigned char *) realloc( head, sizeof( unsigned char ) * zac );
	fread( head + count, sizeof( unsigned char ), zac - count, fInput );
	count = zac;

	//Sifrovani
	EVP_CipherInit( & ctx, cipher, key, iv, encrypt );  // nastaveni kontextu pro sifrovani

	unsigned char * buff = (unsigned char *) malloc( sizeof( unsigned char ) * BUFFER_SIZE );
	unsigned long data_count = 0;
	size_t res;


	std::string outputName;
	if (encrypt){
		outputName = fileName.substr(0, fileName.size()-4).append("_").append(cipherToUse).append((".bmp"));
	} else {
		outputName = fileName.substr(0, fileName.size()-4).append("_dec").append((".bmp"));
	}

	FILE * fOutput = fopen( outputName.c_str(), "w" );
	fwrite( head, sizeof( unsigned char ), zac, fOutput );;
	fseek( fInput, zac, SEEK_SET );
	while ( (res = fread( buff, sizeof( unsigned char ), BUFFER_SIZE, fInput )) ) {
		data_count += res;

		EVP_CipherUpdate( & ctx, st, & stLength, buff, res );  // sifrovani ot
		fwrite( st, sizeof( unsigned char ), stLength, fOutput );
	}
	EVP_CipherFinal( & ctx, st, & stLength );  // dokonceni (ziskani zbytku z kontextu)
	//todo kontrolovat padding
	fwrite( st, sizeof( unsigned char ), stLength, fOutput );
	fclose( fOutput );
	fclose( fInput );
	printf( "Nactena delka dat v souboru: %lu\n", data_count );
	printf( "Zapsana delka dat v souboru: %lu\n", data_count );
	free( head );
	free( buff );

	return 0;
}

