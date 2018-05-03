#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <cstring>

#define INIT_SIZE 20
#define BUFFER_SIZE 512

int main(int argc, char * argv[]) {
	if ( argc < 5 ) {
		std::cout << "Usage: <mode> <public/private key path> <file to de/cipher> <output filename>" << std::endl;
		return 1;
	}


	std::string mode = argv[1];
	std::string keyPath = argv[2];
	std::string inputFilename = argv[3];
	std::string outputfFilename = argv[4];
	int encrypt;

	if ( mode == "-e" ) {
		encrypt = 1;
	} else if ( mode == "-d" ) {
		encrypt = 0;
	} else {
		printf( "Use of application: -e|-d ecb|cbc var-filename\n" );
		return 1;
	}

	OpenSSL_add_all_ciphers();

	if ( encrypt ) {
		FILE * f_pubkey = fopen( keyPath.c_str(), "r" );
		if ( !f_pubkey ) {
			std::cout << "Failed to read file with the key: " << keyPath << "." << std::endl;
			return -3;
		}

		EVP_PKEY * pubkey = PEM_read_PUBKEY( f_pubkey, NULL, NULL, NULL );
		fclose( f_pubkey );

		// Inicializace
		unsigned char * my_enc_key = ( unsigned char * ) malloc( EVP_PKEY_size( pubkey ) );        // symetric cipher enrypted key
		int my_enc_key_length;
		unsigned char iv[EVP_MAX_IV_LENGTH]; // buffer for the init. vector
		EVP_CIPHER_CTX ctx;

		const EVP_CIPHER * cipher = EVP_des_cbc();
		const char * cipher_str = "DES", * cipher_mode_str = "CBC";
		const int key_bitlen = 64;

		if ( !EVP_SealInit( &ctx, cipher, &my_enc_key, &my_enc_key_length, iv, &pubkey, 1 ) ) {
			std::cout << "SealInit failed." << std::endl;
			return 7;
		}

		unsigned char buff[BUFFER_SIZE];
		unsigned char buff_out[BUFFER_SIZE];
		int datalen = 0;
		int outlen = 0;

		FILE * fInput = fopen( inputFilename.c_str(), "r" );
		if ( !fInput ) {
			printf( "Nemuzu otevrit vstupni datovy soubor %s.\n", inputFilename.c_str() );
			return -2;
		}
		FILE * fOutput = fopen( outputfFilename.c_str(), "w" );
		if ( !fOutput ) {
			printf( "Nemuzu otevrit vystupni datovy soubor %s.\n", outputfFilename.c_str() );
			return -2;
		}

		int res;
		while ( ( res = fread( buff, sizeof( unsigned char ), BUFFER_SIZE, fInput ) ) > 0 ) {
			if ( !EVP_SealUpdate( &ctx, buff_out, &outlen, buff, res ) ) {
				printf( "Chyba pri SealUpdate.\n" );
				return 8;
			}
			fwrite( buff_out, sizeof( unsigned char ), outlen, fOutput );
			datalen += outlen;
		}
		if ( !datalen ) {
			printf( "Nic jsem nezasifroval z vstupniho datoveho souboru %s.\n", argv[1] );
			return -2;
		}

		if ( !EVP_SealFinal( &ctx, buff_out, &outlen ) ) {
			printf( "Chyba pri SealFinal.\n" );
			return 9;
		}
		fwrite( buff_out, sizeof( unsigned char ), outlen, fOutput );
		datalen += outlen;

		fclose( fInput );
		fclose( fOutput );

		fOutput = ( argc == 4 ) ? fopen( outputfFilename.c_str(), "w" ) : stdout;

		fprintf( fOutput, "%s %s %d %d\n", cipher_str, cipher_mode_str, key_bitlen, EVP_MAX_IV_LENGTH );
		fwrite( iv, sizeof( unsigned char ), EVP_MAX_IV_LENGTH, fOutput );
		fwrite( my_enc_key, sizeof( unsigned char ), my_enc_key_length, fOutput );

		fprintf( fOutput, "%d\n", datalen );
		fInput = fopen( inputFilename.c_str(), "r" );
		while ( ( res = fread( buff, sizeof( unsigned char ), BUFFER_SIZE, fInput ) ) )
			fwrite( buff, sizeof( unsigned char ), res, fOutput );

		fclose( fInput );
		free( my_enc_key );

		if ( fOutput != stdout )
			fclose( fOutput );
		return 0;
	} else {


		// Nacti verejny klic
		FILE * f_privkey = fopen( keyPath.c_str(), "r" );
		if ( !f_privkey ) {
			printf( "Nemuzu precist klicovy soubor %s.\n", argv[2] );
			return -3;
		}
		EVP_PKEY * privkey = PEM_read_PrivateKey( f_privkey, NULL, NULL, NULL );
		fclose( f_privkey );

		// Inicializace

		int my_enc_key_length = EVP_PKEY_size( privkey );
		unsigned char * my_enc_key = ( unsigned char * ) malloc( my_enc_key_length );        // symetric cipher enrypted key
		unsigned char iv[EVP_MAX_IV_LENGTH]; // buffer for the init. vector
		int iv_length;
		int key_bitlen;
		char cipher_str[16];
		char cipher_mode_str[16];

		FILE * fInput = fopen( argv[1], "r" );
		if ( !fInput ) {
			printf( "Nemuzu otevrit vstupni soubor %s.\n", argv[1] );
			return -2;
		}

		if ( fscanf( fInput, "%s %s %d %d\n", cipher_str, cipher_mode_str, &key_bitlen, &iv_length ) != 4 ) {
			printf( "Problem pri cteni parametru ze souboru %s.\n", argv[1] );
			return -3;
		}

		printf( "Pozadovana sifra: %s (%s)\n", cipher_str, cipher_mode_str );
		printf( "Delka %s klice: %d bitu\n", cipher_str, key_bitlen );
		printf( "Delka IV: %d bytu\n", iv_length );

		const EVP_CIPHER * cipher =
				( !strcmp( cipher_str, "DES" ) )
				? ( !strcmp( cipher_mode_str, "CBC" ) )
				  ? EVP_des_cbc()
				  : ( !strcmp( cipher_mode_str, "ECB" ) )
				    ? EVP_des_ecb()
				    : EVP_des_ede()
				: ( !strcmp( cipher_str, "AES" ) )
				  ? ( !strcmp( cipher_mode_str, "GCM" ) )
				    ? ( key_bitlen == 256 )
				      ? EVP_aes_256_gcm()
				      : ( key_bitlen == 192 )
				        ? EVP_aes_192_gcm()
				        : EVP_aes_128_gcm()
				    : ( !strcmp( cipher_mode_str, "CCM" ) )
				      ? ( key_bitlen == 256 )
				        ? EVP_aes_256_ccm()
				        : ( key_bitlen == 192 )
				          ? EVP_aes_192_ccm()
				          : EVP_aes_128_ccm()
				      : EVP_get_cipherbyname( cipher_str )
				  : EVP_get_cipherbyname( cipher_str );
		if ( !cipher ) {
			printf( "Nerozpoznal jsem sifru %s.\n", cipher_str );
			return -7;
		}

		if ( fread( iv, sizeof( unsigned char ), iv_length, fInput ) != iv_length ) {
			printf( "Chyba pri nacitani IV.\n" );
			return -8;
		}
		if ( fread( my_enc_key, sizeof( unsigned char ), my_enc_key_length, fInput ) != my_enc_key_length ) {
			printf( "Chyba pri nacitani klice.\n" );
			return -9;
		}

		int enclen = 0;
		if ( fscanf( fInput, "%d\n", &enclen ) != 1 || enclen <= 0 ) {
			printf( "Problem pri cteni delky sifrovanych dat z %s.\n", argv[1] );
			return -13;
		}

		printf( "Delka sifrovanych dat: %d bytu\n", enclen );

		EVP_CIPHER_CTX ctx;
		if ( !EVP_OpenInit( &ctx, cipher, my_enc_key, my_enc_key_length, iv, privkey ) ) {
			printf( "Chyba pri OpenInit.\n" );
			return 7;
		}

		// Desifruj datovy soubor
		unsigned char buff[BUFFER_SIZE];
		unsigned char buff_out[BUFFER_SIZE];
		int outlen = 0;
		int datalen = 0;
		int inlen = 0;

		FILE * fOutput = ( argc == 4 ) ? fopen( argv[3], "w" ) : stdout;
		if ( !fOutput ) {
			printf( "Nemuzu otevrit vystupni datovy soubor %s.\n", argv[3] );
			return -2;
		}

		int res;
		while ( ( res = fread( buff, sizeof( unsigned char ), BUFFER_SIZE, fInput ) ) > 0 ) {
			if ( ( inlen += res ) > enclen )
				break;
			if ( !EVP_OpenUpdate( &ctx, buff_out, &outlen, buff, res ) ) {
				printf( "Chyba pri OpenUpdate.\n" );
				return 8;
			}
			fwrite( buff_out, sizeof( unsigned char ), outlen, fOutput );
			datalen += outlen;
		}
		if ( !inlen ) {
			printf( "Nic jsem neprecetl z vstupniho datoveho souboru %s.\n", argv[1] );
			return -2;
		} else if ( inlen != enclen ) {
			printf( "Delka vstupnich dat nesouhlasi: %d != %d\n", inlen, enclen );
			return -2;
		}

		if ( !EVP_OpenFinal( &ctx, buff_out, &outlen ) ) {
			printf( "Chyba pri OpenFinal.\n" );
			return 9;
		}
		fwrite( buff_out, sizeof( unsigned char ), outlen, fOutput );
		datalen += outlen;

		fclose( fInput );
		printf( "Zapsal jsem desifrovany soubor delky %d.\n", datalen );

		free( my_enc_key );

		if ( fOutput != stdout )
			fclose( fOutput );

		return 0;


	}


	return 0;
}