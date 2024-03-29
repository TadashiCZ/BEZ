#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <string>

#define INIT_SIZE 20

#define BUFFER_SIZE 16384

#define TEMP_FILE_PATH "hopeNoOneNamesFileLikeTheseBecauseItWouldDeleteYourFiles.pom"

int main(int argc, char * argv[]) {
	if ( argc != 5 ) {
		printf( "Usage: <mode (-e/-d)> <public/private_key_file> <input_data_file> <output_file>\n" );
		return -1;
	}

	if (RAND_load_file("/dev/random", 32) != 32) {
		puts("Cannot seed the random generator!");
		exit(1);
	}

	std::string mode = argv[1];
	std::string key = argv[2];
	std::string inputName = argv[3];
	std::string outputName = argv[4];
	OpenSSL_add_all_ciphers();

	if ( mode == "-e" ) {
		FILE * f_pubkey = fopen( key.c_str(), "r" );
		if ( !f_pubkey ) {
			printf( "Failed to read public key: %s.\n", key.c_str() );
			return -3;
		}
		EVP_PKEY * pubkey = PEM_read_PUBKEY( f_pubkey, NULL, NULL, NULL );
		fclose( f_pubkey );

		// Inicializace
		auto * my_enc_key = ( unsigned char * ) malloc( EVP_PKEY_size( pubkey ) );
		int my_enc_key_length;
		unsigned char iv[EVP_MAX_IV_LENGTH];
		EVP_CIPHER_CTX ctx;

		const EVP_CIPHER * cipher = EVP_des_cbc();
		const char * cipher_str = "DES", * cipher_mode_str = "CBC";
		const int key_bitlen = 64;

		if ( !EVP_SealInit( &ctx, cipher, &my_enc_key, &my_enc_key_length, iv, &pubkey, 1 ) ) {
			printf( "SealInit failed.\n" );
			return 7;
		}

		printf( "Key encrypted into %d bytes.\n", my_enc_key_length );

		// Sifruj datovy soubor
		unsigned char buff[BUFFER_SIZE];
		unsigned char buff_out[BUFFER_SIZE];
		int datalen = 0;
		int outlen = 0;

		FILE * fInput = fopen( inputName.c_str(), "r" );
		if ( !fInput ) {
			printf( "Failed to open input file: %s.\n", inputName.c_str() );
			return -2;
		}
		FILE * fOutput = fopen( TEMP_FILE_PATH, "w" );
		if ( !fOutput ) {
			printf( "Failed to open temporary file: %s.\n", outputName.c_str() );
			return -2;
		}

		int res;
		while ( ( res = fread( buff, sizeof( unsigned char ), BUFFER_SIZE, fInput ) ) > 0 ) {
			if ( !EVP_SealUpdate( &ctx, buff_out, &outlen, buff, res ) ) {
				printf( "SealUpdate failed.\n" );
				return 8;
			}
			fwrite( buff_out, sizeof( unsigned char ), outlen, fOutput );
			datalen += outlen;
		}
		if ( !datalen ) {
			printf( "Encrypted 0 bytes from the input file: %s.\n", inputName.c_str() );
			return -2;
		}

		if ( !EVP_SealFinal( &ctx, buff_out, &outlen ) ) {
			printf( "SealFinal failed.\n" );
			return 9;
		}
		fwrite( buff_out, sizeof( unsigned char ), outlen, fOutput );
		datalen += outlen;

		fclose( fInput );
		fclose( fOutput );
		printf( "The file was encrypted into %d bytes.\n", datalen );

		fOutput = fopen( outputName.c_str(), "w" );

		fprintf( fOutput, "%s %s %d %d\n", cipher_str, cipher_mode_str, key_bitlen, EVP_MAX_IV_LENGTH );
		fwrite( iv, sizeof( unsigned char ), EVP_MAX_IV_LENGTH, fOutput );
		fwrite( my_enc_key, sizeof( unsigned char ), my_enc_key_length, fOutput );


		fprintf( fOutput, "%d\n", datalen );
		fInput = fopen( TEMP_FILE_PATH, "r" );
		while ( ( res = fread( buff, sizeof( unsigned char ), BUFFER_SIZE, fInput ) ) )
			fwrite( buff, sizeof( unsigned char ), res, fOutput );

		fclose( fInput );
		free( my_enc_key );

		if ( fOutput != stdout )
			fclose( fOutput );

		if (remove(TEMP_FILE_PATH)){
			printf("Failed to delete temp file\n");
		}
		return 0;

	} else if ( mode == "-d" ) {

		OpenSSL_add_all_ciphers();

		// Nacti verejny klic
		FILE * f_privkey = fopen( key.c_str(), "r" );
		if ( !f_privkey ) {
			printf( "Failed to read file with private key: %s.\n", key.c_str() );
			return -3;
		}
		EVP_PKEY * privkey = PEM_read_PrivateKey( f_privkey, NULL, NULL, NULL );
		fclose( f_privkey );

		// Inicializace
		unsigned int my_enc_key_length = EVP_PKEY_size( privkey );
		unsigned char * my_enc_key = ( unsigned char * ) malloc( my_enc_key_length );
		unsigned char iv[EVP_MAX_IV_LENGTH]; // buffer for the init. vector
		unsigned int iv_length;
		int key_bitlen;
		char cipher_str[16];
		char cipher_mode_str[16];

		FILE * fInput = fopen( inputName.c_str(), "r" );
		if ( !fInput ) {
			printf( "Failed to read input file: %s.\n", inputName.c_str() );
			return -2;
		}

		if ( fscanf( fInput, "%s %s %d %u\n", cipher_str, cipher_mode_str, &key_bitlen, &iv_length ) != 4 ) {
			printf( "Failed to read encryption parameters from file %s.\n", inputName.c_str() );
			return -3;
		}

		printf( "Cipher (mode): %s (%s)\n", cipher_str, cipher_mode_str );
		printf( "Length of key %s: %d bits\n", cipher_str, key_bitlen );
		printf( "IV length: %d bytes\n", iv_length );

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
			printf( "Failed to read cipher %s.\n", cipher_str );
			return -7;
		}

		if ( fread( iv, sizeof( unsigned char ), iv_length, fInput ) != iv_length ) {
			printf( "Failed to read IV length.\n" );
			return -8;
		}
		if ( fread( my_enc_key, sizeof( unsigned char ), my_enc_key_length, fInput ) != my_enc_key_length ) {
			printf( "Failed to read key.\n" );
			return -9;
		}

		int enclen = 0;
		if ( fscanf( fInput, "%d\n", &enclen ) != 1 || enclen <= 0 ) {
			printf( "Failed to read encrypted data from %s.\n", inputName.c_str() );
			return -13;
		}

		printf( "Encrypted data length: %d bytes\n", enclen );

		EVP_CIPHER_CTX ctx;
		if ( !EVP_OpenInit( &ctx, cipher, my_enc_key, my_enc_key_length, iv, privkey ) ) {
			printf( "OpenInit failed.\n" );
			return 7;
		}

		// Desifruj datovy soubor
		unsigned char buff[BUFFER_SIZE];
		unsigned char buff_out[BUFFER_SIZE];
		int outlen = 0;
		int datalen = 0;
		int inlen = 0;

		FILE * fOutput = fopen( outputName.c_str(), "w" );
		if ( !fOutput ) {
			printf( "Failed to read output file: %s.\n", outputName.c_str() );
			return -2;
		}

		size_t res;
		while ( ( res = fread( buff, sizeof( unsigned char ), BUFFER_SIZE, fInput ) ) > 0 ) {
			if ( ( inlen += res ) > enclen )
				break;
			if ( !EVP_OpenUpdate( &ctx, buff_out, &outlen, buff, res ) ) {
				printf( "OpenUpdate failed.\n" );
				return 8;
			}
			fwrite( buff_out, sizeof( unsigned char ), outlen, fOutput );
			datalen += outlen;
		}
		if ( !inlen ) {
			printf( "Read 0 bytes from the input file: %s.\n", inputName.c_str() );
			return -2;
		} else if ( inlen != enclen ) {
			printf( "Length of data doesn't match: %d != %d\n", inlen, enclen );
			return -2;
		}

		if ( !EVP_OpenFinal( &ctx, buff_out, &outlen ) ) {
			printf( "OpenFinal failed.\n" );
			return 9;
		}
		fwrite( buff_out, sizeof( unsigned char ), outlen, fOutput );
		datalen += outlen;

		fclose( fInput );
		printf( "Decipher the file into %d bytes.\n", datalen );

		free( my_enc_key );

		if ( fOutput != stdout )
			fclose( fOutput );

		return 0;

	} else {
		printf( "Usage: <mode (-e/-d)> <input_data_file> <public/private_key_file> <output_file>\n" );
		return 1;
	}


}