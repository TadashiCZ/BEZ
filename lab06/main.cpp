#include <cstdio>
#include <cstdlib>
#include <strings.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define IP_ADDRESS "147.32.232.248"

#define BUFF_SIZE 1024

int main(int argc, char * argv[]) {
	if ( argc != 3 ) {
		printf( "Usage: %s <output_file> <output_cert_file>\n", argv[0] );
		return 1;
	}

	char buff[BUFF_SIZE];

	int sockfd;
	struct sockaddr_in servaddr;

	sockfd = socket( AF_INET, SOCK_STREAM, 0 );

	bzero( &servaddr, sizeof( servaddr ) );
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr( IP_ADDRESS ); //ip address
	servaddr.sin_port = htons( 443 ); // port

	if ( connect( sockfd, ( struct sockaddr * ) &servaddr, sizeof( servaddr ) ) != 0 ) {
		perror( "connect" );
		return -1;
	}

	SSL_library_init();

	SSL_CTX * ssl_ctx = SSL_CTX_new( SSLv23_client_method() );
	if ( !ssl_ctx ) {
		perror( "SSL_CTX_new" );
		return -2;
	}

	SSL_CTX_set_options( ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 );

	SSL * ssl = SSL_new( ssl_ctx );
	if ( !ssl ) {
		perror( "SSL_new" );
		return -3;
	}

	if ( !SSL_set_fd( ssl, sockfd ) ) {
		perror( "SSL_set_fd" );
		return -4;
	}

	SSL_set_cipher_list( ssl, "ALL:!ECDHE,DHE" ); // disabling ECDHE cipher
	if ( SSL_connect( ssl ) <= 0 ) {
		perror( "SSL_connect" );
		return -5;
	}

	X509 * cert = SSL_get_peer_certificate( ssl );

	if ( !cert ) {
		perror( "SSL_get_cert" );
		return -7;
	}


	FILE * fPEM = fopen( argv[2], "w" );
	if ( !PEM_write_X509( fPEM, cert ) ) {
		perror( "PEM_write" );
		return -8;
	}
	fclose( fPEM );
	SSL_CTX_load_verify_locations( ssl_ctx, "DigiCertAssuredIDRootCA.crt", NULL );
	int result = SSL_get_verify_result( ssl );
	if ( X509_V_OK == result ) {
		printf( "Verify result: %d\n", X509_V_OK );
	} else {
		printf( "Verify result error: %d\n", result );
	}
	printf( "Certificate written in %s\n", argv[2] );

	snprintf( buff, BUFF_SIZE, "GET /student/odkazy HTTP/1.1\r\nConnection: close\r\nHost: fit.cvut.cz\r\n\r\n" );

	if ( SSL_write( ssl, buff, strlen( buff ) + 1 ) <= 0 ) {
		perror( "SSL_write" );
		return -6;
	}

	int res;
	int datalen = 0;
	FILE * fOutput = fopen( argv[1], "w" );
	while ( ( res = SSL_read( ssl, buff, BUFF_SIZE ) ) > 0 ) {
		fwrite( buff, sizeof( char ), res, fOutput );
		datalen += res;
	}
	fprintf( fOutput, "\n" );

	printf( "%d bytes written in %s\n", datalen, argv[1] );
	const SSL_CIPHER * sc = SSL_get_current_cipher( ssl );
	printf( "Used cipher %s\n", SSL_CIPHER_get_name( sc ) );
	// DHE = Diffie Helmann key exchange;
	// ECDHE = Eliptic curve DHE - vyuziti kryptografie eliptickych krivek - rychlejsi
	// RSA - asymetricka sifra podobna exponencialni
	// AES256 - sym. blokova sifra
	// GCM - operacni mod sifry AES
	// => asymetricka sifra je pouzita pro vygenerovani klice pro symetrickou sifru
	// SHA384 - hashovaci funkce pouzita pro podpis autority

	printf( "\nAvailable cipher list:\n" );
	int prior = 0;
	const char * list;
	while ( ( list = SSL_get_cipher_list( ssl, prior ) ) ) {
		printf( "%s\n", list );
		prior++;
	}

	fclose( fOutput );
	SSL_shutdown( ssl );
	close( sockfd );
	SSL_free( ssl );
	SSL_CTX_free( ssl_ctx );

	printf( "Successfully done.\n" );
	return 0;
}
