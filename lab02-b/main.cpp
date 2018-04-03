#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>

int main(void) {
  int res;
  unsigned char ot[1024] = "abcdefghijklmnopqrstuvwxyz0123";  // open text
  unsigned char ot2[1024] = "Můj text pro rc5.";  // open text
  unsigned char st[1024] = "06fb7405eba8d9e94fb1f28f0dd21fdec55fd54750ee84d95ecccf2b1b48";  // sifrovany text
  unsigned char st2[1024] = "33f6630eaea4dba152baf38d019c04cbc759c94544fb9a815dc68d7b5f1a";  // sifrovany text
  unsigned char dt[1024];
  unsigned char key[EVP_MAX_KEY_LENGTH] = "Muj klic";  // klic pro sifrovani
  unsigned char iv[EVP_MAX_IV_LENGTH] = "a";  // inicializacni vektor
  unsigned char iv2[EVP_MAX_IV_LENGTH] = "adasdasdasdasa";  // inicializacni vektor
  const char cipherName[] = "RC4";
  const EVP_CIPHER * cipher;
  int stLength = 60;
/*
  OpenSSL_add_all_ciphers();
  /* sifry i hashe by se nahraly pomoci OpenSSL_add_all_algorithms()
  cipher = EVP_get_cipherbyname(cipherName);
  if(!cipher) {
    printf("Sifra %s neexistuje.\n", cipherName);
    exit(1);
  }

  int otLength = strlen((const char*) ot);
  int stLength = 0;
  int stLength2 = 0;
  int tmpLength = 0;

  EVP_CIPHER_CTX *ctx; // context structure
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) exit(2);

  printf("OT: %s\n", ot);

  /*
  res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);  // context init - set cipher, key, init vector
  if(res != 1) exit(3);
  res = EVP_EncryptUpdate(ctx,  st, &tmpLength, ot, otLength);  // encryption of pt
  if(res != 1) exit(4);
  stLength += tmpLength;
  res = EVP_EncryptFinal_ex(ctx, st + stLength, &tmpLength);  // get the remaining ct
  if(res != 1) exit(5);
  stLength += tmpLength;

  tmpLength = 0;

  res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv2);  // context init - set cipher, key, init vector
  if(res != 1) exit(3);
  res = EVP_EncryptUpdate(ctx,  st2, &tmpLength, ot2, otLength);  // encryption of pt
  if(res != 1) exit(4);
  stLength2 += tmpLength;
  res = EVP_EncryptFinal_ex(ctx, st2 + stLength, &tmpLength);  // get the remaining ct
  if(res != 1) exit(5);
  stLength2 += tmpLength;

  printf ("Zasifrovano %d znaku.\n", stLength);

  /* Desifrovani
  res = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);  // nastaveni kontextu pro desifrovani
  if(res != 1) exit(6);
  res = EVP_DecryptUpdate(ctx, dt, &tmpLength,  st, stLength);  // desifrovani st
  if(res != 1) exit(7);
  otLength += tmpLength;
  res = EVP_DecryptFinal_ex(ctx, dt + otLength, &tmpLength);  // dokonceni (ziskani zbytku z kontextu)
  if(res != 1) exit(8);
  otLength += tmpLength;

  /* Desifrovani 2
  res = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);  // nastaveni kontextu pro desifrovani
  if(res != 1) exit(6);
  res = EVP_DecryptUpdate(ctx, ot, &tmpLength,  st, stLength);  // desifrovani st
  if(res != 1) exit(7);
  otLength += tmpLength;
  res = EVP_DecryptFinal_ex(ctx, ot + otLength, &tmpLength);  // dokonceni (ziskani zbytku z kontextu)
  if(res != 1) exit(8);
  otLength += tmpLength;


  /* Clean up
  EVP_CIPHER_CTX_free(ctx);*/
  char secondText[stLength];
  /* Vypsani zasifrovaneho a rozsifrovaneho textu. */
  for (int i = 0 ; i < stLength ; i++){
    secondText[i]=st[i]^ot[i];
  }

  printf("ST: %s\nST2: %s\nDT: %s\n", st, st2, dt);
  printf("SecondText: %s\n", secondText);
  exit(0);
}