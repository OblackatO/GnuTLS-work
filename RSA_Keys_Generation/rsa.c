#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

//Check return value
void checkRet(int ret, char* function) {
 if (ret < 0) {
    fprintf(stderr, "An error occurs during %s: %s\n", function, gnutls_strerror(ret));
    exit(1);
  }
}

//Print hex
static void print_hex_datum(FILE * outfile, gnutls_datum_t * dat)
{
	for (unsigned int j = 0; j < dat->size; j++) {
		fprintf(outfile, "%.2x", (unsigned char) dat->data[j]);
	}
}

//Print rsa key function
void print_rsa_pkey(FILE * outfile, gnutls_datum_t * n, gnutls_datum_t * e,
                                    gnutls_datum_t * d, gnutls_datum_t * p,
                                    gnutls_datum_t * q) {
  print_hex_datum(outfile, n);
  fprintf(outfile, ";");
  print_hex_datum(outfile, e);
  fprintf(outfile, ";");
  
  if (d) {
    print_hex_datum(outfile, p);
    fprintf(outfile, ";");
    print_hex_datum(outfile, q);
    fprintf(outfile, ";");
    print_hex_datum(outfile, d);
  }
}

int main() {
  const unsigned int blen = 512;
  int ret;

  //Allocate privkey structure
  gnutls_privkey_t privkey;
  ret = gnutls_privkey_init(&privkey);
  checkRet(ret, "init");
  
  //Generate RSA key pair
  ret = gnutls_privkey_generate(privkey, GNUTLS_PK_RSA, blen, 0);
  checkRet(ret, "generating");

  //Export RSA key pair
  gnutls_datum_t n, e, d, p, q, u, e1, e2;
  ret = gnutls_privkey_export_rsa_raw(privkey, &n, &e, &d, &p, &q, &u, &e1, &e2);
  checkRet(ret, "export rsa");

  //Print RSA key pair
  print_rsa_pkey(stdout, &n, &e, &d, &p, &q);

  //Free private key
  gnutls_privkey_deinit(privkey);
  return 0;
}
