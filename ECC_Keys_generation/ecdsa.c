/**
 * This code is modyfication of rsa key generation code, see ../RSA_Keys_generation/
 */

#define _GNU_SOURCE
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#define CSV_OUTPUT_FILE "ecdsa.csv"

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
void print_rsa_pkey(FILE * outfile, int id, long time, gnutls_datum_t * x, gnutls_datum_t * y, gnutls_datum_t * k) {
  fprintf(outfile, "\n");

  fprintf(outfile, "%d", id);
  fprintf(outfile, ";");

  print_hex_datum(outfile, x);
  fprintf(outfile, ";");

  print_hex_datum(outfile, y);
  fprintf(outfile, ";");

  print_hex_datum(outfile, k);
  fprintf(outfile, ";");

  fprintf(outfile, "%ld", time);
}


void generation_flow(int id, gnutls_ecc_curve_t curve)
{

  int ret;

  //Allocate privkey structure
  gnutls_privkey_t privkey;
  ret = gnutls_privkey_init(&privkey);
  checkRet(ret, "init");
  
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  long t1 = (long)ts.tv_nsec;
  ret = gnutls_privkey_generate(privkey, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(curve), 0); //Generate RSA key pair
  timespec_get(&ts, TIME_UTC);
  long t2 = (long)ts.tv_nsec;
  long nanoseconds = (t2 -t1);
  checkRet(ret, "generating");

  gnutls_datum_t x, y, k;
  ret = gnutls_privkey_export_ecc_raw(privkey, &curve, &x, &y, &k);
  checkRet(ret, "export ecdsa");

  FILE *generated_keys = fopen(CSV_OUTPUT_FILE, "a");
  print_rsa_pkey(generated_keys, id, nanoseconds, &x, &y, &k);
  fclose(generated_keys);

  //Free private key
  gnutls_privkey_deinit(privkey);
}

int main() {

    gnutls_ecc_curve_t curve = GNUTLS_ECC_CURVE_SECP256R1;

  for(int id=1; id<=1000000; id++){
    if(id == 10000){
      printf("[>]10k keys generated.");
    }else if(id == 100000){
      printf("[>]100k keys generated.");
    }else if(id == 500000){
      printf("[>]500k keys generated.");
    }else if(id == 800000){
      printf("[>]800k keys generated");
    }
    generation_flow(id, curve);
  }

  return 0;
}
