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

#define FIX_MARGIN(a) (a-32)
#define CSV_OUTPUT_FILE "ecdsa.csv"

struct timespec diff_time(struct timespec start, struct timespec end)
{
    struct timespec temp;

    if ((end.tv_nsec-start.tv_nsec)<0)
    {
        temp.tv_sec = end.tv_sec-start.tv_sec-1;
        temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
    }
            else
    {
        temp.tv_sec = end.tv_sec-start.tv_sec;
        temp.tv_nsec = end.tv_nsec-start.tv_nsec;
    }
    return temp;
}

//Check return value
void checkRet(int ret, char* function) {
 if (ret < 0) {
    fprintf(stderr, "An error occurs during %s: %s\n", function, gnutls_strerror(ret));
    exit(1);
  }
}

//Print hex
static void print_hex_datum(FILE * outfile, gnutls_datum_t * dat, unsigned int index)
{
	for (; index < dat->size; index++) {
		fprintf(outfile, "%.2x", (unsigned char) dat->data[index]);
	}
}

//Print rsa key function
void print_ec_info(FILE * outfile, int id, struct timespec time, gnutls_datum_t * x, gnutls_datum_t * y, gnutls_datum_t * k) {
  fprintf(outfile, "\n");

  fprintf(outfile, "%d", id);
  fprintf(outfile, ";");

  fprintf(outfile, "04");
  print_hex_datum(outfile, x, FIX_MARGIN(x->size));
  print_hex_datum(outfile, y, FIX_MARGIN(y->size));
  fprintf(outfile, ";");

  print_hex_datum(outfile, k, FIX_MARGIN(k->size));
  fprintf(outfile, ";");

  fprintf(outfile, "%ld", time.tv_sec * 1000000000 + time.tv_nsec);
}


void generation_flow(int id, gnutls_ecc_curve_t curve, FILE *fd)
{

  int ret;
  struct timespec start_time;
  struct timespec end_time;
  struct timespec diff_time_result;


    //Allocate privkey structure
  gnutls_privkey_t privkey;
  ret = gnutls_privkey_init(&privkey);
  checkRet(ret, "init");
  
  timespec_get(&start_time, TIME_UTC);

  ret = gnutls_privkey_generate(privkey, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(curve), 0); //Generate RSA key pair

  timespec_get(&end_time, TIME_UTC);

  diff_time_result = diff_time(start_time, end_time);

  checkRet(ret, "generating");

  gnutls_datum_t x, y, k;
  ret = gnutls_privkey_export_ecc_raw(privkey, &curve, &x, &y, &k);
  checkRet(ret, "export ecdsa");

  print_ec_info(fd, id, diff_time_result, &x, &y, &k);

  //Free private key
  gnutls_privkey_deinit(privkey);
}

int main() {

    gnutls_ecc_curve_t curve = GNUTLS_ECC_CURVE_SECP256R1;
    FILE *fd = fopen(CSV_OUTPUT_FILE, "a");

    fprintf(fd, "id;e;d;t1\n");


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
    generation_flow(id, curve, fd);
  }

    fclose(fd);

  return 0;
}
