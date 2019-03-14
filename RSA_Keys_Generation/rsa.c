#define _GNU_SOURCE
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

int ID = 1;

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
void print_rsa_pkey(FILE * outfile, int id, long long time, 
                                    gnutls_datum_t * n, gnutls_datum_t * e,
                                    gnutls_datum_t * p, gnutls_datum_t * q,
                                    gnutls_datum_t * d) {
  fprintf(outfile, "\n");
  fprintf(outfile, "%d", id);
  fprintf(outfile, ";");
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
    fprintf(outfile, ";");
  }else{
    fprintf(outfile, ";");
    fprintf(outfile, ";");
  }
  fprintf(outfile, "%lld", time);
}


void generation_flow(FILE *handle, int key_size)
{
  /*
  The code on this function was the code in the main 
  function of the old rsa.c, but modified. 
  */
  int ret;

  //Allocate privkey structure
  gnutls_privkey_t privkey;
  ret = gnutls_privkey_init(&privkey);
  checkRet(ret, "init");
  
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  long long t1 = (long long)ts.tv_nsec;
  long long ts1 = (long long)ts.tv_sec;
  ret = gnutls_privkey_generate(privkey, GNUTLS_PK_RSA, key_size, 0); //Generate RSA key pair
  timespec_get(&ts, TIME_UTC);
  long long t2 = (long long)ts.tv_nsec;
  long long ts2 = (long long)ts.tv_sec;
  long long nanoseconds = ((ts2*1000000000+t2)-(ts1*1000000000+t1));
  checkRet(ret, "generating");

  //Export RSA key pair
  gnutls_datum_t n, e, d, p, q, u, e1, e2;
  ret = gnutls_privkey_export_rsa_raw(privkey, &n, &e, &d, &p, &q, &u, &e1, &e2);
  checkRet(ret, "export rsa");

  print_rsa_pkey(handle, ID++, nanoseconds, &n, &e, &p, &q, &d);

  //Free private key
  gnutls_privkey_deinit(privkey);
}

int main() {
  const unsigned int size1 = 512;
  const unsigned int size2 = 1024;
  const unsigned int size3 = 2048;

  FILE *generated_keys = fopen("512.csv", "w");
  fprintf(generated_keys, "id;n;e;p;q;d;t1;\n");
  for(int i=1; i<=1000000; i++){
    if(i == 10000){
      printf("[>]10k 512-bit keys generated.");
    }else if(i == 100000){
      printf("[>]100k 512-bitkeys generated.");
    }else if(i == 500000){
      printf("[>]500k 512-bit keys generated.");
    }else if(i == 800000){
      printf("[>]800k 512-bit keys generated");
    }
    generation_flow(generated_keys, size1);
  }
  fclose(generated_keys);
  ID = 1;

  generated_keys = fopen("1024.csv", "w");
  fprintf(generated_keys, "id;n;e;p;q;d;t1;\n");
  for(int i=1; i<=10000; i++){
    if(i == 3000){
      printf("[>]3k 1024-bit 2048-bit keys generated");
    }else if(i == 8000){
      printf("[>]8k 1024-bit 2048-bit keys generated");
    }
    generation_flow(generated_keys, size2);
  }
  fclose(generated_keys);
  ID = 1;

  generated_keys = fopen("2048.csv", "w");
  fprintf(generated_keys, "id;n;e;p;q;d;t1;\n");
  for(int i=1; i<=10000; i++){
    if(i == 3000){
      printf("[>]3k 1024-bit 2048-bit keys generated");
    }else if(i == 8000){
      printf("[>]8k 1024-bit 2048-bit keys generated");
    }
    generation_flow(generated_keys, size3);
  }
  fclose(generated_keys);
  return 0;
}
