#include <stdio.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_analyzer.h"

int main() {

  printf("sizeof(ULONG) = %ld\n", sizeof(long long));
	printf("CLOCKS_PER_SEC = %ld\n", CLOCKS_PER_SEC);
	printf("######################################\n");

  /***********************SCENARIO 1***********************/
  /**Low and High Hamming weights for the same data.*******/
  /********************************************************/

  void * dataLW = malloc(256); 
  memset(dataLW, 0, 256);
  memset(dataLW, 0x80, 1);
  const gnutls_datum_t low_hamming_data = {
	  (void *) dataLW, 
	  256
  };

  void * dataHW = malloc(256); 
  memset(dataHW, 0xFF, 256);
  const gnutls_datum_t high_hamming_data = {
    (void *) dataHW, 
	  256
  };

  //SIGNING DATA function, in the next two loops.
  FILE *output_file = fopen("LHWData_DataSign_keyX.txt", "w");
  for(int i=0; i<100000; ++i){
    rsa_data_sign(GNUTLS_DIG_SHA256, 0, &low_hamming_data, TRUE, FALSE, FALSE, output_file);  
  }
  fclose(output_file);

  output_file = fopen("HHWData_DataSign_keyX.txt", "w");
  for(int i=0; i<100000; ++i){
    rsa_data_sign(GNUTLS_DIG_SHA256, 0, &high_hamming_data, TRUE, FALSE, FALSE, output_file);  
  }
  fclose(output_file);

  //SIGNING HASHED DATA function, in the next two loops.
  gnutls_datum_t low_hashed_data = rsa_data_sign(GNUTLS_DIG_SHA256, 0, &low_hamming_data, FALSE, FALSE, FALSE, NULL);
  output_file = fopen("LHWData_HashedDataSign_keyX.txt", "w");
  for(int i=0; i<100000; ++i){
    rsa_data_sign(GNUTLS_DIG_SHA256, 0, &low_hashed_data, TRUE, FALSE, FALSE, output_file);  
  };
  fclose(output_file);

  gnutls_datum_t high_hashed_data = rsa_data_sign(GNUTLS_DIG_SHA256, 0, &high_hamming_data, FALSE, FALSE, FALSE, NULL);
  output_file = fopen("HHWData_HashedDataSign_keyX.txt", "w");
  for(int i=0; i<100000; ++i){
    rsa_data_sign(GNUTLS_DIG_SHA256, 0, &high_hashed_data, TRUE, FALSE, FALSE, output_file);  
  };
  fclose(output_file);

  /***decrypt low and high hamming of data with random key*****/
  output_file = fopen("Decrypt_HHWData.txt", "w");
  for(int i=0; i<100000; ++i){
    decrypt_data(FALSE, FALSE, dataLW);
  }
  fclose(output_file);

  output_file = fopen("Decrypt_LHWData.txt", "w");
  for(int i=0; i<100000; ++i){
    decrypt_data(FALSE, FALSE, dataHW);
  }
  fclose(output_file);
  
  /************************************SCENARIO 1 ends********************************/


  /**********************************SCENARIO 2***************************************/
  /**Low Hamming weight of private exponent of the RSA key, with the some data X******/
  /***********************************************************************************/
  
  //Some data X
  const gnutls_datum_t some_dataX = {
    (void *) "hello world", 
	  11
  };



  /**********************************SCENARIO 2 ends**********************************/

  /**********************************SCENARIO 3***************************************/
  /**High Hamming weight of private exponent of the RSA key, with the same data X*****/

  //get key up and running


  return 0;
}