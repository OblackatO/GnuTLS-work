#include <stdio.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_analyzer.h"

const int NUMBER_OF_ITERATIONS = 100000;

int main() {
  printf("sizeof(ULONG) = %ld\n", sizeof(long long));
	printf("CLOCKS_PER_SEC = %ld\n", CLOCKS_PER_SEC);
	printf("######################################\n");


  /***********************SCENARIO 1***********************/
  /**Low and High Hamming weights for the same data.*******/
  /********************************************************/
  //for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
    // LHHW_OnData();
  //}
  /********************************************************/

  /************Low and High hamming weight of the key******/
  //for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
    //RSAHHW();
  //}

  for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
    RSALHW();
  }


  return 0;

}