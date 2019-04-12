#include <stdio.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_analyzer.h"


int main() 
{
  printf("sizeof(ULONG) = %ld\n", sizeof(long long));

	printf("######################################\n");

  //RSALHW();
  //RSAHHW();
  //LHHW_OnData();
  encrypt_data();

  return 0;
}
