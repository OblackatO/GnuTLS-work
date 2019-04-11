#ifndef RSA_ANALYZER_H
#define RSA_ANALYZER_H

#include "gnutls/abstract.h"

#define TRUE 1
#define FALSE 0

void file_writer(FILE *output_file, long elapsed);

gnutls_datum_t importHexData(char * string);

void LHHW_OnData();

void RSAHHW();

void RSALHW();

#endif //RSA_ANALYZER_H