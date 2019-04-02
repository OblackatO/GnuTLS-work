#ifndef RSA_ANALYZER_H
#define RSA_ANALYZER_H

#include "gnutls/abstract.h"

#define TRUE 1
#define FALSE 0

gnutls_datum_t rsa_data_sign( gnutls_digest_algorithm_t hash,
                    		  unsigned int flags,
			        		  const gnutls_datum_t * data,
                    		  int write_ticks,
							  int UseLHW_key,
                              int Use_HHW_key,
							  FILE *output_file);

void rsa_hashedata_sign( gnutls_datum_t *hash_data,
						gnutls_digest_algorithm_t hash_algo,
			            unsigned int flags,
						int UseLHW_key,
                        int Use_HHW_key,
						FILE *output_file);

void decrypt_data();

void file_writer(FILE *output_file, long elapsed);



#endif //RSA_ANALYZER_H