//
// Created by user on 4/1/19.
//

#ifndef SIDE_CHANEL_ANALYZIS_ECC_ANALYZE_H
#define SIDE_CHANEL_ANALYZIS_ECC_ANALYZE_H

#define NUM_OF_ITERATIONS 100000
#define ITERATIONS(i) for(int i = 0; i < NUM_OF_ITERATIONS; i++)

void scenario1(const gnutls_datum_t* low_data, const gnutls_datum_t* high_data, const gnutls_datum_t* rand_data);

void scenario2(const gnutls_datum_t* low_data, const gnutls_datum_t* high_data, const gnutls_datum_t* rand_data);


//ecdsa_sign

//ecdsa decrypt

#endif //SIDE_CHANEL_ANALYZIS_ECC_ANALYZE_H
