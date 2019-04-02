#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "ecc_analyze.h"

#define DATA_LENGTH 256
#define LOW_HW_DATA "low_hw_data.in"
#define HIGH_HW_DATA "high_hw_data.in"
#define RAND_DATA "random_data.in"

int main() {
    printf("Hello, World!\n");

    char low_hw_data[DATA_LENGTH];
    char high_hw_data[DATA_LENGTH];
    char random_data[DATA_LENGTH];

    read_data_from_file(LOW_HW_DATA, low_hw_data, DATA_LENGTH);
    read_data_from_file(HIGH_HW_DATA, high_hw_data, DATA_LENGTH);
    read_data_from_file(RAND_DATA, random_data, DATA_LENGTH);

    const gnutls_datum_t low_hamming_data = {
            (void *) low_hw_data,
            256
    };

    const gnutls_datum_t high_hamming_data = {
            (void *) high_hw_data,
            256
    };

    const gnutls_datum_t rand_data = {
            (void*) random_data,
            256
    };

    scenario1(&low_hamming_data, &high_hamming_data, &rand_data);
    scenario2(&low_hamming_data, &high_hamming_data, &rand_data);


    return 0;
}