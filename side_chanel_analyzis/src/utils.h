//
// Created by user on 4/2/19.
//

#ifndef SIDE_CHANEL_ANALYZIS_UTILS_H
#define SIDE_CHANEL_ANALYZIS_UTILS_H

#include <gnutls/gnutls.h>
#define ELAPSED(a,b) (a - b)

void read_data_from_file(const char* file_name, char* buffer, size_t buff_size);

void write_result_to_file(const char* file_name, int* buffer, size_t buff_size);


gnutls_datum_t importHexData(char * string);

#endif //SIDE_CHANEL_ANALYZIS_UTILS_H
