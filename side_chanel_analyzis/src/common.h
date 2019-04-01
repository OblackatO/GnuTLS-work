//
// Created by user on 4/1/19.
//

#ifndef SIDE_CHANEL_ANALYZIS_COMMON_H
#define SIDE_CHANEL_ANALYZIS_COMMON_H

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#define ELAPSED(a,b) (a - b)

long run_with_measurement(void *func, void *data);

void read_data_from_file(const char* file_name, char* buffer, size_t buff_size);

#endif //SIDE_CHANEL_ANALYZIS_COMMON_H
