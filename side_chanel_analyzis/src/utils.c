//
// Created by user on 4/2/19.
//

#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <gnutls/abstract.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

void read_data_from_file(const char* file_name, char* buffer, size_t buff_size) {
    int fd;

    if ((fd = open(file_name, O_RDONLY, S_IRUSR)) == -1) {
        fprintf(stderr, "Cannot open %s. Try again later, maybe.\n", file_name);
        exit(1);
    }

    read(fd, buffer, buff_size);

    close(fd);
}

void write_result_to_file(const char* file_name, int* buffer, size_t buff_size) {
    /*int fd;

    if ((fd = open(file_name, O_WRONLY | O_CREAT | O_EXCL, S_IWUSR)) == -1) {
        fprintf(stderr, "Cannot open %s. Try again later, maybe.\n", file_name);
        exit(1);
    }

    write(fd, buffer, buff_size);

    close(fd);*/

    FILE* fd = fopen(file_name, "w");
    for(int i = 0; i < buff_size; i++)
        fprintf(fd, "\n%lu", buffer[i]);

    fclose(fd);
}

gnutls_datum_t importHexData(char * string) {
    unsigned int len = (unsigned int)strlen(string);
    unsigned int size = len/2;
    unsigned char* data = (unsigned char*)malloc(size);
    for (unsigned int i = 0; i < size; i++) {
        sscanf(string + 2*i, "%02x", &data[i]);
    }

    gnutls_datum_t result = {
            data,
            size
    };
    return result;
}