//
// Created by user on 4/1/19.
//
#include "common.h"

void read_data_from_file(const char* file_name, char* buffer, size_t buff_size) {
    int fd;

    if ((fd = open(file_name, O_RDONLY, S_IRUSR)) == -1) {
        fprintf(stderr, "Cannot open %s. Try again later, maybe.\n", file_name);
        exit(1);
    }

    read(fd, buffer, buff_size);

    close(fd);
}


