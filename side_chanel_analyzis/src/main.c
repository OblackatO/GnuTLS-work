#include <stdio.h>
#include "common.h"

#define DATA_LENGTH 2048
#define LOW_HW_DATA "low_hw_data.in"

int main() {
    printf("Hello, World!\n");

    char* low_hw_data[DATA_LENGTH];

    read_data_from_file(LOW_HW_DATA, low_hw_data, DATA_LENGTH);


    return 0;
}