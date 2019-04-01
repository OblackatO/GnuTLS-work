cmake_minimum_required(VERSION 3.13)
project(side_chanel_analyzis C)

set(CMAKE_C_STANDARD 99)

include_directories(/usr/include)
link_directories(/usr/lib)

add_executable(side_chanel_analyzis src/main.c src/common.h src/common.c src/ecc_analyze.c src/ecc_analyze.h)

target_link_libraries(side_chanel_analyzis gnutls)