cmake_minimum_required(VERSION 3.13)
project(ECC_Keys_generation)

set(CMAKE_CXX_STANDARD 14)

include_directories(/usr/include)
link_directories(/usr/lib)

add_executable(ECC_Keys_generation ecdsa.c)

target_link_libraries(ECC_Keys_generation gnutls)
