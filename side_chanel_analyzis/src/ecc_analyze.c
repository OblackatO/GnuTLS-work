//
// Created by user on 4/1/19.
//

#include <gnutls/gnutls.h>
#include "ecc_analyze.h"
#include <gnutls/abstract.h>
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>

gnutls_privkey_t import_low_hw_private() {

    gnutls_datum_t k = importHexData("4000000000000000000000000000000000000000000000000000000000000000");
    gnutls_datum_t x = importHexData("01ee7fc202708cfeb0c2bf930bf33a68ad086d4ce99a11e38d93ca698eb99805");
    gnutls_datum_t y = importHexData("9655cef01b024882124be02ef3455711811836ea35be799b09fd5f4e10eeccaf");

    gnutls_privkey_t privkey;

    gnutls_privkey_init(&privkey);
    gnutls_privkey_import_ecc_raw(privkey, GNUTLS_ECC_CURVE_SECP256R1, &x, &y, &k);

    return privkey;
}

gnutls_privkey_t import_high_hw_private() {

    gnutls_datum_t k = importHexData("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    gnutls_datum_t x = importHexData("c1d17269e46e387acbe299ec2cc9cc2dada3f05e4cf412f2ad946b700aa2613a");
    gnutls_datum_t y = importHexData("edb7744f370c13a4f49957d54ff798119d111f69129c24db5f5fb84162909dbb");
    gnutls_privkey_t privkey;

    gnutls_privkey_init(&privkey);
    gnutls_privkey_import_ecc_raw(privkey, GNUTLS_ECC_CURVE_SECP256R1, &x, &y, &k);

    return privkey;
}

gnutls_privkey_t import_rand_privkey() {
    gnutls_privkey_t privkey;
    gnutls_privkey_init(&privkey);

    gnutls_privkey_generate(privkey, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0);

    return privkey;
}

//Check return value
void checkRet(int ret, char* function) {
    if (ret < 0) {
        fprintf(stdout, "An error occurs during %s: %s\n", function, gnutls_strerror(ret));
        exit(1);
    }
}

long signWorker(gnutls_privkey_t privkey,const gnutls_datum_t* data) {
    clock_t begin;
    clock_t end;
    gnutls_datum_t signature;
    int response;

    begin = clock();

    response = gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, data, &signature);

    end = clock();

    checkRet(response, "signWorker");

    return ELAPSED(end, begin);
}

long decryptWorker(gnutls_privkey_t privkey, const gnutls_datum_t* data) {
    clock_t begin;
    clock_t end;
    gnutls_datum_t plaintext;
    int response;

    begin = clock();

    response = gnutls_privkey_decrypt_data(privkey, 0, data, &plaintext);

    end = clock();

    checkRet(response, "decryptWorker");

    return ELAPSED(end, begin);
}

void iterateSignWorker(gnutls_privkey_t key, const gnutls_datum_t* data, const char* file_name) {
    long res;
    FILE* fd = fopen(file_name, "w");

    ITERATIONS(i) {
        res = signWorker(key, data);
        fprintf(fd, "%ld\n", res);
    }

    fclose(fd);
}

void iterateDecryptWorker(gnutls_privkey_t key, const gnutls_datum_t* data, const char* file_name) {
    long res;
    FILE* fd = fopen(file_name, "w");

    ITERATIONS(i) {
        res = decryptWorker(key, data);
        fprintf(fd, "%ld\n", res);
    }

    fclose(fd);
}

void scenario1(const gnutls_datum_t* low_data, const gnutls_datum_t* high_data, const gnutls_datum_t* rand_data) {

    gnutls_privkey_t low_hw_privkey = import_low_hw_private();
    gnutls_privkey_t high_hw_privkey = import_high_hw_private();
    gnutls_privkey_t rand_privkey = import_rand_privkey();

    iterateSignWorker(low_hw_privkey, rand_data, "hash_low_hw_private.out");
    iterateSignWorker(high_hw_privkey, rand_data, "hash_high_hw_private.out");
    iterateSignWorker(rand_privkey, low_data, "hash_rPrivate_low_data.out");
    iterateSignWorker(rand_privkey, high_data, "hash_rPrivate_high_data.out");

}

void scenario2(const gnutls_datum_t* low_data, const gnutls_datum_t* high_data, const gnutls_datum_t* rand_data) {

    gnutls_privkey_t low_hw_privkey = import_low_hw_private();
    gnutls_privkey_t high_hw_privkey = import_high_hw_private();
    gnutls_privkey_t rand_privkey = import_rand_privkey();

    iterateDecryptWorker(low_hw_privkey, rand_data, "decrypt_low_hw_private.out");
    iterateDecryptWorker(high_hw_privkey, rand_data, "decrypt_high_hw_private.out");
    iterateDecryptWorker(rand_privkey, low_data, "decrypt_rPrivate_low_data.out");
    iterateDecryptWorker(rand_privkey, high_data, "decrypt_rPrivate_high_data.out");

}

