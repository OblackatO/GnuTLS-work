#include <stdio.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_analyzer.h"

gnutls_privkey_t privkey = NULL;

static gnutls_datum_t importHexData(char * string) {
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

//RSA key used for all the required procedures.
static gnutls_privkey_t rsa_privkey_import(int isLowHammingWeight){

    
    gnutls_datum_t m = importHexData("c7dfceb56744469de1d608921ca97722990a88fc8d1bda0df450d4f97bee19273fe1bdb89ef9a83ca750521fe7c742f579dd7080ccbd4fa43dccd238f7a0f35357d2d80821f423b53bf22111df8f92ae4282a4dd50bcaaff58c1814e28ea89bf2f44cfc5f01a708337db148c1320a719130813a70b3c88d2da83db47b7b6c23fe49040f3847bd49ba78b49d776fdf9f7153e56078875a5b45836f022c472a2b483d4a7c1cae294d8affd8b35a8c1d2f10983ee05802a5a981b531beab8e6ccc8ea548b1e4c4df1792ca15967e23b4ab2be559947bfa2abeca494517e6b54d4e13491052de26c77ae578f600f8b8b075b9cd15622e6831da03271644c4ef384e7h");
    gnutls_datum_t p = importHexData("ffbd25037436ddd3f6a9578e35bef092bfd97de5a0b0193d50cf86c5c531eac7a3a9e0e0711c2cdcfe5b87c09cb321610dc85530ed3a4a412ed28de8354a5b44867d99c8814287e7b4246714ab85b98292125c23e15e4c583b8bade984059a8123c63d5345ff155fb2be86c9b5041b10b247fc4f1ea5f696dfd217dae9ab037b");
    gnutls_datum_t q = importHexData("c8140f07bd0e7d94c8de7d5cd97545bb47902c6f42900cf0ed5794ad1e696333ee2393881132c8a2bead36a293d6e4f73d05166e5e615f739e25eeeada255f46cd8c56f90c3150a041ace114cf2d60b01c46ba09f52d33b4f5f5e1a5461c120adaa79bee2e38f89d322f52a8b5fdaaebb0186a3705ec6e661d96fc5f7a0f4285");

    gnutls_datum_t el = importHexData("ab49423e832260c860f3cf3f176e82064858f313043d5cfbb1d87d0e5bb9a340ff3f882a05f1e7d0194f778e0fa3e746811d04de45208a6acf78a7eeadb1fa3de56f680b51729a1b6d30bbd56559609accf6335e27476a2c7dfa7dc3a694c3ef5d535ecd501898473a495f2f0db8ba01561e5c8bf94b2310f8e2765ad11c36b3250fec690b902e3e0305ccf0ce1566fa31a5c336be14014a73a2387960adea37c83014717621a9513fcc4e25a0f14b6bf259b6f9a25ed79995e2c275e3ef635c79736eac0e4a23976044d80d6af7fedfd879878b10ebdf37d71fcb315ea91af3256a22573800f8c81e8e72200dab4b3d125f010ecfcdb52d82fd80e7edae6e03h");
    gnutls_datum_t dl = importHexData("80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003h");

    gnutls_datum_t eh = importHexData("4cd370c6f9eba552abd2dff17f4195186f2eb95798b83c152183335cd1bb480855dd088332a5d1aaa0b228dcd6eaa454f22658295b73d8a1c7d09b75ce4d8c92f26a6a3866c162515789119c8dbff0dedc4db65125676e240779c6c1b4e638ba1895c22ea2bb305dbbe2cc10cd213a2edb7a645b478b67a836e2bc3c2ca94c0c40b638d7bfdb9739f9f1732d17223986704f2f07be4e1a6ba4d3a3cb9741d37f9b973010d2e8b032136879287cf72a5a0faed08d25dcd5b4de544d678611db8d5bf3c90fa662523035942c0a03176cc7bcb9efd29d23883739cc3aeb8d3d72c580f9844bf53b5ff0599dd98a4b5e9f6ae4506941e665f9b261d0615dc7f3937fh");
    gnutls_datum_t dh = importHexData("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffh");

    gnutls_privkey_t privkey;
    if(isLowHammingWeight == TRUE){
        
        gnutls_privkey_init(&privkey);
        if (gnutls_privkey_import_rsa_raw(privkey, &m, &el, &dl, &p, &q, NULL, NULL, NULL) < 0) {
            printf("[>]Error while importing key with low hamming weight.");
        }
        return privkey;
    
    }else{
        
        gnutls_privkey_init(&privkey);
        if (gnutls_privkey_import_rsa_raw(privkey, &m, &eh, &dh, &p, &q, NULL, NULL, NULL) < 0) {
            printf("[>]Error while importing key with hight hamming weight.");
        }
        return privkey;
    }
}

static void rsa_key_generator(int key_size){

    if(gnutls_privkey_init(&privkey) < 0){
        printf("[>]Error in init of RSA key.");
    };

    if(gnutls_privkey_generate(privkey, GNUTLS_PK_RSA, key_size, 0) < 0){
        printf("[>]Error generating RSA key.");
    };
}

/**
 * Signes data, using the function: gnutls_privkey_sign_data
 *
 */  
gnutls_datum_t rsa_data_sign(  gnutls_digest_algorithm_t hash,
                                unsigned int flags,
			                    const gnutls_datum_t *data,
                                int write_ticks,
                                int UseLHW_key,
                                int Use_HHW_key,
                                FILE *output_file)
{

    if(privkey == NULL){
       rsa_key_generator(2048);
    };

    clock_t begin, end;
    gnutls_datum_t signature;

    if(UseLHW_key == TRUE){
       
        begin = clock();
        if(gnutls_privkey_sign_data(rsa_privkey_import(TRUE), GNUTLS_DIG_SHA256, 0, data, &signature) < 0){
            printf("[>]Error while signing data.");
        };
        end = clock();
    
    }else if(Use_HHW_key == TRUE){

        begin = clock();
        if(gnutls_privkey_sign_data(rsa_privkey_import(FALSE), GNUTLS_DIG_SHA256, 0, data, &signature) < 0){
            printf("[>]Error while signing data.");
        };
        end = clock();
    
    }else{
        
        begin = clock();
        if(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, data, &signature) < 0){
            printf("[>]Error while signing data.");
            };
        end = clock();
    }

    long elapsed = end - begin;
    if(write_ticks == TRUE){
        file_writer(output_file, elapsed);
    }
    
    return signature;
}

/**
 * Signes hashed data, using the function: gnutls_privkey_sign_hash
 * 
 */ 
void rsa_hashedata_sign(gnutls_datum_t *hash_data, 
                        gnutls_digest_algorithm_t hash_algo,
			            unsigned int flags,
                        int UseLHW_key,
                        int Use_HHW_key,
                        FILE *output_file)
{


    clock_t begin, end;
    gnutls_datum_t signature;
    if(UseLHW_key == TRUE){
        
        begin = clock();
        if(gnutls_privkey_sign_hash(rsa_privkey_import(TRUE), GNUTLS_DIG_SHA256, 0, hash_data, &signature) < 0){
            printf("[>]An error while signing the hash.");
        }
        end = clock();
    
    }else if(Use_HHW_key == TRUE){
        
        begin = clock();
        if(gnutls_privkey_sign_hash(rsa_privkey_import(FALSE), GNUTLS_DIG_SHA256, 0, hash_data, &signature) < 0){
            printf("[>]An error while signing the hash.");
        }
        end = clock();

    }else{

        begin = clock();
        if(gnutls_privkey_sign_hash(privkey, GNUTLS_DIG_SHA256, 0, hash_data, &signature) < 0){
            printf("[>]An error while signing the hash.");
        }
        end = clock();
    }
    
    long elapsed = end - begin;
    file_writer(output_file, elapsed);
}


void decrypt_data( int UseLHW_key,
                   int Use_HHW_key,
                   const gnutls_datum_t *data_to_decrypt)
{
    
    clock_t begin, end;
    gnutls_datum_t plaintext;
    if(UseLHW_key == TRUE){
        
        begin = clock();
        if(gnutls_privkey_decrypt_data(rsa_privkey_import(TRUE), 0, data_to_decrypt, &plaintext) < 0){
            printf("[>]Error while decrypting with low hamming weight.");
        }
        end = clock();
    
    }else if(Use_HHW_key == TRUE){

        begin = clock();
        if(gnutls_privkey_decrypt_data(rsa_privkey_import(FALSE), 0, data_to_decrypt, &plaintext) < 0){
            printf("[>]Error while decrypting with high hamming weight.");
        }
        end = clock();
    
    }else{

        begin = clock();
        if(gnutls_privkey_decrypt_data(privkey, 0, data_to_decrypt, &plaintext) < 0){
            printf("[>]Error while decrypting with low hamming weight.");
        }
        end = clock();
    }
}

void file_writer(FILE *output_file, long elapsed){
    
    fprintf(output_file, "\n%lu", elapsed);
}


