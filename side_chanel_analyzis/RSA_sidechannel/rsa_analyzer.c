#include <stdio.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_analyzer.h"

const int NUMBER_OF_ITERATIONS = 1000000;

//Check return value
void checkRet(int ret, char* function) {
 if (ret < 0) {
    fprintf(stderr, "An error occurs during %s: %s\n", function, gnutls_strerror(ret));
    exit(1);
  }
}


/**
* Writes data to some file.
*/
void file_writer(FILE *output_file, long elapsed){
    fprintf(output_file,"%lu\n", elapsed);
}


/**
 * Imports Hex data, needed to manually import RSA keys.
 *
*/
gnutls_datum_t importHexData(char * string) 
{
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

/**
 * Prints data imported by:gnutls_datum_t importHexData(char * string)
*/ 
static void print_hex_datum(FILE * outfile, gnutls_datum_t * dat)
{
	for (unsigned int j = 0; j < dat->size; j++) {
		fprintf(outfile, "%.2x", (unsigned char) dat->data[j]);
	}
}


const gnutls_datum_t raw_data = {
	(void *) "hello there",
	11
};

//Some RSA key, 1024bits.
static char pem1_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXAIBAAKBgQC7ZkP18sXXtozMxd/1iDuxyUtqDqGtIFBACIChT1yj0Phsz+Y8\n"
    "9+wEdhMXi2SJIlvA3VN8O+18BLuAuSi+jpvGjqClEsv1Vx6i57u3M0mf47tKrmpN\n"
    "aP/JEeIyjc49gAuNde/YAIGPKAQDoCKNYQQH+rY3fSEHSdIJYWmYkKNYqQIDAQAB\n"
    "AoGADpmARG5CQxS+AesNkGmpauepiCz1JBF/JwnyiX6vEzUh0Ypd39SZztwrDxvF\n"
    "PJjQaKVljml1zkJpIDVsqvHdyVdse8M+Qn6hw4x2p5rogdvhhIL1mdWo7jWeVJTF\n"
    "RKB7zLdMPs3ySdtcIQaF9nUAQ2KJEvldkO3m/bRJFEp54k0CQQDYy+RlTmwRD6hy\n"
    "7UtMjR0H3CSZJeQ8svMCxHLmOluG9H1UKk55ZBYfRTsXniqUkJBZ5wuV1L+pR9EK\n"
    "ca89a+1VAkEA3UmBelwEv2u9cAU1QjKjmwju1JgXbrjEohK+3B5y0ESEXPAwNQT9\n"
    "TrDM1m9AyxYTWLxX93dI5QwNFJtmbtjeBQJARSCWXhsoaDRG8QZrCSjBxfzTCqZD\n"
    "ZXtl807ymCipgJm60LiAt0JLr4LiucAsMZz6+j+quQbSakbFCACB8SLV1QJBAKZQ\n"
    "YKf+EPNtnmta/rRKKvySsi3GQZZN+Dt3q0r094XgeTsAqrqujVNfPhTMeP4qEVBX\n"
    "/iVX2cmMTSh3w3z8MaECQEp0XJWDVKOwcTW6Ajp9SowtmiZ3YDYo1LF9igb4iaLv\n"
    "sWZGfbnU3ryjvkb6YuFjgtzbZDZHWQCo8/cOtOBmPdk=\n"
    "-----END RSA PRIVATE KEY-----\n";

//certificate of pem1_key[] above   
static char pem1_cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICHjCCAYmgAwIBAgIERiYdNzALBgkqhkiG9w0BAQUwGTEXMBUGA1UEAxMOR251\n"
    "VExTIHRlc3QgQ0EwHhcNMDcwNDE4MTMyOTI3WhcNMDgwNDE3MTMyOTI3WjAdMRsw\n"
    "GQYDVQQDExJHbnVUTFMgdGVzdCBjbGllbnQwgZwwCwYJKoZIhvcNAQEBA4GMADCB\n"
    "iAKBgLtmQ/Xyxde2jMzF3/WIO7HJS2oOoa0gUEAIgKFPXKPQ+GzP5jz37AR2ExeL\n"
    "ZIkiW8DdU3w77XwEu4C5KL6Om8aOoKUSy/VXHqLnu7czSZ/ju0quak1o/8kR4jKN\n"
    "zj2AC41179gAgY8oBAOgIo1hBAf6tjd9IQdJ0glhaZiQo1ipAgMBAAGjdjB0MAwG\n"
    "A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDwYDVR0PAQH/BAUDAweg\n"
    "ADAdBgNVHQ4EFgQUTLkKm/odNON+3svSBxX+odrLaJEwHwYDVR0jBBgwFoAU6Twc\n"
    "+62SbuYGpFYsouHAUyfI8pUwCwYJKoZIhvcNAQEFA4GBALujmBJVZnvaTXr9cFRJ\n"
    "jpfc/3X7sLUsMvumcDE01ls/cG5mIatmiyEU9qI3jbgUf82z23ON/acwJf875D3/\n"
    "U7jyOsBJ44SEQITbin2yUeJMIm1tievvdNXBDfW95AM507ShzP12sfiJkJfjjdhy\n"
    "dc8Siq5JojruiMizAf0pA7in\n" "-----END CERTIFICATE-----\n";


//******************************************//
/*Conversion of key to gnutls struct*/
const gnutls_datum_t cert_dat[] = {
	{(void *) pem1_cert, sizeof(pem1_cert)}
};

const gnutls_datum_t key_dat[] = {
	{(void *) pem1_key, sizeof(pem1_key)}
};
//*******************************************//


//RSA key with High-Hamming Weight
static char pem1_HHWkey[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIHcAgEAAkEApunQnUVmIVpE12tOzHy5Mm3blrR/f/cpuyiOU7I0I6xMH4hJSalG\n"
    "3mBWSvMg4XhSCtWRBHIwpVN9UHbEy+iBZwIDAQABAkA39aPvVlkLTYxO/LcKb7ZX\n"
    "ZeV8/T7R1De1e79b6B765jpb7bXy3CXUW2N7Uv2Ljt7/OdNb89UVPU9aj1aPfttB\n"
    "AiEAx0DsfPOpPMrdUGNUfRzk94l44iEuhkTI5mXAiXqcYR8CIQDWcwtBQrpbcThF\n"
    "WU54KagQGYRcPJ11+xn8SKK85HVuuQIBAAIBAAIBAA==\n"
    "-----END RSA PRIVATE KEY-----\n";


//RSA key with Low-Hamming Weight
static char pem1_LHWkey[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIHcAgEAAkEA6AFcaP3z7zu6N/DKGgyclY80LZ1gNcQ4OYLuHgJbgXABQ83uq33r\n"
    "1PuWUlwMBw09utd0bvCtae/OFn/hA0NxtQIDAQABAkBoagxj+D8roQ7bFFRwytJC\n"
    "ATQzf0uIhyniwElYWilCpAGdQCy4oQAE0z8BrZZN+QANgAkEayiwTAhWAGBYKlkB\n"
    "AiEA8TEVQdjxGEM/AmMWbeXGkQsaqqiNQPTzTlflGGx/lsECIQD2P+QZOvdVukam\n"
    "3XuNR0EwXdZnx7k11VSbboEtHAXr9QIBAAIBAAIBAA==\n"
    "-----END RSA PRIVATE KEY-----\n";

//*************************************************//
/*Conversion of the two keys above to gnutls struct*/
const gnutls_datum_t HHWkey_dat[] = {
	{(void *) pem1_HHWkey, sizeof(pem1_HHWkey)}
};

const gnutls_datum_t LHWkey_dat[] = {
	{(void *) pem1_LHWkey, sizeof(pem1_LHWkey)}
};
//*************************************************//


/* sha1 hash of "hello" string */
const gnutls_datum_t hash_data = {
	(void *)
	    "\xaa\xf4\xc6\x1d\xdc\xc5\xe8\xa2\xda\xbe"
	    "\xde\x0f\x3b\x48\x2c\xd9\xae\xa9\x43\x4d",
	20
};


/*
* RSA key with Low hamming weight, with the following functions:
*   [>] gnutls_privkey_sign_data()
*   [>] gnutls_privkey_sign_hash
*
*   Scenario: Low Hamming weight key with some data.
*/
void RSALHW(){
    
    gnutls_x509_privkey_t key;
	gnutls_privkey_t privkey;
	gnutls_datum_t out, out2;
	int ret;
	size_t i;

	for (i = 0; i < sizeof(LHWkey_dat) / sizeof(LHWkey_dat[0]); i++) {
        
        ret = gnutls_x509_privkey_init(&key);
		if (ret < 0)
			checkRet(ret, "gnutls_x509_privkey_init\n");

		ret =
		    gnutls_x509_privkey_import(key, &HHWkey_dat[i],
						GNUTLS_X509_FMT_PEM);
		if (ret < 0)
			checkRet(ret, "gnutls_x509_privkey_import\n");

        ret = gnutls_privkey_init(&privkey);
		if (ret < 0)
			checkRet(ret, "gnutls_privkey_init\n");

		ret = gnutls_privkey_import_x509(privkey, key, 0);
		if (ret < 0)
			checkRet(ret, "gnutls_privkey_import_x509\n");

        /*********************************************************************/
        clock_t begin, end;
        gnutls_datum_t signature;
        long elapsed;
        FILE *output_file = fopen("LHWRSAKey_SignData.txt", "a");
        for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
            begin = clock();
            if(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &hash_data, &signature) < 0){
                printf("[>]Error while signing data.");
            }
            end = clock();
            elapsed = end - begin;
            file_writer(output_file, elapsed);
        };
        fclose(output_file);

        output_file = fopen("LHWRSAKey_SignHashedData.txt", "a");
        for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
            begin = clock();
            if(gnutls_privkey_sign_hash(privkey, GNUTLS_DIG_SHA256, 0, &hash_data, &signature) < 0){
                printf("[>]Error while signing hashed data.");
            };
            end = clock();
            elapsed = end - begin;
            file_writer(output_file, elapsed);
        }
        fclose(output_file);
        /***********************************************************************************/
    }
}


/*
* RSA key with High hamming weight, with the following functions:
*   [>] gnutls_privkey_sign_data()
*   [>] gnutls_privkey_sign_hash
*
*   Scenario: High Hamming weight key with some data.
*/
void RSAHHW(){
    
    gnutls_x509_privkey_t key;
	gnutls_privkey_t privkey;
	gnutls_datum_t out, out2;
	int ret;
	size_t i;
    long elapsed;

	for (i = 0; i < sizeof(HHWkey_dat) / sizeof(HHWkey_dat[0]); i++) {
        
        ret = gnutls_x509_privkey_init(&key);
		if (ret < 0)
			checkRet(ret, "gnutls_x509_privkey_init\n");

		ret =
		    gnutls_x509_privkey_import(key, &HHWkey_dat[i],
						GNUTLS_X509_FMT_PEM);
		if (ret < 0)
			checkRet(ret, "gnutls_x509_privkey_import\n");

        ret = gnutls_privkey_init(&privkey);
		if (ret < 0)
			checkRet(ret, "gnutls_privkey_init\n");

		ret = gnutls_privkey_import_x509(privkey, key, 0);
		if (ret < 0)
			checkRet(ret, "gnutls_privkey_import_x509\n");

        /*********************************************************************/
        clock_t begin, end;
        gnutls_datum_t signature;
        FILE *output_file = fopen("HHWRSAKey_SignData.txt", "a");
        for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
            begin = clock();
            if(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &hash_data, &signature) < 0){
                printf("[>]Error while signing data.");
            };
            end = clock();
            elapsed = end - begin;
            file_writer(output_file, elapsed);
        }
        fclose(output_file);

        output_file = fopen("HHWRSAKey_SignHashedData.txt", "a");
        for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
            begin = clock();
            if(gnutls_privkey_sign_hash(privkey, GNUTLS_DIG_SHA256, 0, &hash_data, &signature) < 0){
                printf("[>]Error while signing hashed data.");
            };
            end = clock();
            elapsed = end - begin;
            file_writer(output_file, elapsed);
        }
        fclose(output_file);
        /***********************************************************************************/
    }

    gnutls_x509_privkey_deinit(key);
	gnutls_privkey_deinit(privkey);
}


/*
* Data with Low hamming weight &&
* Data with high hamming weight, with the following functions:
*
*   [>] gnutls_privkey_sign_data()
*   [>] gnutls_privkey_sign_hash
*
*   Scenario: High&&Low Hamming weight data with some RSA key.
*/
void LHHW_OnData()
{
	gnutls_x509_privkey_t key;
	gnutls_x509_crt_t crt;
	gnutls_pubkey_t pubkey;
	gnutls_privkey_t privkey;
	int ret;
	size_t i;

	for (i = 0; i < sizeof(key_dat) / sizeof(key_dat[0]); i++) {
		
        ret = gnutls_x509_privkey_init(&key);
		if (ret < 0)
			checkRet(ret, "gnutls_x509_privkey_init\n");

		ret =
		    gnutls_x509_privkey_import(key, &key_dat[i],
						GNUTLS_X509_FMT_PEM);
		if (ret < 0)
			checkRet(ret, "gnutls_x509_privkey_import\n");

		ret = gnutls_pubkey_init(&pubkey);
		if (ret < 0)
			checkRet(ret, "gnutls_privkey_init\n");

		ret = gnutls_privkey_init(&privkey);
		if (ret < 0)
			checkRet(ret, "gnutls_pubkey_init\n");

		ret = gnutls_privkey_import_x509(privkey, key, 0);
		if (ret < 0)
			checkRet(ret, "gnutls_privkey_import_x509\n");

		ret = gnutls_x509_crt_init(&crt);
		if (ret < 0)
			checkRet(ret, "gnutls_x509_crt_init\n");

		ret =
		    gnutls_x509_crt_import(crt, &cert_dat[i],
					   GNUTLS_X509_FMT_PEM);
		if (ret < 0)
			checkRet(ret, "gnutls_x509_crt_import\n");

		ret = gnutls_pubkey_import_x509(pubkey, crt, 0);
		if (ret < 0)
			checkRet(ret, "gnutls_x509_pubkey_import\n");


	    /*********************************************************/
        void * dataLW = malloc(20); 
        memset(dataLW, 0, 20);
        memset(dataLW, 0x80, 1);
        const gnutls_datum_t low_hamming_data = {
	        (void *) dataLW, 
	        20
        };

        void * dataHW = malloc(20); 
        memset(dataHW,0xFF, 20);
        const gnutls_datum_t high_hamming_data = {
            (void *) dataHW, 
	        20
        };

        clock_t begin, end;
        gnutls_datum_t signature;
        long elapsed;
        FILE *output_file = fopen("LHWData_DataSign_keyX.txt", "a");
        for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
            begin = clock();
            if(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &low_hamming_data, &signature) < 0){
                printf("[>]Error while signing data.");
            };
            end = clock();
            elapsed = end - begin;
            file_writer(output_file, elapsed);
        }
        fclose(output_file);

        
        output_file = fopen("HHWData_DataSign_keyX.txt", "a");
        for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
            begin = clock();
            if(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &high_hamming_data, &signature) < 0){
                printf("[>]Error while signing data.");
            };
            end = clock();
            elapsed = end - begin;
            file_writer(output_file, elapsed);
        }
        fclose(output_file);
        
        output_file = fopen("LHWData_HashedDataSign_keyX.txt", "a");
        for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
            begin = clock();
            int ret = gnutls_privkey_sign_hash(privkey, GNUTLS_DIG_SHA256, 0, &low_hamming_data, &signature);
            end = clock();
            elapsed = end - begin;
            checkRet(ret, "error signing data.");
            file_writer(output_file, elapsed);
        }
        fclose(output_file);

        output_file = fopen("HHWData_HashedDataSign_keyX.txt", "a");
        for(int i=0; i<NUMBER_OF_ITERATIONS; i++){
            begin = clock();
            ret = gnutls_privkey_sign_hash(privkey, GNUTLS_DIG_SHA256, 0, &high_hamming_data, &signature);
            end = clock();
            elapsed = end - begin;
            checkRet(ret, "error signing data.");
            file_writer(output_file, elapsed);
        }
        fclose(output_file);
        /*********************************************************/
    }
        

	gnutls_x509_privkey_deinit(key);
	gnutls_x509_crt_deinit(crt);
	gnutls_privkey_deinit(privkey);
	gnutls_pubkey_deinit(pubkey);
}




