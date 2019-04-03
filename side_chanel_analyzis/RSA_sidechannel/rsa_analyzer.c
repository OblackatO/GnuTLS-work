#include <stdio.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_analyzer.h"

//Check return value
void checkRet(int ret, char* function) {
 if (ret < 0) {
    fprintf(stderr, "An error occurs during %s: %s\n", function, gnutls_strerror(ret));
    exit(1);
  }
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

static void print_hex_datum(FILE * outfile, gnutls_datum_t * dat)
{
	for (unsigned int j = 0; j < dat->size; j++) {
		fprintf(outfile, "%.2x", (unsigned char) dat->data[j]);
	}
}


/* sha1 hash of "hello" string */
const gnutls_datum_t hash_data = {
	(void *)
	    "\xaa\xf4\xc6\x1d\xdc\xc5\xe8\xa2\xda\xbe"
	    "\xde\x0f\x3b\x48\x2c\xd9\xae\xa9\x43\x4d",
	20
};

const gnutls_datum_t raw_data = {
	(void *) "hello there",
	11
};

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

const gnutls_datum_t cert_dat[] = {
	{(void *) pem1_cert, sizeof(pem1_cert)}
};

const gnutls_datum_t key_dat[] = {
	{(void *) pem1_key, sizeof(pem1_key)}
};


static char pem1_HHWkey[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIHcAgEAAkEApunQnUVmIVpE12tOzHy5Mm3blrR/f/cpuyiOU7I0I6xMH4hJSalG\n"
    "3mBWSvMg4XhSCtWRBHIwpVN9UHbEy+iBZwIDAQABAkA39aPvVlkLTYxO/LcKb7ZX\n"
    "ZeV8/T7R1De1e79b6B765jpb7bXy3CXUW2N7Uv2Ljt7/OdNb89UVPU9aj1aPfttB\n"
    "AiEAx0DsfPOpPMrdUGNUfRzk94l44iEuhkTI5mXAiXqcYR8CIQDWcwtBQrpbcThF\n"
    "WU54KagQGYRcPJ11+xn8SKK85HVuuQIBAAIBAAIBAA==\n"
    "-----END RSA PRIVATE KEY-----\n";


static char pem1_LHWkey[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIHcAgEAAkEA6AFcaP3z7zu6N/DKGgyclY80LZ1gNcQ4OYLuHgJbgXABQ83uq33r\n"
    "1PuWUlwMBw09utd0bvCtae/OFn/hA0NxtQIDAQABAkBoagxj+D8roQ7bFFRwytJC\n"
    "ATQzf0uIhyniwElYWilCpAGdQCy4oQAE0z8BrZZN+QANgAkEayiwTAhWAGBYKlkB\n"
    "AiEA8TEVQdjxGEM/AmMWbeXGkQsaqqiNQPTzTlflGGx/lsECIQD2P+QZOvdVukam\n"
    "3XuNR0EwXdZnx7k11VSbboEtHAXr9QIBAAIBAAIBAA==\n"
    "-----END RSA PRIVATE KEY-----\n";


const gnutls_datum_t HHWkey_dat[] = {
	{(void *) pem1_key, sizeof(pem1_HHWkey)}
};

const gnutls_datum_t LHWkey_dat[] = {
	{(void *) pem1_key, sizeof(pem1_LHWkey)}
};

void RSALHW(){
    
    gnutls_x509_privkey_t key;
	gnutls_privkey_t privkey;
	gnutls_datum_t out, out2;
	int ret;
	size_t i;

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
        FILE *output_file = fopen("HHWRSAKey_SignData.txt", "a");
        begin = clock();
        if(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &high_hamming_data, &signature) < 0){
            printf("[>]Error while signing data.");
        };
        end = clock();
        long elapsed = end - begin;
        file_writer(output_file, elapsed);
        fclose(output_file);
        /***********************************************************************************/


    }
}


void doit()
{
	gnutls_x509_privkey_t key;
	gnutls_x509_crt_t crt;
	gnutls_pubkey_t pubkey;
	gnutls_privkey_t privkey;
	gnutls_datum_t out, out2;
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


		ret =
		    gnutls_pubkey_encrypt_data(pubkey, 0, &hash_data,
						&out);

		if (ret < 0)
			checkRet(ret, "gnutls_pubkey_encrypt_data\n");

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
        FILE *output_file = fopen("LHWData_DataSign_keyX.txt", "a");
        begin = clock();
        if(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &low_hamming_data, &signature) < 0){
            printf("[>]Error while signing data.");
        };
        end = clock();
        long elapsed = end - begin;
        file_writer(output_file, elapsed);
        fclose(output_file);

        
        output_file = fopen("HHWData_DataSign_keyX.txt", "a");
        begin = clock();
        if(gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &high_hamming_data, &signature) < 0){
            printf("[>]Error while signing data.");
        };
        end = clock();
        elapsed = end - begin;
        file_writer(output_file, elapsed);
        fclose(output_file);
        
        output_file = fopen("LHWData_HashedDataSign_keyX.txt", "a");
        begin = clock();
        int ret = gnutls_privkey_sign_hash(privkey, GNUTLS_DIG_SHA256, 0, &low_hamming_data, &signature);
        end = clock();
        elapsed = end - begin;
        checkRet(ret, "error signing data.");
        file_writer(output_file, elapsed);
        fclose(output_file);

        output_file = fopen("HHWData_HashedDataSign_keyX.txt", "a");
        begin = clock();
        ret = gnutls_privkey_sign_hash(privkey, GNUTLS_DIG_SHA256, 0, &high_hamming_data, &signature);
        end = clock();
        elapsed = end - begin;
        checkRet(ret, "error signing data.");
        file_writer(output_file, elapsed);
        fclose(output_file);
        return;

        /*
        gnutls_datum_t plaintext;
        output_file = fopen("Decrypt_HHWData.txt", "a");
        begin = clock();
        if(gnutls_privkey_decrypt_data(privkey, 0, &out, &plaintext) < 0){
            printf("[>]Error while decrypting with low hamming weight.");
        }
        end = clock();
        elapsed = end - begin;
        file_writer(output_file, elapsed);   
        fclose(output_file);

        output_file = fopen("Decrypt_LHWData.txt", "a");
        begin = clock();
        if(gnutls_privkey_decrypt_data(privkey, 0, &out, &plaintext) < 0){
            printf("[>]Error while decrypting with low hamming weight.");
        }
        end = clock();
        elapsed = end - begin;
        file_writer(output_file, elapsed);   
        fclose(output_file);
        */
    }
        /*********************************************************/

		gnutls_free(out.data);
		gnutls_free(out2.data);
		gnutls_x509_privkey_deinit(key);
		gnutls_x509_crt_deinit(crt);
		gnutls_privkey_deinit(privkey);
		gnutls_pubkey_deinit(pubkey);
}


//RSA key used for all the required procedures.
gnutls_privkey_t rsa_privkey_import(int isLowHammingWeight){

    
    gnutls_datum_t m = importHexData("c7dfceb56744469de1d608921ca97722990a88fc8d1bda0df450d4f97bee19273fe1bdb89ef9a83ca750521fe7c742f579dd7080ccbd4fa43dccd238f7a0f35357d2d80821f423b53bf22111df8f92ae4282a4dd50bcaaff58c1814e28ea89bf2f44cfc5f01a708337db148c1320a719130813a70b3c88d2da83db47b7b6c23fe49040f3847bd49ba78b49d776fdf9f7153e56078875a5b45836f022c472a2b483d4a7c1cae294d8affd8b35a8c1d2f10983ee05802a5a981b531beab8e6ccc8ea548b1e4c4df1792ca15967e23b4ab2be559947bfa2abeca494517e6b54d4e13491052de26c77ae578f600f8b8b075b9cd15622e6831da03271644c4ef384e7");
    gnutls_datum_t p = importHexData("ffbd25037436ddd3f6a9578e35bef092bfd97de5a0b0193d50cf86c5c531eac7a3a9e0e0711c2cdcfe5b87c09cb321610dc85530ed3a4a412ed28de8354a5b44867d99c8814287e7b4246714ab85b98292125c23e15e4c583b8bade984059a8123c63d5345ff155fb2be86c9b5041b10b247fc4f1ea5f696dfd217dae9ab037b");
    gnutls_datum_t q = importHexData("c8140f07bd0e7d94c8de7d5cd97545bb47902c6f42900cf0ed5794ad1e696333ee2393881132c8a2bead36a293d6e4f73d05166e5e615f739e25eeeada255f46cd8c56f90c3150a041ace114cf2d60b01c46ba09f52d33b4f5f5e1a5461c120adaa79bee2e38f89d322f52a8b5fdaaebb0186a3705ec6e661d96fc5f7a0f4285");

    gnutls_datum_t el = importHexData("ab49423e832260c860f3cf3f176e82064858f313043d5cfbb1d87d0e5bb9a340ff3f882a05f1e7d0194f778e0fa3e746811d04de45208a6acf78a7eeadb1fa3de56f680b51729a1b6d30bbd56559609accf6335e27476a2c7dfa7dc3a694c3ef5d535ecd501898473a495f2f0db8ba01561e5c8bf94b2310f8e2765ad11c36b3250fec690b902e3e0305ccf0ce1566fa31a5c336be14014a73a2387960adea37c83014717621a9513fcc4e25a0f14b6bf259b6f9a25ed79995e2c275e3ef635c79736eac0e4a23976044d80d6af7fedfd879878b10ebdf37d71fcb315ea91af3256a22573800f8c81e8e72200dab4b3d125f010ecfcdb52d82fd80e7edae6e03");
    gnutls_datum_t dl = importHexData("80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003");

    gnutls_datum_t eh = importHexData("4cd370c6f9eba552abd2dff17f4195186f2eb95798b83c152183335cd1bb480855dd088332a5d1aaa0b228dcd6eaa454f22658295b73d8a1c7d09b75ce4d8c92f26a6a3866c162515789119c8dbff0dedc4db65125676e240779c6c1b4e638ba1895c22ea2bb305dbbe2cc10cd213a2edb7a645b478b67a836e2bc3c2ca94c0c40b638d7bfdb9739f9f1732d17223986704f2f07be4e1a6ba4d3a3cb9741d37f9b973010d2e8b032136879287cf72a5a0faed08d25dcd5b4de544d678611db8d5bf3c90fa662523035942c0a03176cc7bcb9efd29d23883739cc3aeb8d3d72c580f9844bf53b5ff0599dd98a4b5e9f6ae4506941e665f9b261d0615dc7f3937f");
    gnutls_datum_t dh = importHexData("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    gnutls_datum_t u = {
        NULL, 0
    };

    gnutls_privkey_t privkey;
    if(isLowHammingWeight == TRUE){
        
        gnutls_privkey_init(&privkey);
        int ret = gnutls_privkey_import_rsa_raw(privkey, &m, &el, &dl, &p, &q, NULL, NULL, NULL);
        checkRet(ret, "LowHammingWeight_import");
        return privkey;
    
    }else{
        
        gnutls_privkey_init(&privkey);
        if (gnutls_privkey_import_rsa_raw(privkey, &m, &eh, &dh, &p, &q, &u, &u, &u) < 0) {
            printf("[>]Error while importing key with hight hamming weight.");
        }
        return privkey;
    }
}

/*
static void rsa_key_generator(int key_size){

    if(gnutls_privkey_init(&privkey) < 0){
        printf("[>]Error in init of RSA key.");
    };

    if(gnutls_privkey_generate(privkey, GNUTLS_PK_RSA, key_size, 0) < 0){
        printf("[>]Error generating RSA key.");
    };
}
*/

/**
 * Signes data, using the function: gnutls_privkey_sign_data
 *
 */  
gnutls_datum_t rsa_data_sign(   gnutls_privkey_t *privkey, 
                                gnutls_digest_algorithm_t hash,
                                unsigned int flags,
			                    const gnutls_datum_t *data,
                                int write_ticks,
                                int UseLHW_key,
                                int Use_HHW_key,
                                FILE *output_file)
{

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
        if(gnutls_privkey_sign_data(&privkey, GNUTLS_DIG_SHA256, 0, data, &signature) < 0){
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
void rsa_hashedata_sign(gnutls_privkey_t *privkey, 
                        gnutls_datum_t *hash_data, 
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
        int ret = gnutls_privkey_sign_hash(rsa_privkey_import(TRUE), GNUTLS_DIG_SHA256, 0, hash_data, &signature);
        end = clock();
        checkRet(ret, "error signing data.");
    
    }else if(Use_HHW_key == TRUE){
        
        begin = clock();
        int ret = gnutls_privkey_sign_hash(rsa_privkey_import(FALSE), GNUTLS_DIG_SHA256, 0, hash_data, &signature);
        end = clock();
        checkRet(ret, "error signing data.");

    }else{

        begin = clock();
        int ret = gnutls_privkey_sign_hash(&privkey, GNUTLS_DIG_SHA256, 0, hash_data, &signature);
        end = clock();
        checkRet(ret, "error signing data.");
    }
    
    long elapsed = end - begin;
    file_writer(output_file, elapsed);
}


void decrypt_data( gnutls_privkey_t privkey, 
                   int UseLHW_key,
                   int Use_HHW_key,
                   const gnutls_datum_t *data_to_decrypt,
                   FILE* output_file)
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

    long elapsed = end - begin;
    file_writer(output_file, elapsed);
}

void file_writer(FILE *output_file, long elapsed){
    
    fprintf(output_file, "%lu\n", elapsed);
}


