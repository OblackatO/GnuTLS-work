#include <stdio.h>
#include <gnutls/abstract.h>


/**
* init_key:
*
* Inits an abstract private key.
*
* returns: Initialized private abstract key 
*/
gnutls_privkey_t init_key() 
{
        gnutls_privkey_t abs_key;
        if(!(gnutls_privkey_init(&abs_key) == GNUTLS_E_SUCCESS))
                printf("An error occurred while init private key");
        return abs_key;
} 


/**
* generate_rsa_keypair:
* @priv_key: Is an initialized private abstract key.
*
*/
int generate_rsa_keypair(gnutls_privkey_t priv_key)
{
        //generates private key
        gnutls_pk_algorithm_t algo_token = gnutls_pk_get_id("RSA");
        int result = gnutls_privkey_generate(priv_key, 
                                     		 algo_token, 
                                     		 512, 
                                     		 0);
        
        //Puts a private key in PEM format and prints it as a string. 
        gnutls_x509_privkey_t key_509;
        gnutls_privkey_export_x509(priv_key, &key_509);
        gnutls_datum_t datum;
        gnutls_x509_privkey_export2_pkcs8(key_509, GNUTLS_X509_FMT_PEM, "", 0, &datum);
        printf("datum:\n%s", datum.data);

        /*
        Code to extract the necessary info about the key.
        gnutls_datum_t m;
        gnutls_datum_t e;
        gnutls_datum_t d;
        gnutls_datum_t p;
        gnutls_datum_t q;
        gnutls_datum_t u;
        gnutls_datum_t e1;
        gnutls_datum_t e2;
        int exportation = gnutls_privkey_export_rsa_raw(priv_key, &m, 
                                                &e, 
                                                &d, 
                                                &p, 
                                                &q, 
                                                &u, 
                                                &e1, 
                                                &e2);
        if(exportation == GNUTLS_E_SUCCESS){
                printf("e:%s\n", e.data);
        }
        */
        
        return result;
}


int main(void) 
{ 

        printf("Result: %d\n", generate_rsa_keypair(init_key()));

}
