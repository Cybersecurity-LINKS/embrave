#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "x509.h"

int verify_x509_cert(unsigned char *cert_buff, int cert_len) {
    // Load from memory the certificate to be verified
    // BIO_new_file("/home/enrico/Documents/PoliTo/PhD/LINKS/test_cert_verify/RSA_EK_cert.bin", "rb");
    BIO *bio = BIO_new_mem_buf((void *) cert_buff, cert_len);
    if (!bio) {
        fprintf(stderr, "ERROR: reading certificate buffer.\n");
        return 1;
    }

    /* for(int i=0; i<cert_len; i++){
        printf("%02x", cert_buff[i]);
    }
    printf("\n"); */

    X509 *cert = d2i_X509_bio(bio, NULL);
    if (!cert) {
        fprintf(stderr, "ERROR: reading certificate from BIO.\n");
        BIO_free(bio);
        return 1;
    }

    // Create a certificate store
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "ERROR: creating X509_STORE.\n");
        return 1;
    }

    // Add a directory lookup method to the store
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (!lookup) {
        fprintf(stderr, "ERROR: creating X509_LOOKUP.\n");
        return 1;
    }
    if (X509_LOOKUP_add_dir(lookup, "/home/linux/Documents/lemon/tpm_ca_certs_hash_dir", X509_FILETYPE_PEM) != 1) {
        fprintf(stderr, "ERROR: adding ca certs hash directory to X509_LOOKUP.\n");
        return 1;
    }

    // Create a certificate context for the certificate to be verified
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "ERROR: creating X509_STORE_CTX.\n");
        return 1;
    }
    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        fprintf(stderr, "ERROR: initializing X509_STORE_CTX.\n");
        return 1;
    }

    // Verify the certificate
    int result = X509_verify_cert(ctx);
    if (result != 1) {
        fprintf(stderr, "ERROR: EK certificate verification failed: %s.\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        return 1;
    }

    // Clean up
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    BIO_free(bio);
    X509_free(cert);

    return 0;
}