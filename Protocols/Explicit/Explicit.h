#ifndef EXPLICIT_H
#define EXPLICIT_H

#include <stdint.h>    
#include <stdio.h>
#include "../common.h"
#include "../tpm_tools/tpm2_quote.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define NONCE_SIZE 32


typedef struct {
    uint16_t size;
    uint8_t buffer[NONCE_SIZE];
} Nonce;

typedef struct {
    //u_int8_t pcr10_sha1[SHA_DIGEST_LENGTH];
    u_int8_t pcr_sha256[15][SHA256_DIGEST_LENGTH];
} Pcr_list;

typedef struct {
    Nonce nonce_blob;
} Ex_challenge;

/* typedef struct tpm2_pcrs tpm2_pcrs;
struct tpm2_pcrs {
    size_t count;
    TPML_DIGEST pcr_values[TPM2_MAX_PCRS];
}; */

typedef struct {
    Nonce nonce_blob;
    UINT16 sig_size;
    BYTE *sig;
    tpm2_pcrs pcrs;
    //char *pcr_selections;
    TPM2B_ATTEST *quoted;
    //IMA
    //AK?
} Ex_challenge_reply;

int nonce_create(Nonce *nonce_blob);
int create_quote (Ex_challenge *chl, Ex_challenge_reply *rply,  ESYS_CONTEXT *ectx);

void free_data (Ex_challenge_reply *rply);
// soft binding
//sofbinding verify
// quote verify
#endif