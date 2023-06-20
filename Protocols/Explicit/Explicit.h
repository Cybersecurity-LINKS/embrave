#ifndef EXPLICIT_H
#define EXPLICIT_H

#include <stdint.h>    
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../common.h"
//#include "../tpm_tools/tpm2_quote.h"
#include "../../tpm2-tools/lib/tpm2_convert.h"
#include "../../tpm2-tools/lib/tpm2_util.h"
#include "../../tpm2-tools/lib/tpm2_alg_util.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define NONCE_SIZE 32


typedef struct {
    uint16_t size;
    uint8_t buffer[NONCE_SIZE];
} Nonce;

/* typedef struct {
    //u_int8_t pcr10_sha1[SHA_DIGEST_LENGTH];
    u_int8_t pcr_sha256[15][SHA256_DIGEST_LENGTH];
} Pcr_list; */

typedef struct {
    Nonce nonce_blob;
} Ex_challenge;

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
void print_quoted(TPM2B_ATTEST * quoted);
void free_data (Ex_challenge_reply *rply);
BYTE * copy_signature(UINT16* size);
void print_signature(UINT16* size, BYTE *sig);
// soft binding
//sofbinding verify
// quote verify
#endif