#ifndef EXPLICIT_H
#define EXPLICIT_H

#include <stdint.h>    
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "../common.h"
#include "../../tpm2-tools/lib/tpm2_openssl.h"
#include "../../tpm2-tools/lib/files.h"
#include "../../tpm2-tools/lib/tpm2_convert.h"
#include "../../tpm2-tools/lib/tpm2_util.h"
#include "../../tpm2-tools/lib/tpm2_alg_util.h"
#include "../../tpm2-tools/lib/pcr.h"
#include "../../tpm2-tools/lib/object.h"
#include "../../tpm2-tools/lib/tpm2.h"
#include <openssl/sha.h>

#include <openssl/rand.h>

#define NONCE_SIZE 32


typedef struct {
    uint16_t size;
    uint8_t buffer[NONCE_SIZE];
} Nonce;

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
    unsigned char * ima_log;
    uint32_t ima_log_size;
    uint8_t wholeLog;
} Ex_challenge_reply;

int nonce_create(Nonce *nonce_blob);
int create_quote (Ex_challenge *chl, Ex_challenge_reply *rply,  ESYS_CONTEXT *ectx);
void print_quoted(TPM2B_ATTEST * quoted);
void free_data (Ex_challenge_reply *rply);
BYTE * copy_signature(UINT16* size);
void print_signature(UINT16* size, BYTE *sig);
void pcr_print_(TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs);

int verify_quote(Ex_challenge_reply *rply,const char* pem_file_name);
int verify_ima_log(Ex_challenge_reply *rply, sqlite3 *db, Tpa_data *tpa);
int PCR9softbindig(ESYS_CONTEXT *esys_context);
int PCR9softbindig_verify(Ex_challenge_reply *rply, Tpa_data * tpa_data);
int check_pcr9(ESYS_CONTEXT *esys_context);
#endif