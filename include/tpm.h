// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef EXPLICIT_H
#define EXPLICIT_H

#include <stdint.h>    
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "common.h"
#include "tpm2_openssl.h"
#include "files.h"
#include "tpm2_convert.h"
#include "tpm2_util.h"
#include "tpm2_alg_util.h"
#include "pcr.h"
#include "object.h"
#include "tpm2.h"
#include <openssl/sha.h>

#include <openssl/rand.h>

#define NONCE_SIZE 32


typedef struct {
    uint16_t size;
    uint8_t buffer[NONCE_SIZE];
} Nonce;

typedef struct {
    Nonce nonce_blob;
    uint8_t send_wholeLog;
} tpm_challenge;

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
    //int dsc;
} tpm_challenge_reply;

int nonce_create(Nonce *nonce_blob);
int create_quote (tpm_challenge *chl, tpm_challenge_reply *rply,  ESYS_CONTEXT *ectx);
void print_quoted(TPM2B_ATTEST * quoted);
void free_data (tpm_challenge_reply *rply);
BYTE * copy_signature(UINT16* size);
void print_signature(UINT16* size, BYTE *sig);
void pcr_print_(TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs);

int verify_quote(tpm_challenge_reply *rply,const char* pem_file_name, Tpa_data *tpa);
int verify_ima_log(tpm_challenge_reply *rply, sqlite3 *db, Tpa_data *tpa);
int PCR9softbindig(ESYS_CONTEXT *esys_context);
int PCR9softbindig_verify(tpm_challenge_reply *rply, Tpa_data * tpa_data);
int check_pcr9(ESYS_CONTEXT *esys_context);
int refresh_tpa_entry(Tpa_data *tpa);
#endif