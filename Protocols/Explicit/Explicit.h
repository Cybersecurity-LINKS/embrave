#ifndef EXPLICIT_H
#define EXPLICIT_H

#include <stdint.h>    
#include <stdio.h>
#include "../common.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define NONCE_SIZE 32


typedef struct {
    uint16_t size;
    uint8_t buffer[NONCE_SIZE];
} Nonce;

typedef struct {
  //uint8_t tag; // 1
  uint16_t size;
  uint8_t *buffer;
} Signature;

typedef struct {
    //u_int8_t pcr10_sha1[SHA_DIGEST_LENGTH];
    u_int8_t pcr_sha256[15][SHA256_DIGEST_LENGTH];
} Pcr_list;

typedef struct {
    Nonce nonce_blob;
} Ex_challenge;

typedef struct {
    Nonce nonce_blob;
    Signature sig_blob;
    Pcr_list pcrs;
    //IMA
    //AK?
} Ex_challenge_reply;

int nonce_create(Nonce *nonce_blob);
int  create_quote (Ex_challenge *chl, Ex_challenge_reply *rply);
// soft binding
//sofbinding verify
// quote verify
#endif