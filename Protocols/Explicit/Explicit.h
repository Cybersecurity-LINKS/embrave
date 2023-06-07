#ifndef EXPLICIT_H
#define EXPLICIT_H

#define NONCE_SIZE 32
#include <stdint.h>    
#include <stdio.h>
typedef struct {
    uint16_t size;
    uint8_t buffer[NONCE_SIZE];
} Nonce;





typedef struct {
    Nonce nonce_blob;
    uint32_t PCR;
} Ex_challenge;

Ex_challenge* challenge_create(void);
#endif