#include "Explicit.h"

int challenge_create(Ex_challenge *chl)
{
    if (!RAND_bytes(chl->nonce_blob.buffer, NONCE_SIZE)){
        printf("Attestor client random generation error\n");
        return -1;
    }

    chl->nonce_blob.size = NONCE_SIZE;
    printf("NONCE sent:");
    for(int i= 0; i < NONCE_SIZE; i++)
        printf("%02X", chl->nonce_blob.buffer[i]);
    printf("\n");
    return 0;
}