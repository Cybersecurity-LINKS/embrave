#include "Explicit.h"

int nonce_create(Nonce *nonce_blob)
{
    if (!RAND_bytes(nonce_blob->buffer, NONCE_SIZE)){
        printf("Attestor client random generation error\n");
        return -1;
    }

    nonce_blob->size = NONCE_SIZE;
    printf("NONCE sent:");
    for(int i= 0; i < NONCE_SIZE; i++)
        printf("%02X", nonce_blob->buffer[i]);
    printf("\n");
    return 0;
}