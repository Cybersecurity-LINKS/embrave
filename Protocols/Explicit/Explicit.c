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

int create_quote(Ex_challenge *chl, Ex_challenge_reply *rply,  ESYS_CONTEXT *ectx)
{
    char key[11] = "0x81000004";
    char pcrs[10] ="sha256:all";
    char hash[7] ="sha256";
    if (ectx == NULL) {
        return -1;
    }
    //AK handle
    set_option('c', key);
    //pcr select all
    set_option('l', pcrs);
    //hash
    set_option('g', hash);
    //nonce
    set_option('q', chl->nonce_blob.buffer);

    tpm2_quote_start(ectx);
    //free used data 
    tpm2_quote_free(ectx);

    return 0;
}
