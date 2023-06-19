#include "Explicit.h"

int get_quote_parameters(ESYS_CONTEXT *ectx, Ex_challenge_reply *rply);

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
    int ret;
   // char hash[7] ="sha256";
    if (ectx == NULL) {
        return -1;
    }
    //Set AK handle
    set_option('c', key);
    //Set pcr sha256 select all
    set_option('l', pcrs);
    //hash
   // set_option('g', hash);
    //Set nonce
    set_option('q', chl->nonce_blob.buffer);
    ret = tpm2_quote_start(ectx);
    if(ret != 0){
        printf("tpm2_quote_start error %d\n", ret);
        return -1;
    }
    //fill challenge reply structure
    if(get_quote_parameters(ectx, rply) != 0){
        printf("get_quote_parameters error\n");
        return -1;
    }
    //free used data 
    ret = tpm2_quote_free(ectx);
    if(ret != 0){
        printf("tpm2_quote_free error %d\n", ret);
        return -1;
    }
    return 0;
}

int get_quote_parameters(ESYS_CONTEXT *ectx ,Ex_challenge_reply *rply){
    //get quoted data
    rply->quoted = get_quoted();
    if(rply->quoted == NULL) return -1;
    printf("\n\n");
    printf("Quoted: ");
    print_tpm2b(rply->quoted);
    printf("\n\n");

    //get signature
    printf("Signature: ");
    rply->sig = get_signature(&(rply->sig_size));
    if(rply->sig == NULL) return -1;
    printf("\n\n");

    //get pcr list
    if (get_pcrList(ectx, &(rply->pcrs)) != 0 ){
        return -1;
    }
    pcr_print_(&(rply->pcrs));
    return 0;
}

void free_data (Ex_challenge_reply *rply){
    if(rply->quoted == NULL)
        printf("quoted alredy freed\n");
    else
        free(rply->quoted);
    if(rply->sig == NULL)
        printf("sig alredy freed\n");
    else
        free(rply->sig);
}