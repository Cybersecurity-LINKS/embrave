#include "Explicit.h"



TPML_PCR_SELECTION pcr_select;
TPMT_SIG_SCHEME in_scheme;
TPMI_ALG_SIG_SCHEME sig_scheme;
tpm2_convert_sig_fmt sig_format;
TPMI_ALG_HASH sig_hash_algorithm;
TPM2B_DATA qualification_data;
TPMS_CAPABILITY_DATA cap_data;
tpm2_convert_pcrs_output_fmt pcrs_format;
TPMT_SIGNATURE *signature;

struct {
        const char *handle;
        const char *auth_str;
        tpm2_loaded_object object;
} key;




//int get_quote_parameters(ESYS_CONTEXT *ectx, Ex_challenge_reply *rply);
tool_rc tpm2_quote_free(void);
int get_pcrList(ESYS_CONTEXT *ectx, tpm2_pcrs *pcrs);


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
    char handle[11]= "0x81000004";
    char pcrs[10] = "sha256:all";
    int ret;
    tpm2_algorithm algs;
   // char hash[7] ="sha256";
    if (ectx == NULL || rply == NULL || chl == NULL) {
        return -1;
    }
    sig_hash_algorithm = TPM2_ALG_NULL;
    //qualification_data = TPM2B_EMPTY_INIT;
    pcrs_format = pcrs_output_format_serialized;
    in_scheme.scheme = TPM2_ALG_NULL;
    sig_scheme = TPM2_ALG_NULL;
    //set default values

    //Set AK handle
    key.handle=handle;

    //load AK aut (NULL)
    tool_rc rc = tpm2_util_object_load_auth(ectx, key.handle,key.auth_str, &(key.object), false, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        printf("Invalid key authorization");
        return -1;
    }     

    //Set pcr to quote (all sha256) 
    if (!pcr_parse_selections(pcrs, &pcr_select)) {
        printf("pcr_parse_selections failed\n");
        return -1;
    }


    //Set nonce
    qualification_data.size = TPM2_SHA256_DIGEST_SIZE;
    memcpy(qualification_data.buffer, chl->nonce_blob.buffer, qualification_data.size);

    
    rc = pcr_get_banks(ectx, &cap_data, &algs);
    if (rc != tool_rc_success) {
        return -1;
    }

    //Get signature type based on the key
    rc = tpm2_alg_util_get_signature_scheme(ectx, key.object.tr_handle,
        &sig_hash_algorithm, sig_scheme, &in_scheme);
    if (rc != tool_rc_success) {
        return -1;
    }

    rc = tpm2_quote(ectx, &key.object, &in_scheme,&qualification_data, &pcr_select, &rply->quoted, &signature, NULL, TPM2_ALG_ERROR);
    if(rc != 0){
        printf("tpm2 quote error %d\n", rc);
        return -1;
    }

    print_quoted(rply->quoted);

    rply->sig = copy_signature(&(rply->sig_size));
    if(rply->sig == NULL) return -1;
    print_signature(&(rply->sig_size), rply->sig);

    //Get PCR List
    if (get_pcrList(ectx, &(rply->pcrs)) != 0 ){
        return -1;
    }
    //
    //free used data 
    ret = tpm2_quote_free();
    if(ret != 0){
        printf("tpm2_quote_free error %d\n", ret);
        return -1;
    }
    pcr_print_(&(rply->pcrs));


    return 0;
}

int get_pcrList(ESYS_CONTEXT *ectx, tpm2_pcrs *pcrs){
    if( ectx == NULL || pcrs == NULL) return -1;

    // Filter out invalid/unavailable PCR selections
    if (!pcr_check_pcr_selection(&cap_data, &pcr_select)) {
        printf("Failed to filter unavailable PCR values for quote!\n");
        return -1;
    }

    // Read PCR values from the TPM because the quote doesn't have them!
    tool_rc rc = pcr_read_pcr_values(ectx, &pcr_select, pcrs, NULL, TPM2_ALG_ERROR);
    if (rc != tool_rc_success) {
        printf("Failed to retrieve PCR values related to quote!\n");
        return -1;
    }

/*        //Check if computed digest 
    // Grab the digest from the quote
    rc = files_tpm2b_attest_to_tpms_attest(ctx.quoted, &ctx.attest);
    if (rc != tool_rc_success) {
        return rc;
    }


    // Calculate the digest from our selected PCR values (to ensure correctness)
    TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    bool is_pcr_hashing_success = tpm2_openssl_hash_pcr_banks(
        ctx.sig_hash_algorithm, &ctx.pcr_selections, &ctx.pcrs,
        &pcr_digest);
    if (!is_pcr_hashing_success) {
        LOG_ERR("Failed to hash PCR values related to quote!");
        return tool_rc_general_error;
    }
    tpm2_tool_output("calcDigest: ");
    tpm2_util_hexdump(pcr_digest.buffer, pcr_digest.size);
    tpm2_tool_output("\n");

    // Make sure digest from quote matches calculated PCR digest
    bool is_pcr_digests_equal = tpm2_util_verify_digests(
        &ctx.attest.attested.quote.pcrDigest, &pcr_digest);
    if (!is_pcr_digests_equal) {
        LOG_ERR("Error validating calculated PCR composite with quote");
        return tool_rc_general_error;
    } */



    return 0;
}

void pcr_print_(tpm2_pcrs *pcrs){
    pcr_print_pcr_struct(&pcr_select, pcrs);
}

/* int get_quote_parameters(ESYS_CONTEXT *ectx ,Ex_challenge_reply *rply){
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
    //pcr_print_(&(rply->pcrs));
    return 0;
} */

tool_rc tpm2_quote_free(void) {

/*     if (ctx.pcr_output) {
        fclose(ctx.pcr_output);
    } */
    //free(ctx.quoted);
    free(signature);

    //Close authorization sessions
    tool_rc rc = tpm2_session_close(&key.object.session);

    return rc;
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

void print_quoted(TPM2B_ATTEST * quoted){
    printf("Quoted: ");
    tpm2_util_print_tpm2b(quoted);
    printf("\n");
}

void print_signature(UINT16* size, BYTE *sig){
    printf("Signature: ");
    tpm2_util_hexdump(sig, *size);
    printf("\n");
}

BYTE * copy_signature(UINT16* size){
    BYTE *sig = tpm2_convert_sig(size, signature);
    if (!sig) {
        printf("tpm2_convert_sig error\n");
        return NULL;
    }
    return sig;
}