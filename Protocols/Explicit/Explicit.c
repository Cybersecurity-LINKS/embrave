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
int callback(void *NotUsed, int argc, char **argv, char **azColName);
int read_ima_log_row(Ex_challenge_reply *rply, size_t *total_read, uint8_t * hash_ima, char * hash_name, char ** path_name);


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
    //set default values    
    sig_hash_algorithm = TPM2_ALG_NULL;
    pcrs_format = pcrs_output_format_serialized;
    in_scheme.scheme = TPM2_ALG_NULL;
    sig_scheme = TPM2_ALG_NULL;


    //Set AK handle
    key.handle=handle;

    //load AK aut (NULL)
    tool_rc rc = tpm2_util_object_load_auth(ectx, key.handle,key.auth_str, &(key.object), false, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        printf("Invalid key authorization\n");
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

    rc = tpm2_quote(ectx, &key.object, &in_scheme,&qualification_data, &pcr_select,
        &rply->quoted, &signature, NULL, TPM2_ALG_ERROR);
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
    pcr_print_(&pcr_select, &(rply->pcrs));
    //Copy nonce
    rply->nonce_blob.size = chl->nonce_blob.size;
    memcpy(&rply->nonce_blob.buffer, &chl->nonce_blob.buffer, rply->nonce_blob.size);

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

void pcr_print_(TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs){
    pcr_print_pcr_struct(pcr_select, pcrs);
}

int verify_quote(Ex_challenge_reply *rply, char* pem_file_name)
{
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    TPMS_ATTEST attest;
    TPM2B_DIGEST msg_hash =  TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPM2B_DIGEST pcr_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    char pcrs_select[10] = "sha256:all";
    if( rply == NULL || pem_file_name == NULL) return -1;
    
    bio = BIO_new_file(pem_file_name, "rb");
    if (!bio) {
        printf("Failed to open AK public key file '%s': %s\n", pem_file_name, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    //Load AK pub key from BIO
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        printf("Failed to convert public key from PEM\n");
        OPENSSL_free(bio);
        return -1;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx) {
        printf("EVP_PKEY_CTX_new failed\n");
        OPENSSL_free(bio);
        EVP_PKEY_free(pkey);
        return -1;
    }

    //Check if the key is a valid public key
    if(!EVP_PKEY_public_check(pkey_ctx)){
        printf("check key failed\n");
        goto err;
    }

    const EVP_MD *md = EVP_sha256();

    int rc = EVP_PKEY_verify_init(pkey_ctx);
    if (!rc) {
        printf("EVP_PKEY_verify_init failed \n");
        goto err;
    }

    rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, md);
    if (!rc) {
        printf("EVP_PKEY_CTX_set_signature_md failed \n");
        goto err;
    }

    //Convert from TPM2B to TPMS format to validate nonce and pcr digest
    tool_rc tmp_rc = files_tpm2b_attest_to_tpms_attest(rply->quoted, &attest);
    if (tmp_rc != tool_rc_success) {
        printf("files_tpm2b_attest_to_tpms_attest failed \n");
        goto err;
    }

    //Hash the quoted data
    rc = tpm2_openssl_hash_compute_data(TPM2_ALG_SHA256, rply->quoted->attestationData, rply->quoted->size, &msg_hash);
    if (!rc) {
        printf("Compute message hash failed!\n");
        goto err;
    }

    //1 verify OK 0 verify failed -rc ohter errors
    rc = EVP_PKEY_verify(pkey_ctx, rply->sig, rply->sig_size, msg_hash.buffer, msg_hash.size);
    if (rc != 1) {
        if (rc == 0) {
            printf("Quote signature verification failed\n");
        } else {
            printf("Error %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
        goto err;
    }

    // Verify the nonce
    if (attest.extraData.size != rply->nonce_blob.size || 
        memcmp(attest.extraData.buffer, rply->nonce_blob.buffer, attest.extraData.size) != 0) {
        printf("Error validating nonce\n");
        goto err;
    }

    // Deine the pcr selection
    if (!pcr_parse_selections(pcrs_select, &pcr_select)) {
        printf("pcr_parse_selections failed\n");
        goto err;
    } 

    //Create the pcr digest with the received pcrs
    if (!tpm2_openssl_hash_pcr_banks_le(TPM2_ALG_SHA256, &pcr_select, &rply->pcrs, &pcr_hash)) {
        printf("Failed to hash PCR values\n");
        goto err;
    }

    // Verify that the digest from quote matches PCR digest
    if (!tpm2_util_verify_digests(&attest.attested.quote.pcrDigest, &pcr_hash)) {
        goto err;
    }

    OPENSSL_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return 0;
err:
    OPENSSL_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return -1;
}


//dest buff, input data, len of data
void bin_2_hash(char *buff, BYTE *data, size_t len){

    size_t i;
    for (i = 0; i < len; i++) {
    /* "sprintf" converts each byte in the "buf" array into a 2 hex string
     * characters appended with a null byte, for example 10 => "0A\0".
     *
     * This string would then be added to the output array starting from the
     * position pointed at by "ptr". For example if "ptr" is pointing at the 0
     * index then "0A\0" would be written as output[0] = '0', output[1] = 'A' and
     * output[2] = '\0'.
     *
     * "sprintf" returns the number of chars in its output excluding the null
     * byte, in our case this would be 2. So we move the "ptr" location two
     * steps ahead so that the next hex string would be written at the new
     * location, overriding the null byte from the previous hex string.
     *
     * We don't need to add a terminating null byte because it's been already 
     * added for us from the last hex string. */  
        buff += sprintf(buff, "%02x", data[i]);
    }
   // buff[i] = '\0';

}
//read one row of the IMA Log
int read_ima_log_row(Ex_challenge_reply *rply, size_t *total_read, uint8_t * hash_ima, char * hash_name, char ** path_name){

    
    uint32_t pcr;
    uint32_t field_len;
	uint32_t field_path_len;
	uint8_t alg_field[8];
    uint8_t hash_name_byte[SHA256_DIGEST_LENGTH];

    memcpy(&pcr, rply ->ima_log, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);
    //printf("%d ", pcr);
    //printf("%ld\n ", *total_read);
    
    memcpy(hash_ima, rply ->ima_log + *total_read, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
    *total_read += sizeof(uint8_t) * SHA_DIGEST_LENGTH;
    //tpm2_util_hexdump(hash_ima, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
   // printf("\n ");
    

    uint32_t template_name_len;
    memcpy(&template_name_len, rply ->ima_log + *total_read, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);
    //printf("%d ", template_name_len);

    char template_type[TCG_EVENT_NAME_LEN_MAX + 1];
    memcpy(template_type, rply ->ima_log + *total_read, template_name_len);
    *total_read += template_name_len * sizeof(char);
    //printf("%s\n", template_type);
    

    uint32_t template_len;
    memcpy(&template_len, rply ->ima_log + *total_read, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);
    //printf("%d ", template_len);


    memcpy(&field_len, rply ->ima_log + *total_read, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);
    //printf("%d\n", field_len);

    memcpy(alg_field, rply ->ima_log + *total_read, 8*sizeof(uint8_t));
    *total_read += 8 * sizeof(uint8_t);
    //printf("%s", alg_field);

    memcpy(hash_name_byte, rply ->ima_log + *total_read, SHA256_DIGEST_LENGTH *sizeof(uint8_t));
    *total_read += SHA256_DIGEST_LENGTH * sizeof(uint8_t);
    //tpm2_util_hexdump(hash_name_byte, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);
   // printf("\n");
    bin_2_hash(hash_name, hash_name_byte, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);
    //printf("buff %s\n", hash_name);

    memcpy(&field_path_len, rply ->ima_log + *total_read, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);

    //
    *path_name = malloc(sizeof(char) * field_path_len);
    memcpy(*path_name, rply ->ima_log + *total_read, sizeof(char) * field_path_len);
    *total_read += sizeof(char) * field_path_len;
    //printf(" %s\n", *path_name);
   

    return 0;
}

int check_goldenvalue(sqlite3 *db, char * hash_name, char * path_name){
    sqlite3_stmt *res;
    char *sql = "SELECT * FROM golden_values WHERE name = @name and hash = @hash ";
    //char *sql = "SELECT * FROM golden_values WHERE name = @name ";
    int idx, idx2;
    char *err_msg = 0;


    //printf("%s\n", hash_name);
    //convert the sql statament 
    int  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        //Set the parametrized input
        idx = sqlite3_bind_parameter_index(res, "@name");
        sqlite3_bind_text(res, idx, path_name, strlen(path_name), NULL);
        
        idx2 = sqlite3_bind_parameter_index(res, "@hash");
        sqlite3_bind_text(res, idx2, hash_name, strlen(hash_name), NULL);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    int step = sqlite3_step(res);
    if (step == SQLITE_ROW) {
        
        printf("%s: ", sqlite3_column_text(res, 0));
        printf("%s\n", sqlite3_column_text(res, 1));
        
    } 

    sqlite3_finalize(res);

}

int verify_ima_log(Ex_challenge_reply *rply, sqlite3 *db){
    
    
    
    char hash_name[(SHA256_DIGEST_LENGTH * 2) + 1];
    uint8_t hash_ima[SHA_DIGEST_LENGTH];
    char event_name[TCG_EVENT_NAME_LEN_MAX + 1];
    char *path_name = NULL;
    
    size_t total_read = 0;
    uint32_t template_len;

    //verify the correct IMA log template 
    //ima_ng: PCR SHA1 TEMPLATE_NAME SHA256 HASH PATH_NAME
    total_read = sizeof(uint32_t) + SHA_DIGEST_LENGTH*sizeof(u_int8_t);
    memcpy(&template_len, rply ->ima_log + total_read, sizeof(uint32_t));
    total_read += sizeof(uint32_t);
    memcpy(event_name, rply ->ima_log + total_read, template_len);
    total_read = 0;
    
    //int ret = strcmp(event_name, "ima-ng") ;
    //printf("%d\n", ret);
    if(strcmp(event_name, "ima-ng") != 0){
        //other template here
        printf("Unknown IMA template\n");
        return -1;
    }

    //Read the first IMA log line  
    //TODO check is is incremental ima log
    read_ima_log_row(rply, &total_read,hash_ima, hash_name, &path_name);
    //TODO check the boot aggregate


    while(rply->ima_log_size != total_read){
        read_ima_log_row(rply, &total_read,hash_ima, hash_name, &path_name);
        
        //1 verify hash => golden value
        check_goldenvalue(db, hash_name, path_name);


        //Compute PCR10
        
        
        
        free(path_name);
    }
   // printf("%d\n", total_read);
    




    



    //printf("QUIIIIIIi 111\n");






  //  printf("QUIIIIIIi sql\n");

    return 0;
}

int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    
    //NotUsed = 0;

/*     for (int i = 0; i < argc; i++) {

        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    } */
    if(argv[0] > 0)
        return 0;
    else
        return 1;
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
    if(rply->quoted != NULL)
        free(rply->quoted);

    if(rply->sig != NULL)
        free(rply->sig);

    if(rply->ima_log != NULL)
        free(rply->ima_log);
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