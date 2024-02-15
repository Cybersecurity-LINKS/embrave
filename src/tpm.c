// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


#include "tpm.h"


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

tool_rc tpm2_quote_free(void);
int get_pcrList(ESYS_CONTEXT *ectx, tpm2_pcrs *pcrs, TPML_PCR_SELECTION *pcr_select);
int callback(void *NotUsed, int argc, char **argv, char **azColName);
int read_ima_log_row(tpm_challenge_reply *rply, size_t *total_read, uint8_t * template_hash, uint8_t * template_hash_sha256, char * hash_name, char ** path_name, uint8_t *hash_name_byte);
int compute_pcr10(uint8_t * pcr10_sha1, uint8_t * pcr10_sha256, uint8_t * sha1_concatenated, uint8_t * sha256_concatenated, uint8_t *template_hash, uint8_t *template_hash_sha256);
int verify_pcrsdigests(TPM2B_DIGEST *quoteDigest, TPM2B_DIGEST *pcr_digest);

int nonce_create(uint8_t *nonce)
{
    if (!RAND_bytes(nonce, NONCE_SIZE)){
        fprintf(stderr, "ERROR: random generation error\n");
        return -1;
    }
//#ifdef VERBOSE
    printf("NONCE created:");
    for(int i= 0; i < NONCE_SIZE; i++)
        printf("%02X", nonce[i]);
    printf("\n"); 
//#endif
    fflush(stdout);
    return 0;
}

int openPEM(const char *path, unsigned char **pem_file) {
  int len_file = 0;
  unsigned char *data;
  FILE *fp = fopen(path, "r");
  if(fp == NULL){
    fprintf(stderr, "ERROR: Could not open the PEM file %s \n", path);
    return -1;
  }

  //get len of file
  fseek(fp, 0L, SEEK_END);
  len_file = ftell(fp);
  fseek(fp, 0L, SEEK_SET);

  // read the data from the file 
  data = (unsigned char*) malloc((len_file + 1)*sizeof(char));
  if(data == NULL){
    fprintf(stderr, "ERROR: malloc error for reading file %s\n", path);
    return -1;
  }
  fread(data, 1, len_file, fp);
  data[len_file] = '\0';

  *pem_file = data;
  fclose (fp);
  return 0;
}

int create_quote(tpm_challenge *chl, tpm_challenge_reply *rply,  ESYS_CONTEXT *ectx)
{
    char handle[27]= "/var/lemon/attester/ak.ctx";
    TPML_PCR_SELECTION pcr_select;
    int ret;
    tpm2_algorithm algs;
    TPMS_ATTEST attest;
    TPM2B_DIGEST pcr_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

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
        fprintf(stderr, "ERROR: Invalid key authorization\n");
        return -1;
    }     

    //Set pcr to quote (all sha256) 
    if (!pcr_parse_selections("sha1:10+sha256:all", &pcr_select, NULL)) {
        fprintf(stderr, "ERROR: pcr_parse_selections failed\n");
        /* printf("ERRORE QUI?\n"); */
        return -1;
    }

    //Set nonce
    qualification_data.size = TPM2_SHA256_DIGEST_SIZE;
    memcpy(qualification_data.buffer, chl->nonce, qualification_data.size);

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
    
    //Retry quote util quoted pcr digest == read pcr digest
    do{
        rc = tpm2_quote(ectx, &key.object, &in_scheme,&qualification_data, &pcr_select,
        &rply->quoted, &signature, NULL, TPM2_ALG_ERROR);
        if(rc != 0){
            fprintf(stderr, "ERROR: tpm2 quote error %d\n", rc);
            return -1;
        }

        //Get PCR List
        if (get_pcrList(ectx, &(rply->pcrs), &pcr_select) != 0 ){
            return -1;
        }

        //Convert from TPM2B to TPMS format to validate nonce and pcr digest
        rc = files_tpm2b_attest_to_tpms_attest(rply->quoted, &attest);
        if (rc != tool_rc_success) {
            fprintf(stderr, "ERROR: files_tpm2b_attest_to_tpms_attest failed \n");
            return -1;
        }

        //Create the pcr digest with the received pcrs
        if (!tpm2_openssl_hash_pcr_banks_le(TPM2_ALG_SHA256, &pcr_select, &rply->pcrs, &pcr_hash)) {
            fprintf(stderr, "ERROR: Failed to hash PCR values\n");
            return -1;
        }

        // Verify that the digest from quote matches PCR digest
        rc = verify_pcrsdigests(&attest.attested.quote.pcrDigest, &pcr_hash);

    } while (rc != 0);

    rply->sig = copy_signature(&(rply->sig_size));
    if(rply->sig == NULL) return -1;
    print_signature(&(rply->sig_size), rply->sig);

    //Free used data 
    ret = tpm2_quote_free();
    if(ret != 0){
        fprintf(stderr, "ERROR: tpm2_quote_free error %d\n", ret);
        return -1;
    }

    //Copy he nonce
    memcpy(&rply->nonce, &chl->nonce, NONCE_SIZE * sizeof(uint8_t));

    return 0;
}

int get_pcrList(ESYS_CONTEXT *ectx, tpm2_pcrs *pcrs, TPML_PCR_SELECTION *pcr_select){
    if( ectx == NULL || pcrs == NULL) return -1;

    // Filter out invalid/unavailable PCR selections
    if (!pcr_check_pcr_selection(&cap_data, pcr_select)) {
        fprintf(stderr, "ERROR: Failed to filter unavailable PCR values for quote!\n");
        return -1;
    }

    // Read PCR values from the TPM because the quote doesn't have them!
    tool_rc rc = pcr_read_pcr_values(ectx, pcr_select, pcrs, NULL, TPM2_ALG_ERROR);
    if (rc != tool_rc_success) {
        fprintf(stderr, "ERROR: Failed to retrieve PCR values related to quote!\n");
        return -1;
    }

    return 0;
}

void pcr_print_(TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs){
    pcr_print_pcr_struct(pcr_select, pcrs);
}

int verify_pcrsdigests(TPM2B_DIGEST *quoteDigest, TPM2B_DIGEST *pcr_digest) {

    // Sanity check -- they should at least be same size!
    if (quoteDigest->size != pcr_digest->size) {
        fprintf(stderr, "ERROR: PCR values failed to match quote's digest!\n");
        return -1;
    }

    // Compare running digest with quote's digest
    int k;
    for (k = 0; k < quoteDigest->size; k++) {
        if (quoteDigest->buffer[k] != pcr_digest->buffer[k]) {

            return -2;
        }
    }

    return 0;
}


int verify_quote(tpm_challenge_reply *rply, char* ak_pub, agent_list *agent)
{
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    TPMS_ATTEST attest;
    TPM2B_DIGEST msg_hash =  TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPM2B_DIGEST pcr_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPML_PCR_SELECTION pcr_select;
    if( rply == NULL || ak_pub == NULL) return -1;

   // bio = BIO_new(, "rb");
    bio = BIO_new_mem_buf((void *) ak_pub, strlen(ak_pub));
    if (!bio) {
        fprintf(stderr, "ERROR: Failed to open AK public key file '%s': %s\n", ak_pub, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    //Load AK pub key from BIO
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "ERROR: Failed to convert public key from PEM\n");
        OPENSSL_free(bio);
        return -1;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx) {
        fprintf(stderr, "ERROR: EVP_PKEY_CTX_new failed\n");
        OPENSSL_free(bio);
        EVP_PKEY_free(pkey);
        return -1;
    }

    //Check if the key is a valid public key
    if(!EVP_PKEY_public_check(pkey_ctx)){
        fprintf(stderr, "ERROR: check key failed\n");
        goto err;
    }

    const EVP_MD *md = EVP_sha256();

    int rc = EVP_PKEY_verify_init(pkey_ctx);
    if (!rc) {
        fprintf(stderr, "ERROR: EVP_PKEY_verify_init failed \n");
        goto err;
    }

    rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, md);
    if (!rc) {
        fprintf(stderr, "ERROR: EVP_PKEY_CTX_set_signature_md failed \n");
        goto err;
    }

    //Convert from TPM2B to TPMS format to validate nonce and pcr digest
    tool_rc tmp_rc = files_tpm2b_attest_to_tpms_attest(rply->quoted, &attest);
    if (tmp_rc != tool_rc_success) {
        fprintf(stderr, "ERROR: files_tpm2b_attest_to_tpms_attest failed \n");
        goto err;
    }

    if(agent->pcr10_sha256 == NULL ){
        //Save resetCount
        agent->resetCount = attest.clockInfo.resetCount;
    } else if(agent->resetCount != attest.clockInfo.resetCount && rply->wholeLog == 1 ) {
        fprintf(stdin, "INFO: agent rebooted after last attestation\n");
        OPENSSL_free(bio);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pkey_ctx);
        return -2;
    }
    
    //Hash the quoted data
    rc = tpm2_openssl_hash_compute_data(TPM2_ALG_SHA256, rply->quoted->attestationData, rply->quoted->size, &msg_hash);
    if (!rc) {
        fprintf(stderr, "ERROR: Compute message hash failed!\n");
        goto err;
    }

    //1 verify OK 0 verify failed -rc other errors
    rc = EVP_PKEY_verify(pkey_ctx, rply->sig, rply->sig_size, msg_hash.buffer, msg_hash.size);
    if (rc != 1) {
        if (rc == 0) {
            fprintf(stderr, "ERROR: Quote signature verification failed\n");
        } else {
            fprintf(stderr, "ERROR: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
        goto err;
    }

    // Verify the nonce
    if (attest.extraData.size != NONCE_SIZE *sizeof(uint8_t) || 
        memcmp(attest.extraData.buffer, rply->nonce, attest.extraData.size) != 0) {
        fprintf(stderr, "ERROR: Error validating nonce\n");
        goto err;
    }

    // Define the pcr selection
    if (!pcr_parse_selections("sha1:10+sha256:all", &pcr_select, NULL)) {
        fprintf(stderr, "ERROR: pcr_parse_selections failed\n");
        goto err;
    } 

    //Create the pcr digest with the received pcrs
    if (!tpm2_openssl_hash_pcr_banks_le(TPM2_ALG_SHA256, &pcr_select, &rply->pcrs, &pcr_hash)) {
        fprintf(stderr, "ERROR: Failed to hash PCR values\n");
        goto err;
    }

    // Verify that the digest from quote matches PCR digest
    rc = verify_pcrsdigests(&attest.attested.quote.pcrDigest, &pcr_hash);
    if (rc == -1) {
        goto err;
    } else if (rc == -2) {
        //TODO fixed??
        fprintf(stdin, "INFO: PCR values failed to match quote's digest!, possible desynch\n");
        OPENSSL_free(bio);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pkey_ctx);
        return -2;
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


//Convert len byte from data to hex and put them in buff
void bin_2_hash(char *buff, BYTE *data, size_t len){
    size_t i;
    for (i = 0; i < len; i++) {
        //No need a terminating null byte, already from the last hex string
        buff += sprintf(buff, "%02x", data[i]); 
    }
}

/*  read one row of the IMA Log
    format of ima row
    pcr|template_hash|template_name_length|template_name|template_data_lenght|template_data
    template_data = hash_length|hash_name(null terminated string)|filedata_hash|filename_length|filename(null terminated string)
    template_hash = sha1(template_data) */
int read_ima_log_row(tpm_challenge_reply *rply, size_t *total_read, uint8_t * template_hash, uint8_t * template_hash_sha256, char * hash_name, char ** path_name, uint8_t *hash_name_byte){
    uint32_t pcr;
    uint32_t field_len;
	uint32_t field_path_len;
	uint8_t alg_field[8];
    uint8_t alg_sha1_field[6];
    uint8_t acc = 0;
    uint8_t *entry_aggregate;
    int sz;
    unsigned char *calculated_template_hash = NULL;

    memcpy(&pcr, rply ->ima_log, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);
    //printf("%d ", pcr);

    memcpy(template_hash, rply ->ima_log + *total_read, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
    *total_read += sizeof(uint8_t) * SHA_DIGEST_LENGTH;
    //tpm2_util_hexdump(template_hash, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
    //printf("\n");

    uint32_t template_name_len;
    memcpy(&template_name_len, rply ->ima_log + *total_read, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);
    //printf("%d ", template_name_len);

    char template_type[TCG_EVENT_NAME_LEN_MAX + 1];
    memcpy(template_type, rply ->ima_log + *total_read, template_name_len);
    *total_read += template_name_len * sizeof(char);
    //printf("%s ", template_type);
    

    uint32_t template_len;
    memcpy(&template_len, rply ->ima_log + *total_read, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);
    //printf("%d ", template_len);

    //Allocate a buffer for PCR extension verification
    entry_aggregate = calloc(template_len + 1, sizeof(uint8_t));
    
    memcpy(&field_len, rply ->ima_log + *total_read, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);
    
    memcpy(entry_aggregate + acc, &field_len, sizeof(uint32_t));
    acc += sizeof(uint32_t);


    //sha256 len = 0x28
    if(field_len != 0x28){
        //the next field must be "sha256:" 
        //so if it is "sha1:" means that there was an error during the IMA log creation => skip row
        //EX: 10 20..5c ima-ng sha256:a6..e6 /var/lib/logrotate/status
        //10 00..00 ima-ng sha1:00..00 /var/lib/logrotate/status
        memcpy(alg_sha1_field, rply ->ima_log + *total_read, 6*sizeof(uint8_t));
        *total_read += 6 * sizeof(uint8_t);
        memcpy(entry_aggregate + acc, alg_sha1_field, sizeof alg_sha1_field);
        acc += sizeof alg_sha1_field;
        
        *total_read += SHA_DIGEST_LENGTH * sizeof(uint8_t);

        //PCR10 extends FF not 00
        memset(template_hash, 0xff, SHA_DIGEST_LENGTH);
        memset(template_hash_sha256, 0xff, SHA256_DIGEST_LENGTH); 

        memcpy(&field_path_len, rply ->ima_log + *total_read, sizeof(uint32_t));
        *total_read += sizeof(uint32_t);
        *total_read += sizeof(char) * field_path_len;
        free(entry_aggregate);
        return 1;
    } 

    memcpy(alg_field, rply ->ima_log + *total_read, 8*sizeof(uint8_t));
    *total_read += 8 * sizeof(uint8_t);
    //printf("%s", alg_field);

    memcpy(entry_aggregate + acc, alg_field, sizeof alg_field);
    acc += 8*sizeof(uint8_t);

    memcpy(hash_name_byte, rply ->ima_log + *total_read, SHA256_DIGEST_LENGTH *sizeof(uint8_t));
    *total_read += SHA256_DIGEST_LENGTH * sizeof(uint8_t);
    bin_2_hash(hash_name, hash_name_byte, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);

    memcpy(entry_aggregate + acc, hash_name_byte, SHA256_DIGEST_LENGTH *sizeof(uint8_t));
    acc += SHA256_DIGEST_LENGTH *sizeof(uint8_t);

    memcpy(&field_path_len, rply ->ima_log + *total_read, sizeof(uint32_t));
    *total_read += sizeof(uint32_t);

    memcpy(entry_aggregate + acc, &field_path_len, sizeof(uint32_t));
    acc += sizeof(uint32_t);

    *path_name = malloc(sizeof(char) * field_path_len);

    memcpy(*path_name, rply ->ima_log + *total_read, sizeof(char) * field_path_len);
    *total_read += sizeof(char) * field_path_len;
    //printf("%ld %s\n",field_path_len, *path_name);

    memcpy(entry_aggregate + acc, *path_name, sizeof(uint8_t) * field_path_len);
    acc += sizeof(char) * field_path_len;

    calculated_template_hash = malloc(SHA_DIGEST_LENGTH *sizeof(unsigned char));
    
    if (digest_message(entry_aggregate, template_len, 1, calculated_template_hash, &sz) != 0){
        fprintf(stderr, "ERROR: Digest creation error\n");
        free(calculated_template_hash);
        free(entry_aggregate);
        return -1;
    }

    //tpm2_util_hexdump(template_hash, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
    //printf("\n");

    //Compare the read SHA1 template hash agaist his calculation
    if(memcmp(calculated_template_hash, template_hash,sizeof(uint8_t) *   SHA_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "ERROR: Mismatch template hash agaist calculated one\n");
        free(calculated_template_hash);
        free(entry_aggregate);
        return -1;
        //tpm2_util_hexdump((uint8_t*) calculated_template_hash, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
        //printf("\n");
        //tpm2_util_hexdump(template_hash, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
        //printf("\n\n\n");
    } 

    //tpm2_util_hexdump(template_hash, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
    //printf("\n");

    //Compute the template digest SHA256
    if (digest_message(entry_aggregate, template_len, 0, template_hash_sha256, &sz) != 0){
        fprintf(stderr, "ERROR: Digest creation error\n");
        free(calculated_template_hash);
        free(entry_aggregate);
        return -1;
    }

    free(calculated_template_hash);
    free(entry_aggregate);
    return 0;
}

int check_goldenvalue(sqlite3 *db, char * hash_name, char * path_name){
    sqlite3_stmt *res;
    char *sql = "SELECT * FROM golden_values WHERE name = @name and hash = @hash ";
    char *sql2 = "SELECT * FROM whitelist WHERE name = substr(@name, 1, length(name)) ";
    int idx, idx2;
    //char *err_msg = 0;
    int step;

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
    
    //Execute the sql query
    step = sqlite3_step(res);
    if (step == SQLITE_ROW) {
        //Golden value found, IMA row OK
        //printf("%s: ", sqlite3_column_text(res, 0));
        //printf("%s\n", sqlite3_column_text(res, 1));
        sqlite3_finalize(res);
        return 0;
        
    } 
    
    //IMA row not found in golden values db, try the whitelist database
    sqlite3_finalize(res);

    //convert the sql statament 
    rc = sqlite3_prepare_v2(db, sql2, -1, &res, 0);
    if (rc == SQLITE_OK) {
        //Set the parametrized input
        idx = sqlite3_bind_parameter_index(res, "@name");
        sqlite3_bind_text(res, idx, path_name, strlen(path_name), NULL);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }
    
    //Execute the sql query
    step = sqlite3_step(res);
    if (step == SQLITE_ROW) {
        //Path name found in the whitelist, IMA row OK
        sqlite3_finalize(res);
        return 0;
    } 
    sqlite3_finalize(res);

    //IMA row not found in the whitelist db 
    return -1;
}

int compute_pcr10(uint8_t * pcr10_sha1, uint8_t * pcr10_sha256, uint8_t * sha1_concatenated, 
            uint8_t * sha256_concatenated, uint8_t *template_hash, uint8_t *template_hash_sha256){
    int sz;
    //PCR concatenation
    //SHA256
    memcpy(sha256_concatenated, pcr10_sha256, SHA256_DIGEST_LENGTH *sizeof(uint8_t));
    memcpy(sha256_concatenated + (SHA256_DIGEST_LENGTH *sizeof(uint8_t)), template_hash_sha256, SHA256_DIGEST_LENGTH *sizeof(uint8_t));
   
    //SHA1
    memcpy(sha1_concatenated, pcr10_sha1, SHA_DIGEST_LENGTH *sizeof(uint8_t));
    memcpy(sha1_concatenated +(SHA_DIGEST_LENGTH *sizeof(uint8_t)), template_hash, SHA_DIGEST_LENGTH *sizeof(uint8_t));

    //digest
    //SHA256
    if (digest_message(sha256_concatenated, (SHA256_DIGEST_LENGTH *2 * sizeof(uint8_t)), 0, pcr10_sha256, &sz) != 0){
        fprintf(stderr, "ERROR: Digest creation error\n");
        return -1;
    }

    //SHA1
    if (digest_message(sha1_concatenated, (SHA_DIGEST_LENGTH *2 * sizeof(uint8_t)), 1, pcr10_sha1, &sz) != 0){
        fprintf(stderr, "ERROR: Digest creation error\n");
        return -1;
    }

    return 0;
}

int refresh_verifier_database_entry(agent_list *agent){
    sqlite3_stmt *res;
    sqlite3 *db;
    char *sql = "UPDATE agent SET pcr10_sha256 = NULL, pcr10_sha1 = NULL, timestamp = NULL, resetCount = NULL, byte_rcv = NULL WHERE id = @id ";
    //int idx;
    int step;
    
    int rc = sqlite3_open_v2(agent->gv_path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_URI, NULL);
   //int rc = sqlite3_open_v2(verifier_config->, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_URI, NULL);
    if ( rc != SQLITE_OK) {
        fprintf(stderr, "ERROR: Cannot open the verifier database, error %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    //convert the sql statament
    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        //Set the parametrized input
        //idx = sqlite3_bind_parameter_index(res, "@id");
        //sqlite3_bind_int(res, idx, agent->id);
    } else if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
        
    } 

    //Execute the sql query
    step = sqlite3_step(res);
    if (step == SQLITE_ROW) {
        //Golden value found, IMA row OK
        fprintf(stderr, "ERROR: error sql update\n");
        //printf("%s\n", sqlite3_column_text(res, 1));
        sqlite3_finalize(res);
        sqlite3_close(db);
        return -1;
        
    } 
    
    sqlite3_finalize(res);
    sqlite3_close(db);
    //printf("%d %s %s\n", agent->id, agent->pcr10_old_sha1, agent->pcr10_old_sha256);
    return 0;

}

int save_pcr10(agent_list *agent, char * db_path){
    sqlite3_stmt *res;
    sqlite3 *db;
    char *sql = "UPDATE attesters SET pcr10_sha256 = @sha256, pcr10_sha1 = @sha1, resetCount =@resetCount, byte_rcv =@bytercv WHERE uuid = @uuid ";
    int idx, idx2, idx3, idx4, idx5;
    int step;

    printf("Save PCR10 \n");
    int rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_URI, NULL);
    if ( rc != SQLITE_OK) {
        fprintf(stderr, "ERROR: Cannot open the agent  database, error %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    //convert the sql statament 
    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        //Set the parametrized input
        idx = sqlite3_bind_parameter_index(res, "@sha256");
        sqlite3_bind_text(res, idx, agent->pcr10_sha256, strlen(agent->pcr10_sha256), NULL);

        idx2 = sqlite3_bind_parameter_index(res, "@sha1");
        sqlite3_bind_text(res, idx2, agent->pcr10_sha1, strlen(agent->pcr10_sha1), NULL);

        idx3 = sqlite3_bind_parameter_index(res, "@uuid");
        sqlite3_bind_text(res, idx3, agent->uuid, -1, NULL);

        idx4 = sqlite3_bind_parameter_index(res, "@resetCount");
        sqlite3_bind_int(res, idx4, agent->resetCount);

        idx5 = sqlite3_bind_parameter_index(res, "@bytercv");
        sqlite3_bind_int(res, idx5, agent->byte_rcv);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    //Execute the sql query
    step = sqlite3_step(res);
    if (step == SQLITE_ROW) {
        fprintf(stderr, "ERROR: error sql insert pcr10\n");
        //printf("%s\n", sqlite3_column_text(res, 1));
        sqlite3_finalize(res);
        sqlite3_close(db);
        return -1;
        
    } 
    sqlite3_finalize(res);
    sqlite3_close(db);
    return 0;

}

int verify_ima_log(tpm_challenge_reply *rply, sqlite3 *db, agent_list *agent, char * db_path){
    
    char file_hash[(SHA256_DIGEST_LENGTH * 2) + 1];
    uint8_t template_hash[SHA_DIGEST_LENGTH];
    uint8_t template_hash_sha256[SHA256_DIGEST_LENGTH];
    char *event_name = calloc((TCG_EVENT_NAME_LEN_MAX + 1),  sizeof(char));
    uint8_t hash_name_byte[SHA256_DIGEST_LENGTH];
    char *path_name = NULL;
    int ret;
    size_t total_read = 0;
    uint32_t template_len;
    uint8_t * pcr10_sha1 = calloc(SHA_DIGEST_LENGTH, sizeof(uint8_t));
    uint8_t * pcr10_sha256 = calloc(SHA256_DIGEST_LENGTH, sizeof(uint8_t));
    uint8_t * sha1_concatenated = calloc(SHA_DIGEST_LENGTH * 2, sizeof(uint8_t));
    uint8_t * sha256_concatenated = calloc(SHA256_DIGEST_LENGTH * 2, sizeof(uint8_t));
    UINT16 sz = (UINT16) SHA256_DIGEST_LENGTH;
    UINT16 sz1 = (UINT16) SHA_DIGEST_LENGTH;

    if((rply->ima_log == NULL && rply->ima_log_size > 0) || (rply->ima_log_size < 0) || (db == NULL)){
        fprintf(stderr, "ERROR: verify_ima_log bad input\n");
        return -1;
    }

    if(agent->pcr10_sha256 != NULL && agent->pcr10_sha1 != NULL && !rply->wholeLog){
        //Old PCR 10 values to use, convert to byte
        tpm2_util_bin_from_hex_or_file(agent->pcr10_sha256, &sz, pcr10_sha256);
        tpm2_util_bin_from_hex_or_file(agent->pcr10_sha1, &sz1, pcr10_sha1);
        //tpm2_util_hexdump(pcr10_sha1, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
        //printf("\n");
    } else {
        if(agent->pcr10_sha256 == NULL){
            agent->pcr10_sha256 = calloc((SHA256_DIGEST_LENGTH * 2 + 1), sizeof(uint8_t));
            agent->pcr10_sha1 = calloc((SHA_DIGEST_LENGTH * 2 + 1), sizeof(uint8_t));
        }
        //No old PCR10 values, allocates space for saving them

    }

    /*No new event in the agent*/
    if(rply->ima_log_size == 0 && agent->pcr10_sha256 != NULL && agent->pcr10_sha1 != NULL){
        fprintf(stdout, "INFO: No IMA log received, compare the old PCR10 with received one:\n");
        goto PCR10;

    } else if (rply->ima_log_size == 0 && agent->pcr10_sha256 == NULL && agent->pcr10_sha1 == NULL) {
        fprintf(stderr, "ERROR: No IMA log received but no old PCR10 in the agent db error\n");
        goto error;
    }
    
    //verify the correct IMA log template 
    //ima_ng: PCR SHA1 TEMPLATE_NAME SHA256 HASH PATH_NAME
    total_read = sizeof(uint32_t) + SHA_DIGEST_LENGTH*sizeof(uint8_t);
    memcpy(&template_len, rply ->ima_log + total_read, sizeof(uint32_t));

    total_read += sizeof(uint32_t);
    memcpy(event_name, rply ->ima_log + total_read, template_len);
    total_read = 0;

    if(strcmp(event_name, "ima-ng") != 0){
        //printf("%s\n", event_name);
        fprintf(stderr, "ERROR: Unknown IMA template\n");
        return -1;
    }//other template here

    while(rply->ima_log_size != total_read){
        //Read a row from IMA log
        ret = read_ima_log_row(rply, &total_read, template_hash, template_hash_sha256, file_hash, &path_name, hash_name_byte);
        if (ret == 1){
            //Error in the IMA log so skip the golden value verification
            if(compute_pcr10(pcr10_sha1, pcr10_sha256, sha1_concatenated, sha256_concatenated, template_hash, template_hash_sha256) != 0){
                fprintf(stderr, "ERROR: pcr10 digest error\n");
                goto error;
            }
            continue;
        } else if(ret == -1){
            free(path_name);
            fprintf(stderr, "ERROR: Error during read_ima_log_row\n");
            goto error;
        }

        //verify that (name,hash) present in in golden values db
        if(check_goldenvalue(db, file_hash, path_name) != 0){
            printf("Event name: %s and hash value %s not found from golden values db!\n", path_name, file_hash);
            //free(path_name);
            //goto error;
        }
        free(path_name);

        //Compute PCR10
        if(compute_pcr10(pcr10_sha1, pcr10_sha256, sha1_concatenated, sha256_concatenated, template_hash, template_hash_sha256) != 0){
            fprintf(stderr, "ERROR: pcr10 digest error\n");
            free(path_name);
            goto error;
        }

    }

    fprintf(stdout, "INFO: IMA log verification OK\n");

    //pcrs.pcr_values[0].digests->size == 20 == sha1
    //pcrs.pcr_values[1].digests->size == 32 == sha256
    //digests[i] i = pcrid mod 8 => 10 mod 8 2
/*     printf("Compued pcrs10 OK\n");
    tpm2_util_hexdump(pcr10_sha256, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);
    printf("\n");
    tpm2_util_hexdump(pcr10_sha1, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
    printf("\n");

    printf("Computed pcrs10 OK\n");
    tpm2_util_hexdump(rply->pcrs.pcr_values[1].digests[3].buffer, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);
    printf("\n");
    tpm2_util_hexdump(rply->pcrs.pcr_values[0].digests[0].buffer, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
    printf("\n"); */

    //Compare PCR10 with the received one
PCR10:  if(memcmp(rply->pcrs.pcr_values[0].digests[0].buffer, pcr10_sha1, sizeof(uint8_t) * SHA_DIGEST_LENGTH) != 0 
            && memcmp(rply->pcrs.pcr_values[1].digests[3].buffer, pcr10_sha256, sizeof(uint8_t) * SHA256_DIGEST_LENGTH) != 0){
        
        printf("PCR10 calculation mismatch, PCRS10:\n");
        tpm2_util_hexdump(rply->pcrs.pcr_values[1].digests[3].buffer, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);
        printf("\n");
        tpm2_util_hexdump(pcr10_sha1, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
        printf("\n");  
        
        //refresh_verifier_database_entry
        refresh_verifier_database_entry(agent);
        goto unknown;
    }

    fprintf(stdout, "INFO: PCR10 calculation OK\n");

    //Convert PCR10 to save it
    bin_2_hash(agent->pcr10_sha1, pcr10_sha1, sizeof(uint8_t) * SHA_DIGEST_LENGTH);
    bin_2_hash(agent->pcr10_sha256, pcr10_sha256, sizeof(uint8_t) * SHA256_DIGEST_LENGTH);

    //Update the number of recievd bytes
    agent->byte_rcv += rply->ima_log_size;
    //Store the PCRs10 for future incremental IMA log
    ret = save_pcr10(agent, db_path);
    if(ret == -1)
        goto error;

    free(pcr10_sha1);
    free(pcr10_sha256);
    free(sha1_concatenated);
    free(sha256_concatenated);
    free(event_name);
    return 0;
error:
    free(pcr10_sha1);
    free(pcr10_sha256);
    free(sha1_concatenated);
    free(sha256_concatenated);
    free(event_name);
    return -1;
unknown:
    free(pcr10_sha1);
    free(pcr10_sha256);
    free(sha1_concatenated);
    free(sha256_concatenated);
    free(event_name);
    return -2;
}

int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    if(argv[0] > 0)
        return 0;
    else
        return 1;
}

tool_rc tpm2_quote_free(void) {

    free(signature);

    //Close authorization sessions
    tool_rc rc = tpm2_session_close(&key.object.session);

    return rc;
}

void free_data (tpm_challenge_reply *rply){
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
        fprintf(stderr, "ERROR: tpm2_convert_sig error\n");
        return NULL;
    }
    return sig;
}