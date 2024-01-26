// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "join_service.h"
#include "config_parse.h"
#include "x509.h"
#include "common.h"
#include "tpm_makecredential.h"

#define VALID 1
#define REVOKED 0

static char* secret = "12345678";

struct ek_db_entry {
    char uuid[1024];
    unsigned char ek_cert[4096];
};

struct ak_db_entry {
    char uuid[1024];
    unsigned char ak_pem[1024];
    int confirmed;
    int validity;
};

static struct join_service_conf js_config;

/* responsibility of the caller to free the ak_db_entry */
static struct ak_db_entry *retrieve_ak(char *uuid, unsigned char *ak){
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;
    struct ak_db_entry *ak_entry = NULL;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    char *sql = "SELECT * FROM attesters_credentials WHERE uuid = ? AND ak_pub = ?";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, uuid, -1, NULL);
        if (rc != SQLITE_OK ) {
            return NULL;
        }
        rc = sqlite3_bind_text(res, 2, ak, -1, NULL);
        if (rc != SQLITE_OK ) {
            return NULL;
        }
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }
        
    int step = sqlite3_step(res);
    
    if (step == SQLITE_ROW) {
        ak_entry = (struct ak_db_entry *) malloc(sizeof(struct ak_db_entry));
        if(ak_entry == NULL) {
            fprintf(stderr, "ERROR: could not allocate ak_db_struct\n");
            return NULL;
        }
        strcpy(ak_entry->uuid, sqlite3_column_text(res, 0));
        strcpy(ak_entry->ak_pem, sqlite3_column_text(res, 1));
        ak_entry->validity = atoi(sqlite3_column_text(res, 2));
        ak_entry->confirmed = atoi(sqlite3_column_text(res, 3));
    #ifdef DEBUG
        printf("%s: ", sqlite3_column_text(res, 0));
        printf("%s\n", sqlite3_column_text(res, 1));
    #endif
        fprintf(stdout, "INFO: AK already present in the db\n");
    }
    else {
        fprintf(stdout, "INFO: no entry in the db with the specified AK\n");
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return ak_entry;
}

static int set_ak_confirmed(unsigned char *ak, char *uuid){
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    char *sql = "UPDATE attesters_credentials SET confirmed = 1 WHERE ak_pub = ? AND uuid = ?;";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, ak, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
        rc = sqlite3_bind_text(res, 2, uuid, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
    } else {
        fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }
        
    int step = sqlite3_step(res);
    
    if (step == SQLITE_DONE && sqlite3_changes(db) == 1) {
        fprintf(stdout, "INFO: AK succesfully updated\n");
    }
    else {
        fprintf(stderr, "ERROR: could not update AK\n");
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return 0;
}

static int set_ak_valid(unsigned char *ak, char *uuid){
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    char *sql = "UPDATE attesters_credentials SET validity = 1 WHERE ak_pub = ? AND uuid = ?;";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, ak, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
        rc = sqlite3_bind_text(res, 2, uuid, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
    } else {
        fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }
        
    int step = sqlite3_step(res);
    
    if (step == SQLITE_DONE && sqlite3_changes(db) == 1) {
        fprintf(stdout, "INFO: AK succesfully updated (validity = 1)\n");
    }
    else {
        fprintf(stderr, "ERROR: could not update AK\n");
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return 0;
}

/* responsibility of the caller to free the ek_db_entry */
static struct ek_db_entry *retrieve_ek(char *uuid){
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;
    struct ek_db_entry *ek_entry = NULL;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    char *sql = "SELECT * FROM attesters_ek_certs WHERE uuid = ?;";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, uuid, -1, NULL);
        if (rc != SQLITE_OK ) {
            return NULL;
        }
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }
        
    int step = sqlite3_step(res);
    
    if (step == SQLITE_ROW) {
        ek_entry = (struct ek_db_entry *) malloc(sizeof(struct ek_db_entry));
        if(ek_entry == NULL) {
            fprintf(stderr, "ERROR: could not allocate ek_db_struct\n");
            return NULL;
        }
        strcpy(ek_entry->uuid, sqlite3_column_text(res, 0));
        strcpy(ek_entry->ek_cert, sqlite3_column_text(res, 1));
    #ifdef DEBUG
        printf("%s: ", sqlite3_column_text(res, 0));
        printf("%s\n", sqlite3_column_text(res, 1));
    #endif
        fprintf(stdout, "INFO: EK already present in the db\n");
    }
    else {
        fprintf(stdout, "INFO: no entry in the db with the specified UUID\n");
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return ek_entry;
}

static int insert_ak(struct ak_db_entry *ak_entry){
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    char *sql = "INSERT INTO attesters_credentials values (?, ?, ?, ?);";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, ak_entry->uuid, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
        rc = sqlite3_bind_text(res, 2, ak_entry->ak_pem, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
        rc = sqlite3_bind_int(res, 3, ak_entry->validity);
        if (rc != SQLITE_OK ) {
            return -1;
        }
        rc = sqlite3_bind_int(res, 4, ak_entry->confirmed);
        if (rc != SQLITE_OK ) {
            return -1;
        }
    } else {
        fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    int step = sqlite3_step(res);
    
    if (step == SQLITE_DONE && sqlite3_changes(db) == 1) {
        fprintf(stdout, "INFO: AK succesfully inserted into the db\n");
    }
    else {
        fprintf(stderr, "ERROR: could not insert AK into the db\n");
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return 0;
}

static int insert_ek(struct ek_db_entry *ek_entry){
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    char *sql = "INSERT INTO attesters_ek_certs values (?, ?);";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, ek_entry->uuid, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
        rc = sqlite3_bind_text(res, 2, ek_entry->ek_cert, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
    } else {
        fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }
        
    int step = sqlite3_step(res);
    
    if (step == SQLITE_DONE && sqlite3_changes(db) == 1){
        fprintf(stdout, "INFO: EK succesfully inserted into the db\n");
    }
    else {
        fprintf(stderr, "ERROR: could not insert AK into the db\n");
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return 0;
}

static void join_service_manager(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_http_match_uri(hm, API_JOIN) && !strncmp(hm->method.ptr, POST, hm->method.len)) {
        
        //#ifdef DEBUG
            printf("%.*s\n", (int) hm->message.len, hm->message.ptr);
        //#endif

            /* Read post */
            /*
                {
                    "uuid": "aaaaaaaaa",
                    "ek_cert_b64": "aaaaaaaaa",
                    "ak_pub_b64": "aaaaaaaa",
                    "ak_name_b64": "aaaaaaaa"
                }
            */
            unsigned char* uuid = mg_json_get_str(hm->body, "$.uuid");
            unsigned char* ek_cert_b64 = mg_json_get_str(hm->body, "$.ek_cert_b64");
            unsigned char* ak_pub_b64 = mg_json_get_str(hm->body, "$.ak_pub_b64");
            unsigned char* ak_name_b64 = mg_json_get_str(hm->body, "$.ak_name_b64");
            struct ek_db_entry *ek_entry;
            size_t ek_cert_len = B64DECODE_OUT_SAFESIZE(strlen(ek_cert_b64));
            size_t ak_name_len = B64DECODE_OUT_SAFESIZE(strlen(ak_name_b64));

            /* Calculate the actual length removing base64 padding ('=') */
            for(int i=0; i<strlen(ek_cert_b64); i++){
                if(ek_cert_b64[i] == '='){
                    ek_cert_len--;
                }
            }

            /* Calculate the actual length removing base64 padding ('=') */
            for(int i=0; i<strlen(ak_name_b64); i++){
                if(ak_name_b64[i] == '='){
                    ak_name_len--;
                }
            }

            printf("EK_BASE64_LEN: %d\n", strlen(ek_cert_b64));

            unsigned char *ek_cert_buff = (unsigned char *) malloc(ek_cert_len + 1);

        #ifdef DEBUG
            printf("EK_CERT: %s\n", ek_cert_b64);
            printf("AK_PUB: %s\n", ak_pub_b64);
        #endif

            ek_entry = retrieve_ek(uuid);
            if(ek_entry == NULL) {
                //Malloc buffer
                if(ek_cert_buff == NULL) {
                    free(ek_cert_b64);
                    free(ak_pub_b64);
                    free(ak_name_b64);
                    mg_http_reply(c, 500, NULL, "\n");
                    return;
                }

                //Decode b64
                if(mg_base64_decode(ek_cert_b64, strlen(ek_cert_b64), ek_cert_buff) == 0){
                    fprintf(stderr, "ERROR: Transmission challenge data error.\n");
                    free(ek_cert_buff);
                    free(ek_cert_b64);
                    free(ak_pub_b64);
                    mg_http_reply(c, 500, NULL, "\n");
                    return;
                }

                /* Verify the X509 certificate of the EK */
                if(verify_x509_cert(ek_cert_buff, ek_cert_len)){
                    mg_http_reply(c, OK, APPLICATION_JSON,
                        "{\"error\":\"ek certificate verification failed\"}\n");
                    MG_INFO(("%s %s %d", POST, API_JOIN, OK));

                    free(ek_cert_buff);
                    free(ek_cert_b64);
                    free(ak_pub_b64);
                    return;
                }
                else {
                    fprintf(stdout, "INFO: EK certificate verified successfully\n");

                    struct ek_db_entry ek;
                    strcpy(ek.ek_cert, ek_cert_b64);
                    strcpy(ek.uuid, uuid);

                    insert_ek(&ek);
                }

            #ifdef DEBUG
                /* FOR DEBUG */
                printf("AK_NAME_LEN: %d\n", ak_name_len);
                printf("AK_NAME: ");
                for(int k=0; k<ak_name_len; k++){
                    printf("%02x", ak_name_buff[k]);
                }
                printf("\n");
            #endif
            }
            else {
            #ifdef DEBUG
                printf("AK: %s", ak_entry->ak_pem);
                printf("Validity: %d\n", ak_entry->validity);
            #endif

                
            }

            unsigned char *ak_name_buff = (unsigned char *) malloc(ak_name_len + 1);
            if(ak_name_buff == NULL) {
                free(ek_cert_b64);
                free(ak_pub_b64);
                free(ak_name_b64);
                free(ek_cert_buff);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            if(mg_base64_decode(ak_name_b64, strlen(ak_name_b64), ak_name_buff) == 0){
                fprintf(stderr, "ERROR: Transmission challenge data error.\n");
                free(ek_cert_buff);
                free(ek_cert_b64);
                free(ak_pub_b64);
                free(ak_name_b64);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            struct ak_db_entry *ak_entry = retrieve_ak(uuid, ak_pub_b64);
            if (ak_entry == NULL) {
                fprintf(stdout, "INFO: AK not present in the db\n");
            }
            else {
                fprintf(stdout, "INFO: AK already present in the db\n");

                if(ak_entry->validity == VALID) {
                    printf("INFO: AK is valid\n");
                    mg_http_reply(c, OK, APPLICATION_JSON,
                        "{\"message\":\"ak already registered and valid\"}\n");
                    MG_INFO(("%s %s %d", POST, API_JOIN, OK));
                    return;
                }
                else {
                    printf("INFO: AK is NOT valid (revoked)\n");
                    mg_http_reply(c, FORBIDDEN, APPLICATION_JSON,
                        "{\"message\":\"ak is revoked\"}\n");
                    MG_INFO(("%s %s %d", POST, API_JOIN, FORBIDDEN));
                    return;
                }
            }

            /* tpm2_makecredential */
            unsigned char *out_buf;
            size_t out_buf_size;
            if(tpm_makecredential(ek_cert_buff, ek_cert_len, secret, ak_name_buff, ak_name_len, &out_buf, &out_buf_size)){
                fprintf(stderr, "ERROR: tpm_makecredential failed\n");
            }

            printf("OUT_BUF: ");
            for(int i=0; i<out_buf_size; i++){
                printf("%02x", out_buf[i]);
            }
            printf("\n");

            //insert_ak(ak_pub_b64);
            char *mkcred_out_b64;
            size_t mkcred_out_b64_len = B64ENCODE_OUT_SAFESIZE(out_buf_size);

            mkcred_out_b64 = (char *) malloc(mkcred_out_b64_len + 1);
            if(mkcred_out_b64 == NULL) {
                free(ek_cert_buff);
                free(ek_cert_b64);
                free(ak_pub_b64);
                free(ak_name_b64);
                free(ak_name_buff);
                free(out_buf);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            if(mg_base64_encode(out_buf, out_buf_size, mkcred_out_b64) == 0){
                fprintf(stderr, "ERROR: could not encode mkcred out buf.\n");
                free(ek_cert_buff);
                free(ek_cert_b64);
                free(ak_pub_b64);
                free(ak_name_b64);
                free(ak_name_buff);
                free(out_buf);
                free(mkcred_out_b64);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            struct ak_db_entry ak;
            strcpy(ak.ak_pem, ak_pub_b64);
            strcpy(ak.uuid, uuid);
            ak.confirmed = 0;
            ak.validity = 0;

            insert_ak(&ak);

            mg_http_reply(c, OK, APPLICATION_JSON,
                "{\"mkcred_out\":\"%s\"}\n", mkcred_out_b64);
            MG_INFO(("%s %s %d", POST, API_JOIN, OK));

            free(ak_name_buff);
            free(ek_cert_buff);
            free(uuid);
            free(ak_entry);
            free(ek_cert_b64);
            free(ak_pub_b64);

            /* Check if AK already present in the database or in the revoked db */

            /* if present send OK */

            /* if not present => challenge */

            /* mg_http_reply(c, OK, APPLICATION_JSON,
                        "OK\n");
            MG_INFO(("%s %s %d", POST, API_JOIN, OK)); */
        }
        else if (mg_http_match_uri(hm, API_CONFIRM_CREDENTIAL) && !strncmp(hm->method.ptr, POST, hm->method.len)) {
            
            /* receive and verify the value calculated by the attester with tpm_activatecredential */
            unsigned char* secret_b64 = mg_json_get_str(hm->body, "$.secret_b64");
            unsigned char* uuid = mg_json_get_str(hm->body, "$.uuid");
            unsigned char* ak_pub = mg_json_get_str(hm->body, "$.ak_pub_b64");
            size_t secret_len = B64DECODE_OUT_SAFESIZE(strlen(secret_b64));

            /* Calculate the actual length removing base64 padding ('=') */
            for(int i=0; i<strlen(secret_b64); i++){
                if(secret_b64[i] == '='){
                    secret_len--;
                }
            }

            unsigned char *secret_buff = (unsigned char *) malloc(secret_len + 1);
            if(secret_buff == NULL) {
                free(secret_b64);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            /* Decode b64 */
            if(!mg_base64_decode(secret_b64, strlen(secret_b64), secret_buff)){
                fprintf(stderr, "ERROR: Transmission challenge data error.\n");
                free(secret_buff);
                free(secret_b64);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }
            secret_buff[secret_len] = '\0';
            fprintf(stdout, "INFO: secret received: %s\n", secret_buff);

            /* verify the correctness of the secret_buff received */
            if(!strcmp(secret_buff, secret)){
                fprintf(stdout, "INFO: secret verified succesfully\n");
            }
            else {
                fprintf(stdout, "INFO: secret does not match\n");
                free(secret_buff);
                free(secret_b64);
                mg_http_reply(c, OK, NULL, "\n");
                return;
            }

            /* Set the AK in the database as confirmed (=1) */
            set_ak_confirmed(ak_pub, uuid);

            /* Set the AK in the database as valid (=1) */
            set_ak_valid(ak_pub, uuid);

            free(secret_buff);
            free(secret_b64);
            free(uuid);
            free(ak_pub);

            /* notify verifiers */

            mg_http_reply(c, OK, APPLICATION_JSON,
                        "OK\n");
            MG_INFO(("%s %s %d", POST, API_JOIN, OK));


        }
        else {
            mg_http_reply(c, 500, NULL, "\n");
        }
    }
}

/*Create db connection and, if not presents, create the keys databases
    ret:
    -1 error
    0 OK
    -------------
    attester_credentials
    ----------------------------------------
    | uuid | ak_pub | validity | confirmed |
    ----------------------------------------

    -------------
    attester_ek_certs
    ------------------
    | uuid | ek_cert |
    ------------------
*/
static int init_database(void){
    sqlite3_stmt *res= NULL;
    sqlite3 *db = NULL;
    int byte;
    char *sql2 = "CREATE TABLE IF NOT EXISTS attesters_credentials (\
        uuid text NOT NULL,\
        ak_pub text NOT NULL,\
        validity INT NOT NULL,\
        confirmed INT NOT NULL,\
        PRIMARY KEY (uuid, ak_pub)\
        FOREIGN KEY (uuid) REFERENCES attesters_ek_certs\
    );";
    char *sql1 = "CREATE TABLE IF NOT EXISTS attesters_ek_certs (\
        uuid text NOT NULL,\
        ek_cert text NOT NULL,\
        PRIMARY KEY (uuid)\
    );";
    //char *sql2 = "CREATE TABLE IF NOT EXISTS revoked (ak text NOT NULL, PRIMARY KEY (ak)); ";
    int step, idx;

    printf("%s\n", js_config.db);
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    if ( rc != SQLITE_OK) {
        printf("Cannot open or create the join service database, error %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    //attesters_credentials table
    rc = sqlite3_prepare_v2(db, sql1, -1, &res, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    rc = sqlite3_exec(db, sql1, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    //attesters_ek_certs table
    rc = sqlite3_prepare_v2(db, sql2, -1, &res, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    rc = sqlite3_exec(db, sql2, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    /* rc = sqlite3_exec(db, sql2, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    */
    sqlite3_close(db);
    return 0;
}

int main(int argc, char *argv[]) {
    struct mg_mgr mgr;
    struct mg_connection *c;
    mg_mgr_init(&mgr);
    char url[MAX_BUF];

    struct stat st = {0};
    if (stat("/var/lemon", &st) == -1) {
        if(!mkdir("/var/lemon", 0711)) {
            fprintf(stdout, "INFO: /var/lemon directory successfully created\n");
        }
        else {
            fprintf(stderr, "ERROR: cannot create /var/lemon directory\n");
        }
    }
    if (stat("/var/lemon/join_service", &st) == -1) {
        if(!mkdir("/var/lemon/join_service", 0711)) {
            fprintf(stdout, "INFO: /var/lemon/join_service directory successfully created\n");
        }
        else {
            fprintf(stderr, "ERROR: cannot create /var/lemon/join_service directory\n");
        }
    }

    /* read configuration from cong file */
    if(read_config(/* join_service */ 2, (void * ) &js_config)){
        int err = errno;
        fprintf(stderr, "ERROR: could not read configuration file\n");
        exit(err);
    }

    /* init database */
    if(init_database()){
        fprintf(stderr, "ERROR: could not init the db\n");
        exit(-1);
    }

    #ifdef DEBUG
    printf("join_service_config->ip: %s\n", js_config.ip);
    printf("join_service_config->port: %d\n", js_config.port);
    printf("join_service_config->tls_port: %d\n", js_config.tls_port);
    printf("join_service_config->tls_cert: %s\n", js_config.tls_cert);
    printf("join_service_config->tls_key: %s\n", js_config.tls_key);
    printf("join_service_config->db: %s\n", js_config.db);
    #endif

    snprintf(url, 1024, "http://%s:%d", js_config.ip, js_config.port);
                                          // Init manager
    if((c = mg_http_listen(&mgr, url, join_service_manager, &mgr)) == NULL){  // Setup listener
        MG_ERROR(("Cannot listen on http://%s:%d", js_config.ip, js_config.port));
        exit(EXIT_FAILURE);
    }

    MG_INFO(("Listening on http://%s:%d", js_config.ip, js_config.port));

    for (;;) mg_mgr_poll(&mgr, 1000);                         // Event loop
    mg_mgr_free(&mgr);                                        // Cleanup
    return 0;
}