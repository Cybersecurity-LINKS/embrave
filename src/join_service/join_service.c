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

static struct ak_db_entry {
    unsigned char ak_pem[1024];
    unsigned char ak_name[1024];
    int validity;
};

static struct join_service_conf js_config;

static struct ak_db_entry *retrieve_ak(unsigned char *ak){
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

    char *sql = "SELECT * FROM attesters_credentials WHERE ak = ?";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, ak, -1, NULL);
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
        strcpy(ak_entry->ak_pem, sqlite3_column_text(res, 0));
        strcpy(ak_entry->ak_name, sqlite3_column_text(res, 1));
        ak_entry->validity = atoi(sqlite3_column_text(res, 2));
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

static insert_ak(unsigned char *ak){
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    char *sql = "INSERT INTO attesters_credentials values (?, 1);";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, ak, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
    } else {
        fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }
        
    int step = sqlite3_step(res);
    
    if (step == SQLITE_DONE) {
        fprintf(stdout, "INFO: AK succesfully inserted into the db\n");
    }
    else {
        fprintf(stderr, "ERROR: could not insert AK into the db\n");
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return 0;
}

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_http_match_uri(hm, API_JOIN) && !strncmp(hm->method.ptr, POST, hm->method.len)) {
        
        //#ifdef DEBUG
            printf("%.*s\n", (int) hm->message.len, hm->message.ptr);
        //#endif

            /* Read post */
            /*
                {
                    "ek_cert_b64": "aaaaaaaaa",
                    "ak_pub_b64": "aaaaaaaa",
                    "ak_name_b64": "aaaaaaaa"
                }
            */
            unsigned char* ek_cert_b64 = mg_json_get_str(hm->body, "$.ek_cert_b64");
            unsigned char* ak_pub_b64 = mg_json_get_str(hm->body, "$.ak_pub_b64");
            unsigned char* ak_name_b64 = mg_json_get_str(hm->body, "$.ak_name_b64");
            struct ak_db_entry *ak_entry;
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

        #ifdef DEBUG
            printf("EK_CERT: %s\n", ek_cert_b64);
            printf("AK_PUB: %s\n", ak_pub_b64);
        #endif

            ak_entry = retrieve_ak(ak_pub_b64);
            if(ak_entry == NULL) {
                //Malloc buffer
                unsigned char *ek_cert_buff = (unsigned char *) malloc(ek_cert_len + 1);
                if(ek_cert_buff == NULL) {
                    free(ek_cert_b64);
                    free(ak_pub_b64);
                    free(ak_name_b64);
                    mg_http_reply(c, 500, NULL, "\n");
                    return;
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

                //Decode b64
                if(mg_base64_decode(ek_cert_b64, strlen(ek_cert_b64), ek_cert_buff) == 0){
                    fprintf(stderr, "ERROR: Transmission challenge data error.\n");
                    free(ek_cert_buff);
                    free(ek_cert_b64);
                    free(ak_pub_b64);
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

                mg_http_reply(c, OK, APPLICATION_JSON,
                    "{\"mkcred_out\":\"%s\"}\n", mkcred_out_b64);
                MG_INFO(("%s %s %d", POST, API_JOIN, OK));

                free(ak_name_buff);
                free(ek_cert_buff);
            }
            else {
            #ifdef DEBUG
                printf("AK: %s", ak_entry->ak_pem);
                printf("Validity: %d\n", ak_entry->validity);
            #endif
                if(ak_entry->validity == VALID) {
                    printf("INFO: AK is valid\n");
                    mg_http_reply(c, OK, APPLICATION_JSON,
                        "{\"message\":\"ak already registered and valid\"}\n");
                    MG_INFO(("%s %s %d", POST, API_JOIN, OK));
                }
                else {
                    printf("INFO: AK is NOT valid (revoked)\n");
                }
            }

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
*/
static init_database(void){
    sqlite3_stmt *res= NULL;
    sqlite3 *db = NULL;
    int byte;
    char *sql1 = "CREATE TABLE IF NOT EXISTS attesters_credentials (ak text NOT NULL, validity INT NOT NULL, PRIMARY KEY (ak));";
    //char *sql2 = "CREATE TABLE IF NOT EXISTS revoked (ak text NOT NULL, PRIMARY KEY (ak)); ";
    int step, idx;

    printf("%s\n", js_config.db);
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    if ( rc != SQLITE_OK) {
        printf("Cannot open or create the join service database, error %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    //convert the sql statament 
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
    if((c = mg_http_listen(&mgr, url, fn, &mgr)) == NULL){  // Setup listener
        MG_ERROR(("Cannot listen on http://%s:%d", js_config.ip, js_config.port));
        exit(EXIT_FAILURE);
    }

    MG_INFO(("Listening on http://%s:%d", js_config.ip, js_config.port));

    for (;;) mg_mgr_poll(&mgr, 1000);                         // Event loop
    mg_mgr_free(&mgr);                                        // Cleanup
    return 0;
}