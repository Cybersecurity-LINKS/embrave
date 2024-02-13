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
#include "mqtt_client.h"

#define VALID 1
#define REVOKED 0

static unsigned char secret [B64ENCODE_OUT_SAFESIZE(SECRET_SIZE)];
static int verifier_num = 0;
static int last_requested_verifier = 0;
static struct join_service_conf js_config;
struct mg_connection *c_mqtt;
struct mg_mgr mgr_mqtt;

static const uint64_t s_timeout_ms = 1500;  // Connect timeout in milliseconds

struct ek_db_entry {
    char uuid[1024];
    unsigned char ek_cert[4096];
};

struct ak_db_entry {
    char uuid[1024];
    char ip[100];
    unsigned char ak_pem[1024];
    int confirmed;
    int validity;
    bool Continue;
};

int notify_verifier(int id, struct ak_db_entry * ak_entry);
int get_verifier_id(void);
int get_verifier_ip(int id, char * ip);

pthread_mutex_t mutex;
pthread_cond_t cond;
int stop_event = 0;
static int stop_polling = 1;

struct queue_entry {
  char uuid[128];
  struct queue_entry *next;
  struct queue_entry *previous;
};

/* FIFO queue */
struct queue_entry *head = NULL;
struct queue_entry *tail = NULL;

int is_empty(struct queue_entry *head){
  if(head == NULL)
    return 1;

  return 0;
}

void push_uuid(char *uuid){
  struct queue_entry *entry;
  struct queue_entry *tmp;

  entry = malloc(sizeof(struct queue_entry));
  if(entry == NULL){
    fprintf(stderr, "ERROR: could not allocate memory for queue entry\n");
    return;
  }

  strcpy(entry->uuid, uuid);

  /* first element */
  if(head == NULL){
    head = entry;
    tail = entry;
    entry->next = NULL;
    entry->previous = NULL;
    return;
  }

  tmp = head;
  head = entry;
  entry->next = tmp;
  entry->previous = NULL;
  tmp->previous = entry;
}

int pop_uuid(char *uuid){
  if(uuid == NULL){
    fprintf(stderr, "ERROR: uuid output buffer is NULL\n");
    return 1;
  }

  if(tail == NULL){
    fprintf(stdout, "INFO: could not pop from queue because it is empty\n");
    return 1;
  }

  struct queue_entry *tmp;

  strcpy(uuid, tail->uuid);

  tmp = tail;
  if(tmp->previous == NULL){
    head = NULL;
    tail = NULL;
    goto out;
  }
  tail = tail->previous;

out:
  free(tmp);
  return 0;
}

/* responsibility of the caller to free the ak_db_entry */
static struct ak_db_entry *retrieve_ak(char *uuid, unsigned char *ak){
    sqlite3 *db;
    sqlite3_stmt *res;
    struct ak_db_entry *ak_entry = NULL;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    char *sql = ak == NULL ? "SELECT * FROM attesters_credentials WHERE uuid = ?" : "SELECT * FROM attesters_credentials WHERE uuid = ? AND ak_pub = ?";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, uuid, -1, NULL);
        if (rc != SQLITE_OK ) {
            return NULL;
        }
        if(ak != NULL){
            rc = sqlite3_bind_text(res, 2, (char *) ak, -1, NULL);
            if (rc != SQLITE_OK ) {
                return NULL;
            }
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
        strcpy(ak_entry->uuid, (char *) sqlite3_column_text(res, 0));
        strcpy((char *) ak_entry->ak_pem, (char *) sqlite3_column_text(res, 1));
        strcpy(ak_entry->ip, (char *) sqlite3_column_text(res, 2));
        ak_entry->validity = atoi((char *) sqlite3_column_text(res, 3));
        ak_entry->confirmed = atoi((char *) sqlite3_column_text(res, 4));
    #ifdef DEBUG
        printf("%s: ", sqlite3_column_text(res, 0));
        printf("%s\n", sqlite3_column_text(res, 1));
    #endif
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return ak_entry;
}

void single_attestation(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_OPEN) {
        // Connection created. Store connect expiration time in c->data
        *(uint64_t *) c->data = mg_millis() + s_timeout_ms;
    } else if (ev == MG_EV_POLL) {
        if (mg_millis() > *(uint64_t *) c->data &&
            (c->is_connecting || c->is_resolving)) {
        mg_error(c, "Connect timeout");
        }
    } else if (ev == MG_EV_CONNECT) {
        struct ak_db_entry *ak_entry = (struct ak_db_entry *) c->fn_data;
        size_t object_length = 0;
        char object[4096];

        fprintf(stdout, "INFO: %s\n %s\n", ak_entry->uuid, ak_entry->ak_pem);

        object_length = snprintf(object, 4096, "{\"uuid\":\"%s\",\"ak_pem\":\"%s\",\"ip_addr\":\"%s\"}", ak_entry->uuid, ak_entry->ak_pem, ak_entry->ip);

        /* Send request */
        mg_printf(c,
        "POST /request_attestation HTTP/1.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %ld\r\n"
        "\r\n"
        "%s\n",
        object_length,
        object);

    } else if (ev == MG_EV_HTTP_MSG) {
        const struct mg_http_message *hm = (const struct mg_http_message *) ev_data;
        int status = mg_http_status(hm);
        if (status == 200) {
            MG_INFO(("200 OK"));
            stop_polling = 0;
        } else {
            MG_ERROR(("HTTP ERROR: %d", status));
            stop_polling = 0;
        }
    } else if (ev == MG_EV_CLOSE) {
        MG_INFO(("Connection closed"));
        stop_polling = 0;
    }
}

void *queue_manager(void *vargp){
    struct mg_mgr mgr;
    struct mg_connection *c;
    char s_conn[280];

    mg_mgr_init(&mgr);

    printf("INFO: queue manager started\n");
    fflush(stdout);
    while(!stop_event){
        pthread_mutex_lock(&mutex);
        while (is_empty(head)) {
            pthread_cond_wait(&cond, &mutex);
            // Equivalent to:
            // pthread_mutex_unlock(&mutex);
            // wait for signal on condFuel
            // pthread_mutex_lock(&mutex);
        }
        // consume queue
        char uuid[128];

        if(pop_uuid(uuid) != 0)
            continue;

        pthread_mutex_unlock(&mutex);

        printf("INFO: popped uuid: %s\n", uuid);
        fflush(stdout);

        /*Uuid and AK pem and ip address*/
        struct ak_db_entry *ak_entry = retrieve_ak(uuid, NULL);
        int id = get_verifier_id();
        /* if(id == -1){
            fprintf(stderr, "ERROR: could not get verifier id\n");
            continue;
        } */
        
        //get_verifier_ip(id, ip);
        char topic[25];
        sprintf(topic, "attest/%d", id);
        char object[4096];

        fprintf(stdout, "INFO: %s\n %s\n", ak_entry->uuid, ak_entry->ak_pem);

        size_t object_length = snprintf(object, 4096, "{\"uuid\":\"%s\",\"ak_pem\":\"%s\",\"ip_addr\":\"%s\"}", ak_entry->uuid, ak_entry->ak_pem, ak_entry->ip);

        mqtt_publish(c_mqtt, topic, object);

        /* snprintf(s_conn, 280, "http://%s", ip);

        c = mg_http_connect(&mgr, s_conn, single_attestation, (void *) ak_entry);
        if (c == NULL) {
            MG_ERROR(("CLIENT cant' open a connection"));
            continue;
        }
        while (stop_polling) mg_mgr_poll(&mgr, 10); //10ms */
    }
    //pthread_mutex_unlock(&mutex);

    printf("INFO: queue manager ended\n");
    fflush(stdout);
    return NULL;
}

int create_secret(unsigned char * secret)
{
    unsigned char data[SECRET_SIZE];
    
    if(secret == NULL){
        fprintf(stderr, "ERROR: secret buffer is NULL\n");
        return -1;
    }

    /* RAND_priv_bytes() has the same semantics as RAND_bytes().
    *  It is intended to be used for generating values that should remain private
    */

    if (!RAND_priv_bytes(data, SECRET_SIZE)){
        fprintf(stderr, "ERROR: random generation error\n");
        return -1;
    }

    if(mg_base64_encode(data, SECRET_SIZE, (char *) secret, B64ENCODE_OUT_SAFESIZE(SECRET_SIZE)) == 0){
        fprintf(stderr, "ERROR: could not encode secret buf.\n");
        return -1;
    }

#ifdef DEBUG
    printf("Secret created: %s\n", secret);
#endif
    
    return 0;
}

static int set_agent_data(unsigned char *ak, char *uuid){
    sqlite3 *db;
    sqlite3_stmt *res;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    char *sql = "UPDATE attesters_credentials SET confirmed = 1, validity = 1 WHERE ak_pub = ? AND uuid = ?;";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, (char *) ak, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
            return -1;
        }
        rc = sqlite3_bind_text(res, 2, uuid, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
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

/* static int set_ak_confirmed(unsigned char *ak, char *uuid){
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
} */

/* responsibility of the caller to free the ek_db_entry */
/* static struct ek_db_entry *retrieve_ek(char *uuid){
    sqlite3 *db;
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
        strcpy(ek_entry->uuid, (char *) sqlite3_column_text(res, 0));
        strcpy((char *) ek_entry->ek_cert, (char *) sqlite3_column_text(res, 1));
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
} */

int check_verifier_presence(char *ip){
    sqlite3 *db;
    sqlite3_stmt *res;
    int val = 0;
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    char *sql = "SELECT id FROM verifiers WHERE ip = ?;";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, ip, -1, NULL);
        if (rc != SQLITE_OK ) {
            return -1;
        }
    } else {
        fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }
        
    int step = sqlite3_step(res);
    
    if (step == SQLITE_ROW){
        val = sqlite3_column_int(res, 0);
    }
        
    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return val;
}

bool check_ek_presence(char *uuid){
    sqlite3 *db;
    sqlite3_stmt *res;
    bool ret = false;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
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
        fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }
        
    int step = sqlite3_step(res);
    
    if (step == SQLITE_ROW)
        ret = true;

    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return ret;
}

static int insert_verifier(char *ip){
    sqlite3 *db;
    sqlite3_stmt *res;
    int ret = -1;

    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    char *sql = "INSERT INTO verifiers (ip) values (?);";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, ip, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            return -1;
        }
    } else {
        fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    int step = sqlite3_step(res);
    
    if (step == SQLITE_DONE && sqlite3_changes(db) == 1) {
        fprintf(stdout, "INFO: verifier succesfully inserted into the db\n");
        ret = sqlite3_last_insert_rowid(db);
        verifier_num ++;
    }
    else {
        fprintf(stderr, "ERROR: could not insert verifier ip into the db\n");
    }
    
    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return ret;
}

int get_verifier_ip(int id, char * ip){
    sqlite3 *db;
    sqlite3_stmt *res;
    int val = -1;
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    char *sql = "SELECT ip FROM verifiers WHERE id = ?;";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(res, 1, id);
        if (rc != SQLITE_OK ) {
            return -1;
        }
    } else {
        fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(res);
        sqlite3_close(db);
        return -1;
    }
        
    int step = sqlite3_step(res);
    
    if (step == SQLITE_ROW){
        strcpy(ip, (char *) sqlite3_column_text(res, 0));
        val = 0;
    } else {
        fprintf(stderr, "ERROR: Verifier id %d not found\n", id);
    }
        
    sqlite3_finalize(res);
    sqlite3_close(db);
    
    return val;
}

static int insert_ak(struct ak_db_entry *ak_entry){
    sqlite3 *db;
    sqlite3_stmt *res;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    char *sql = "INSERT INTO attesters_credentials values (?, ?, ?, ?, ?);";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(res, 1, ak_entry->uuid, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
            return -1;
        }
        rc = sqlite3_bind_text(res, 2, (char *) ak_entry->ak_pem, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
            return -1;
        }
        rc = sqlite3_bind_text(res, 3, (char *) ak_entry->ip, -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
            return -1;
        }
        rc = sqlite3_bind_int(res, 4, ak_entry->validity);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
            return -1;
        }
        rc = sqlite3_bind_int(res, 5, ak_entry->confirmed);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
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
    sqlite3_stmt *res;
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
    if (rc != SQLITE_OK) {        
        fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
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
        rc = sqlite3_bind_text(res, 2, (char *) ek_entry->ek_cert, -1, SQLITE_TRANSIENT);
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

static void join_service_manager(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_http_match_uri(hm, API_JOIN) && !strncmp(hm->method.ptr, POST, hm->method.len)) {
        
        #ifdef DEBUG
            printf("%.*s\n", (int) hm->message.len, hm->message.ptr);
        #endif

            /* Read post */
            /*
                {
                    "uuid": "aaaaaaaaa",
                    "ek_cert_b64": "aaaaaaaaa",
                    "ak_pub_b64": "aaaaaaaa",
                    "ak_name_b64": "aaaaaaaa",
                    "ip_addr": "ip:port"
                }
            */
            unsigned char* uuid = (unsigned char *) mg_json_get_str(hm->body, "$.uuid");
            unsigned char* ek_cert_b64 = (unsigned char *) mg_json_get_str(hm->body, "$.ek_cert_b64");
            unsigned char* ak_pub_b64 = (unsigned char *) mg_json_get_str(hm->body, "$.ak_pub_b64");
            unsigned char* ak_name_b64 = (unsigned char *) mg_json_get_str(hm->body, "$.ak_name_b64");
            char* ip_addr = mg_json_get_str(hm->body, "$.ip_addr");
            size_t ek_cert_len = B64DECODE_OUT_SAFESIZE(strlen((char *) ek_cert_b64));
            size_t ak_name_len = B64DECODE_OUT_SAFESIZE(strlen((char *) ak_name_b64));

            printf("%s\n", ip_addr);

            unsigned char *ek_cert_buff = (unsigned char *) malloc(ek_cert_len);
            

        #ifdef DEBUG
            printf("EK_CERT: %s\n", ek_cert_b64);
            printf("AK_PUB: %s\n", ak_pub_b64);
        #endif

            //ek_entry = retrieve_ek();
            if(!check_ek_presence((char *) uuid)) {
                //Malloc buffer
                if(ek_cert_buff == NULL) {
                    free(ek_cert_b64);
                    free(ak_pub_b64);
                    free(ak_name_b64);
                    mg_http_reply(c, 500, NULL, "\n");
                    return;
                }
                #ifdef DEBUG
                printf("%s\n", ek_cert_b64);
                printf("%d\n", ek_cert_len);
                printf("%d\n", strlen((char *) ek_cert_b64));
                #endif
                //Decode b64
                if(mg_base64_decode((char *) ek_cert_b64, strlen((char *) ek_cert_b64), (char *) ek_cert_buff, ek_cert_len + 1) == 0){
                    fprintf(stderr, "ERROR: Transmission challenge data error.\n");
                    free(ek_cert_buff);
                    free(ek_cert_b64);
                    free(ak_pub_b64);
                    free(ip_addr);
                    mg_http_reply(c, 500, NULL, "\n");
                    return;
                }

                /* Verify the X509 certificate of the EK */
                if(verify_x509_cert(ek_cert_buff, ek_cert_len, js_config.ca_x509_path)){
                    mg_http_reply(c, OK, APPLICATION_JSON,
                        "{\"error\":\"ek certificate verification failed\"}\n");
                    MG_INFO(("%s %s %d", POST, API_JOIN, OK));

                    free(ek_cert_buff);
                    free(ek_cert_b64);
                    free(ip_addr);
                    free(ak_pub_b64);
                    return;
                }
                else {
                    fprintf(stdout, "INFO: EK certificate verified successfully\n");

                    struct ek_db_entry ek;
                    strcpy((char *) ek.ek_cert,(char *) ek_cert_b64);
                    strcpy(ek.uuid, (char *) uuid);

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
                //Malloc buffer
                if(ek_cert_buff == NULL) {
                    free(ek_cert_b64);
                    free(ak_pub_b64);
                    free(ak_name_b64);
                    free(ip_addr);
                    mg_http_reply(c, 500, NULL, "\n");
                    return;
                }

                //Decode b64
                ek_cert_len = mg_base64_decode((char *) ek_cert_b64, strlen((char *) ek_cert_b64) + 1, (char *) ek_cert_buff, ek_cert_len );
                if(ek_cert_len == 0){
                    fprintf(stderr, "ERROR: Transmission challenge data error.\n");
                    free(ek_cert_buff);
                    free(ek_cert_b64);
                    free(ak_pub_b64);
                    free(ip_addr);
                    mg_http_reply(c, 500, NULL, "\n");
                    return;
                }

            }

            unsigned char *ak_name_buff = (unsigned char *) malloc(ak_name_len + 1);
            if(ak_name_buff == NULL) {
                free(ek_cert_b64);
                free(ak_pub_b64);
                free(ak_name_b64);
                free(ek_cert_buff);
                free(ip_addr);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            ak_name_len = mg_base64_decode((char *) ak_name_b64, strlen((char *) ak_name_b64), (char *) ak_name_buff, ak_name_len);
            if(ak_name_len == 0){
                fprintf(stderr, "ERROR: Transmission challenge data error.\n");
                free(ek_cert_buff);
                free(ek_cert_b64);
                free(ak_pub_b64);
                free(ak_name_b64);
                free(ip_addr);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            struct ak_db_entry *ak_entry = retrieve_ak((char *) uuid, ak_pub_b64);
            if (ak_entry == NULL) {
                fprintf(stdout, "INFO: AK not present in the db\n");
            }
            else {
                fprintf(stdout, "INFO: AK already present in the db\n");

                if(ak_entry->validity == VALID) {
                    printf("INFO: AK is valid\n");
                    mg_http_reply(c, ALREDY_JOINED, APPLICATION_JSON,
                        "{\"message\":\"ak already registered and valid\"}\n");
                    MG_INFO(("%s %s %d", POST, API_JOIN, ALREDY_JOINED));
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

            /* create secret */
            if (create_secret(secret) != 0){
                fprintf(stderr, "ERROR: create_secret failed\n");
                return;
            }

            /* tpm2_makecredential */
            unsigned char *out_buf;
            size_t out_buf_size;
            if(tpm_makecredential(ek_cert_buff, ek_cert_len, secret, ak_name_buff, ak_name_len, &out_buf, &out_buf_size)){
                fprintf(stderr, "ERROR: tpm_makecredential failed\n");
            }

/*             printf("OUT_BUF: ");
            for(int i=0; i<out_buf_size; i++){
                printf("%02x", out_buf[i]);
            }
            printf("\n"); */

            //insert_ak(ak_pub_b64);
            char *mkcred_out_b64;
            size_t mkcred_out_b64_len = B64ENCODE_OUT_SAFESIZE(out_buf_size);

            mkcred_out_b64 = (char *) malloc(mkcred_out_b64_len);
            if(mkcred_out_b64 == NULL) {
                free(ek_cert_buff);
                free(ek_cert_b64);
                free(ak_pub_b64);
                free(ak_name_b64);
                free(ak_name_buff);
                free(out_buf);
                free(ip_addr);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            if(mg_base64_encode(out_buf, out_buf_size, mkcred_out_b64, mkcred_out_b64_len + 1) == 0){
                fprintf(stderr, "ERROR: could not encode mkcred out buf.\n");
                free(ek_cert_buff);
                free(ek_cert_b64);
                free(ak_pub_b64);
                free(ak_name_b64);
                free(ak_name_buff);
                free(out_buf);
                free(mkcred_out_b64);
                free(ip_addr);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            struct ak_db_entry ak;
            strcpy((char *) ak.ak_pem, (char *) ak_pub_b64);
            strcpy(ak.uuid, (char *) uuid);
            strcpy(ak.ip, ip_addr);
            ak.confirmed = 0;
            ak.validity = 0;

            insert_ak(&ak);

            pthread_mutex_lock(&mutex);
            push_uuid(ak.uuid);
            pthread_mutex_unlock(&mutex);
            pthread_cond_signal(&cond);

            mg_http_reply(c, CREATED, APPLICATION_JSON,
                "{\"mkcred_out\":\"%s\"}\n", mkcred_out_b64);
            MG_INFO(("%s %s %d", POST, API_JOIN, CREATED));

            free(ak_name_buff);
            free(ek_cert_buff);
            free(uuid);
            free(ak_entry);
            free(ek_cert_b64);
            free(ak_pub_b64);
            free(ip_addr);

        }
        else if (mg_http_match_uri(hm, API_CONFIRM_CREDENTIAL) && !strncmp(hm->method.ptr, POST, hm->method.len)) {
           // struct ak_db_entry ak_entry;
            /* receive and verify the value calculated by the attester with tpm_activatecredential */
            unsigned char* secret_b64 = (unsigned char *) mg_json_get_str(hm->body, "$.secret_b64");
            unsigned char* uuid = (unsigned char *) mg_json_get_str(hm->body, "$.uuid");
            unsigned char* ak_pub = (unsigned char *) mg_json_get_str(hm->body, "$.ak_pub_b64");
            
            size_t secret_len = B64DECODE_OUT_SAFESIZE(strlen((char *) secret_b64));

            unsigned char *secret_buff = (unsigned char *) malloc(secret_len + 1);
            if(secret_buff == NULL) {
                free(secret_b64);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }
            
            /* Decode b64 */
            secret_len = mg_base64_decode((char *) secret_b64, strlen((char *) secret_b64), (char *) secret_buff, secret_len);
            if(secret_len == 0){
                fprintf(stderr, "ERROR: Transmission challenge data error.\n");
                free(secret_buff);
                free(secret_b64);
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }
            secret_buff[secret_len] = '\0';
            fprintf(stdout, "INFO: secret received: %s\n", secret_buff);

            /* verify the correctness of the secret_buff received */
            if(!strcmp((char *) secret_buff, (char *) secret)){
                fprintf(stdout, "INFO: secret verified succesfully\n");
            }
            else {
                fprintf(stdout, "INFO: secret does not match\n");
                free(secret_buff);
                free(secret_b64);
                mg_http_reply(c, OK, NULL, "\n");
                return;
            }

            /* Set the AK in the database as confirmed (=1) and valid (=1)*/
            if(set_agent_data(ak_pub, (char *) uuid) != 0){
                //TODO database error ??
                free(secret_buff);
                free(secret_b64);
                free(uuid);
                free(ak_pub);
                return;
            }

            /* reply the agent  */
            mg_http_reply(c, OK, APPLICATION_JSON,
                        "OK\n");
            MG_INFO(("%s %s %d", POST, API_CONFIRM_CREDENTIAL, OK));
            c->is_draining = 1;
            /* copy agent data */
            //memcpy(uuid, ak_entry.uuid, strlen((char *) uuid));
           // memcpy(ak_pub, ak_entry.ak_pem, strlen((char *) ak_pub));
            /* notify a verifier */
            //TODO
           // if (notify_verifier(get_verifier_id(), &ak_entry)){
//
            //}
            /* notify all verifiers?? */
            free(secret_buff);
            free(secret_b64);
            free(uuid);
            free(ak_pub);
            

        }else if (mg_http_match_uri(hm, API_JOIN_VERIFIER) && !strncmp(hm->method.ptr, POST, hm->method.len)){

            int ret;
            /* Read post */
            /*
                {
                    "ip": "0.0.0.0:22",
                }
            */
            char* verifier_ip = mg_json_get_str(hm->body, "$.ip");
            if(verifier_ip == NULL){
                mg_http_reply(c, 500, NULL, "\n");
                return;
            }

            fprintf(stdout, "INFO: verifier ip: %s wants to join\n", verifier_ip);

            ret = check_verifier_presence(verifier_ip);
            if(ret == 0){
                ret = insert_verifier(verifier_ip);
                mg_http_reply(c, OK, APPLICATION_JSON, "{\"topic_id\":%d}\n", ret);
                MG_INFO(("%s %s %d", POST, API_JOIN_VERIFIER, OK));
            }
            else {
                fprintf(stdout, "INFO: verifier alredy joined, id: %d\n", ret);
                mg_http_reply(c, OK, APPLICATION_JSON, "{\"topic_id\":%d}\n", ret);
                MG_INFO(("%s %s %d", POST, API_JOIN_VERIFIER, OK));
           }

        } 
        else {
            mg_http_reply(c, 500, NULL, "\n");
        }
    } else if (ev == MG_EV_WAKEUP) {
        struct mg_str *data = (struct mg_str *) ev_data;
        mg_http_reply(c, 200, "", "Result: %.*s\n", data->len, data->ptr);
  }
}

static void request_attestation(struct mg_connection *c, int ev, void *ev_data){
    if (ev == MG_EV_OPEN) {
        // Connection created. Store connect expiration time in c->data
        *(uint64_t *) c->data = mg_millis() + s_timeout_ms;
    } else if (ev == MG_EV_POLL) {
        if (mg_millis() > *(uint64_t *) c->data && (c->is_connecting || c->is_resolving)) {
            mg_error(c, "Connect timeout");
        }
    } else if (ev == MG_EV_CONNECT){
        struct ak_db_entry *ak_entry = (struct ak_db_entry *) c->fn_data;
        size_t object_length = 0;
        char object[4096];

        fprintf(stdout, "INFO: %s\n %s\n", ak_entry->uuid, ak_entry->ak_pem);

        object_length = snprintf(object, 4096, "{\"uuid\":\"%s\",\"ak_pem\":\"%s\",\"ip_addr\":\"%s\"}", ak_entry->uuid, ak_entry->ak_pem, ak_entry->ip);

        /* Send request */
        mg_printf(c,
        "POST /request_attestation HTTP/1.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "\r\n"
        "%s\n",
        object_length,
        object);

    } else if (ev == MG_EV_HTTP_MSG) {
        // Response is received. Print it
    } else if (ev == MG_EV_ERROR) {
        struct ak_db_entry *ak_entry = (struct ak_db_entry *) c->fn_data;
        ak_entry->Continue = false;  // Error, tell event loop to stop
    }





    /////
}

int notify_verifier(int id, struct ak_db_entry  * ak_entry){
    //char *buff = malloc(100);
    char url[MAX_BUF];
    struct mg_mgr mgr;  // Event manager
    struct mg_connection *c;
    
    ak_entry->Continue = true;

    fprintf(stdout, "INFO: Retrieve verifier information id: %d\n", id);

    if (get_verifier_ip(id, ak_entry->ip) != 0){
        fprintf(stderr, "ERROR: get_verifier_ip\n");
        return -1;
    }
    
    /* Contact the join service */
    snprintf(url, 280, "http://%s", ak_entry->ip);
    
    fprintf(stdout, "INFO: ip: %s\n", url);

    /* Connect to the verifier */

    mg_mgr_init(&mgr);

    c = mg_http_connect(&mgr, url, request_attestation, ak_entry);
    if (c == NULL) {
        MG_ERROR(("CLIENT cant' open a connection"));
        return -1;
    }

    while (ak_entry->Continue) mg_mgr_poll(&mgr, 1); //1ms


    return 0;
}

/* return the DB id of a verifier based on a round-robin selection*/
int get_verifier_id(void){
    //last_requested_verifier++;
    if(verifier_num == 0){
        return -1;
    }

    if (last_requested_verifier == verifier_num){
        last_requested_verifier = 0;
    }
    return ++last_requested_verifier;
}

/*Create db connection and, if not presents, create the keys databases
    ret:
    -1 error
    0 OK
    -------------
    attester_credentials
    ---------------------------------------------
    | uuid | ak_pub | ip | validity | confirmed |
    ---------------------------------------------

    -------------
    attester_ek_certs
    ------------------
    | uuid | ek_cert |
    ------------------

    -------------
    verifiers
    ------------------
    | id     | ip     |
    ------------------
*/
static int init_database(void){
    sqlite3_stmt *res= NULL;
    sqlite3 *db = NULL;

    char *sql1 = "CREATE TABLE IF NOT EXISTS attesters_ek_certs (\
        uuid text NOT NULL,\
        ek_cert text NOT NULL,\
        PRIMARY KEY (uuid)\
    );";

    char *sql2 = "CREATE TABLE IF NOT EXISTS attesters_credentials (\
        uuid text NOT NULL,\
        ak_pub text NOT NULL,\
        ip text NOT NULL,\
        validity INT NOT NULL,\
        confirmed INT NOT NULL,\
        PRIMARY KEY (uuid, ak_pub)\
        FOREIGN KEY (uuid) REFERENCES attesters_ek_certs\
    );";

    char *sql3 = "CREATE TABLE IF NOT EXISTS verifiers (\
        id INTEGER PRIMARY KEY AUTOINCREMENT,\
        ip text NOT NULL\
    );";

    char *sql4 = "SELECT COUNT(id) FROM verifiers;";
    
    int rc = sqlite3_open_v2(js_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    if ( rc != SQLITE_OK) {
        printf("Cannot open or create the join service database, error %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    /*Checking if already joined verifiers are present*/
    rc = sqlite3_prepare_v2(db, sql4, -1, &res, 0);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(res) == SQLITE_ROW){
            /*Db present with verifiers*/
            verifier_num = sqlite3_column_int(res, 0);
            fprintf(stdout, "INFO: Old database present with %d verifiers joined\n", verifier_num);
            sqlite3_finalize(res);
            sqlite3_close(db);
            return 0;
        }
    }

    //verifiers table
    rc = sqlite3_prepare_v2(db, sql3, -1, &res, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    rc = sqlite3_exec(db, sql3, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    //attesters_ek_certs table
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

    //attesters_credentials table
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

    sqlite3_close(db);
    return 0;
}

static void mqtt_handler(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_OPEN) {
    MG_INFO(("%lu CREATED", c->id));
    // c->is_hexdumping = 1;
  } else if (ev == MG_EV_ERROR) {
    // On error, log error message
    MG_ERROR(("%lu ERROR %s", c->id, (char *) ev_data));
  } else if (ev == MG_EV_CONNECT) {
    // If target URL is SSL/TLS, command client connection to use TLS
    /* if (mg_url_is_ssl(s_url)) {
      struct mg_tls_opts opts = {.ca = mg_str("ca.pem")};
      mg_tls_init(c, &opts);
    } */
  } else if (ev == MG_EV_MQTT_OPEN) {
    // MQTT connect is successful
    /* struct mg_str subt = mg_str(s_sub_topic);
    struct mg_str pubt = mg_str(s_pub_topic), data = mg_str("hello"); */
    MG_INFO(("%lu CONNECTED", c->id));
    
    
  } else if (ev == MG_EV_MQTT_MSG) {
    // When we get echo response, print it
    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    MG_INFO(("%lu RECEIVED %.*s <- %.*s", c->id, (int) mm->data.len,
             mm->data.ptr, (int) mm->topic.len, mm->topic.ptr));
  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("%lu CLOSED", c->id));
    //s_conn = NULL;  // Mark that we're closed
  }
  (void) c->fn_data;
}

int main(int argc, char *argv[]) {
    struct mg_mgr mgr;
    struct mg_connection *c;
    mg_mgr_init(&mgr);
    char url[MAX_BUF];
    pthread_t thread_id;  // queue manager thread
    stop_event = 0;

    mg_mgr_init(&mgr_mqtt);
    c_mqtt = mqtt_connect(&mgr_mqtt, mqtt_handler);

    int ret = pthread_create(&thread_id, NULL, queue_manager, NULL);
    if(ret != 0){
        fprintf(stderr, "ERROR: could not create queue manager thread\n");
        exit(ret);
    }

    pthread_cond_init(&cond, NULL);
    pthread_mutex_init(&mutex, NULL);

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

    for (;;) {
        mg_mgr_poll(&mgr, 1000);    //http
        mg_mgr_poll(&mgr_mqtt, 1000);   //mqtt
    }

    mg_mgr_free(&mgr);                                        // Cleanup
    return 0;
}