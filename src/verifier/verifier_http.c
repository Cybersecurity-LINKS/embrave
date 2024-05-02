// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "mongoose.h"
#include "verifier.h"
#include "config_parse.h"
#include "common.h"
#include "mqtt_client.h"

static bool Continue = true;

static tpm_challenge_reply rpl;

static struct verifier_conf verifier_config;
extern agent_list *agents;
static const uint64_t s_timeout_ms = 1500;  // Connect timeout in milliseconds

struct mg_mgr mgr_mqtt;
struct mg_connection *c_mqtt;
int id;

int load_challenge_reply(struct mg_http_message *hm, tpm_challenge_reply *rpl);
void print_data(tpm_challenge_reply *rpl);
int encode_challenge(tpm_challenge *chl, char* buff, size_t *buff_length);
void create_attestation_thread(agent_list * agent);
int add_agent_data(agent_list * ptr);
int update_agent_data(agent_list * ptr);

bool parse_whitelist(char * gv, char * whitelist_uri){
  struct stat st = {0};
  struct mg_str whitelist_uri_str = mg_str(whitelist_uri);
  char buff[1025];

  if(mg_strstr(whitelist_uri_str, mg_str("file://")) != NULL){
    snprintf(buff, 1025, "%s%s",verifier_config.whitelist_path, whitelist_uri_str.ptr + 7 );

    if (stat(buff, &st) == -1) {
      /*TODO DOWNLOAD WHITELIST*/
      printf("ERROR missing whitelist file %s\n", buff);
      return false;
    }

    snprintf(gv, 2048, "file:%s", buff);
    return true;
  } else 
  if (mg_strstr(whitelist_uri_str, mg_str("http")) != NULL){
    /*TODO DOWNLOAD WHITELIST*/
    printf("ERROR donwload wihitelist no implmented yet\n");
    return false;
  } 

  printf("ERROR unknow URI format file %s\n", whitelist_uri_str.ptr);
  return false;
}

static void mqtt_handler(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_OPEN) {
    MG_INFO(("%lu CREATED", c->id));
  } else if (ev == MG_EV_ERROR) {
    // On error, log error message
    MG_ERROR(("%lu ERROR %s", c->id, (char *) ev_data));
  } else if (ev == MG_EV_CONNECT) {
  } else if (ev == MG_EV_MQTT_OPEN) {
    // MQTT connect is successful
    MG_INFO(("%lu CONNECTED", c->id));
  } else if (ev == MG_EV_MQTT_MSG) {
    // When we get echo response, print it
    char gv[2048];
    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    MG_INFO(("%lu RECEIVED %.*s <- %.*s", c->id, (int) mm->data.len,
              mm->data.ptr, (int) mm->topic.len, mm->topic.ptr));
    /*
          {
            "uuid": "aaaaaaaaa",
            "ip_port": "aaaaaaaaa",
            "ak_pub_b64": "aaaaaaaa",
            "whitelist_uri": "aaaaaaaa"
          }
      */

    char* uuid = mg_json_get_str(mm->data, "$.uuid");
    char* ak_pub = mg_json_get_str(mm->data, "$.ak_pem");
    char* ip_addr = mg_json_get_str(mm->data, "$.ip_addr");
    char* whitelist_uri = mg_json_get_str(mm->data, "$.whitelist_uri");

    agent_list *last_ptr = agent_list_find_uuid(uuid);

    parse_whitelist(gv, whitelist_uri);
    
    if(last_ptr != NULL){
      last_ptr->running = false;
      last_ptr->continue_polling = false;

      last_ptr = agent_list_new();
      strcpy(last_ptr->ip_addr, ip_addr);
      strcpy(last_ptr->ak_pub, ak_pub);
      strcpy(last_ptr->uuid, uuid);
      strcpy(last_ptr->gv_path, gv);

      last_ptr->running = true;
      last_ptr->max_connection_retry_number = 0;

      update_agent_data(last_ptr);
      create_attestation_thread(last_ptr);
    } else {
      last_ptr = agent_list_new();
      strcpy(last_ptr->ip_addr, ip_addr);
      strcpy(last_ptr->ak_pub, ak_pub);
      strcpy(last_ptr->uuid, uuid);
      strcpy(last_ptr->gv_path, gv); 

      last_ptr->running = true;
      last_ptr->max_connection_retry_number = 0;

      /*add attester dato to verifier db*/
      add_agent_data(last_ptr);
      create_attestation_thread(last_ptr);
    }

    free(uuid);
    free(ak_pub);
    free(ip_addr);
    //free(whitelist);

  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("%lu CLOSED", c->id));
  }
  (void) c->fn_data;
}

int update_agent_data(agent_list * ptr){
  sqlite3 *db;
  sqlite3_stmt *res;
    
  int rc = sqlite3_open_v2(verifier_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
  if (rc != SQLITE_OK) {        
    fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  char *sql = "UPDATE attesters SET ak_pub=?, ip_addr=?, goldenvalue_database=? WHERE uuid=?";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    rc = sqlite3_bind_text(res, 1, ptr->ak_pub, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
    rc = sqlite3_bind_text(res, 2, ptr->ip_addr, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
    rc = sqlite3_bind_text(res, 3, ptr->gv_path, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
    rc = sqlite3_bind_text(res, 4, ptr->uuid, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
  } else {
    fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
  }

  int step = sqlite3_step(res);
    
  if (step == SQLITE_DONE && sqlite3_changes(db) == 1) {
    fprintf(stdout, "INFO: attester succesfully updated into the db\n");
  }
  else {
    fprintf(stderr, "ERROR: could not update the attester into the db\n");
  }

  sqlite3_finalize(res);
  sqlite3_close(db);
    
  return 0;
}


int add_agent_data(agent_list * ptr){
  sqlite3 *db;
  sqlite3_stmt *res;
    
  int rc = sqlite3_open_v2(verifier_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
  if (rc != SQLITE_OK) {        
    fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  char *sql = "INSERT INTO attesters values (?, ?, ?, ?);";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    rc = sqlite3_bind_text(res, 1, ptr->uuid, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
    rc = sqlite3_bind_text(res, 2, ptr->ak_pub, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
    rc = sqlite3_bind_text(res, 3, ptr->ip_addr, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
    rc = sqlite3_bind_text(res, 4, ptr->gv_path, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
  } else {
    fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
  }

  int step = sqlite3_step(res);
    
  if (step == SQLITE_DONE && sqlite3_changes(db) == 1) {
    fprintf(stdout, "INFO: attester succesfully inserted into the db\n");
  }
  else {
    fprintf(stderr, "ERROR: could not insert attester into the db\n");
  }

  sqlite3_finalize(res);
  sqlite3_close(db);
    
  return 0;
}

int remove_agent(agent_list * ptr){
  sqlite3 *db;
  sqlite3_stmt *res;
    
  int rc = sqlite3_open_v2(verifier_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    
  if (rc != SQLITE_OK) {        
    fprintf(stderr, "ERROR: Cannot open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  char *sql = "DELETE FROM attesters where uuid=? and ak_pub=?;";

  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    rc = sqlite3_bind_text(res, 1, ptr->uuid, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
    rc = sqlite3_bind_text(res, 2, ptr->ak_pub, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK ) {
      sqlite3_close(db);
      return -1;
    }
  } else {
    fprintf(stderr, "ERROR: Failed to execute statement: %s\n", sqlite3_errmsg(db));
  }

  int step = sqlite3_step(res);
    
  if (step == SQLITE_DONE && sqlite3_changes(db) == 1) {
    fprintf(stdout, "INFO: attester succesfully removed from the db\n");
  }
  else {
    fprintf(stderr, "ERROR: could not remove attester from the db\n");
  }

  sqlite3_finalize(res);
  sqlite3_close(db);
    
  return 0;
}

int load_challenge_reply(struct mg_http_message *hm, tpm_challenge_reply *rpl){
  size_t b64_sz = hm->body.len;
  size_t byte_sz = B64DECODE_OUT_SAFESIZE(b64_sz);
  size_t i = 0;
  char * byte_buff;

  //Malloc buffer
  byte_buff = malloc(byte_sz);
  if(byte_buff == NULL) return -1;

  //Decode b64
  if(mg_base64_decode(hm->body.ptr, b64_sz, byte_buff, byte_sz) == 0){
    printf("Transmission challenge data error \n");
    return -1;
  }

  // Read the buffer
  //Signature
  memcpy(&rpl->sig_size, byte_buff,  sizeof(UINT16));
  i += sizeof(UINT16);

  rpl->sig =  malloc(rpl->sig_size * sizeof(BYTE *));
  memcpy(rpl->sig, byte_buff + i, rpl->sig_size);
  i += rpl->sig_size;

  //Nonce
  memcpy(&rpl->nonce, byte_buff + i, NONCE_SIZE * sizeof(uint8_t));
  i += NONCE_SIZE * sizeof(uint8_t);

  //Data quoted
  rpl->quoted = (TPM2B_ATTEST  *) malloc(sizeof(TPM2B_ATTEST));
  memcpy(&rpl->quoted->size, byte_buff + i, sizeof(UINT16));
  i += sizeof(UINT16);
  memcpy(&rpl->quoted->attestationData, byte_buff + i, rpl->quoted->size);
  i += rpl->quoted->size;

  //Pcr
  memcpy(&rpl->pcrs.count, byte_buff + i, sizeof(uint32_t));
  i += sizeof(uint32_t);
  memcpy(&rpl->pcrs.pcr_values, byte_buff + i, sizeof(rpl->pcrs.pcr_values));
  i += sizeof(rpl->pcrs.pcr_values);

  //IMA Log
  memcpy(&rpl->ima_log_size, byte_buff + i, sizeof(uint32_t));
  i += sizeof(uint32_t);
  if(rpl->ima_log_size != 0){
    rpl->ima_log = (unsigned char *) malloc(rpl->ima_log_size);
    memcpy(rpl->ima_log, byte_buff + i, rpl->ima_log_size);
    i += rpl->ima_log_size;
    memcpy(&rpl->wholeLog, byte_buff + i, sizeof(uint8_t));
    i += sizeof(uint8_t);
  }
#ifdef DEBUG  
  print_data(rpl);
#endif
  return 0;

}

int encode_challenge(tpm_challenge *chl, char* buff, size_t *buff_length){
  size_t sz = B64ENCODE_OUT_SAFESIZE(sizeof(tpm_challenge));

  *buff_length = mg_base64_encode((const unsigned char *)chl, sizeof(tpm_challenge), buff, sz);
  if(buff_length == 0){
    printf("mg_base64_encode error\n");
    return -1;
  }

  return 0;
}

static void request_join_verifier(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_OPEN) {
    // Connection created. Store connect expiration time in c->data
    *(uint64_t *) c->data = mg_millis() + s_timeout_ms;
  } else if (ev == MG_EV_POLL) {
    if (mg_millis() > *(uint64_t *) c->data &&
        (c->is_connecting || c->is_resolving)) {
      mg_error(c, "Connect timeout");
    }
  } else if (ev == MG_EV_CONNECT) {
    char buff[280];

    snprintf(buff, 280, "{\"ip\":\"%s:%d\"}", verifier_config.ip, verifier_config.port);

#ifdef DEBUG
    printf("%s\n", object);
#endif

    /* Send request */
    mg_printf(c,
      "POST /api/request_join_verifier HTTP/1.1\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: %ld\r\n"
      "\r\n"
      "%s\n",
      strlen(buff),
      buff);

  } else if (ev == MG_EV_HTTP_MSG) {
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

#ifdef DEBUG
    printf("%.*s", (int) hm->message.len, hm->message.ptr);
#endif
    int status = mg_http_status(hm);
    if(status == 403){ /* forbidden */
      /*TODO errors*/
      fprintf(stderr, "ERROR: join service response code is not 403 (forbidden)\n");
      c->is_draining = 1;        // Tell mongoose to close this connection
      Continue = false;  // Tell event loop to stop
      return;
    } else if (status == OK){
      
      id = mg_json_get_long(hm->body, "$.topic_id", -1);

      char topic[25];
      sprintf(topic, "%s%d", ATTEST_TOPIC_PREFIX, id);
      mqtt_subscribe(c_mqtt, topic);

      fprintf(stdout, "INFO: Topic id: %d\n", id);
      c->is_draining = 1;        // Tell mongoose to close this connection
      Continue = false;  // Tell event loop to stop

      return;
    } 
  } else if (ev == MG_EV_ERROR) {
    Continue = false;  // Error, tell event loop to stop
  }
}

static void verifier_manager(struct mg_connection *c, int ev, void *ev_data){
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (mg_http_match_uri(hm, API_ALIVE) && !strncmp(hm->method.ptr, GET, hm->method.len)) {
      mg_http_reply(c, 200, NULL, "\n");
      MG_INFO(("%s %d", API_ALIVE, 200));
    }
    else {
      mg_http_reply(c, 404, NULL, "\n");
    }
  }
}

void create_integrity_report(agent_list  *agent_data, char *buff){
  snprintf(buff, 4096, "{\"uuid\":\"%s\",\"ak_pub\":\"%s\",\"status\":%d}", agent_data->uuid, agent_data->ak_pub, agent_data->trust_value);
}

// Print HTTP response and signal that we're done
static void remote_attestation(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_OPEN) {
    // Connection created. Store connect expiration time in c->data
    *(uint64_t *) c->data = mg_millis() + s_timeout_ms;
  } else if (ev == MG_EV_POLL) {
    if (mg_millis() > *(uint64_t *) c->data &&
        (c->is_connecting || c->is_resolving)) {
      mg_error(c, "Connect timeout");
    }
  } else if (ev == MG_EV_CONNECT) {
    agent_list *agent_data = (agent_list *) c->fn_data;
    tpm_challenge chl;
    size_t buff_length = 0;
    char buff [B64ENCODE_OUT_SAFESIZE(sizeof(tpm_challenge))];

    //If PCRs10 from agent db are null, ask all ima log
    if(agent_data->pcr10_sha256 == NULL){
      chl.send_wholeLog = 1;
    } else {
      chl.send_wholeLog = 0;
   }

    //Create nonce
    if(ra_challenge_create(&chl, agent_data)!= 0){
      agent_data->continue_polling = false;
      agent_data->trust_value = VERIFIER_INTERNAL_ERROR;
      c->is_draining = 1;        // Tell mongoose to close this connection
      return;
    }

    //Encode it in json form
    if(encode_challenge(&chl, buff, &buff_length)!= 0){
      agent_data->continue_polling = false;
      agent_data->trust_value = VERIFIER_INTERNAL_ERROR;
      c->is_draining = 1;        // Tell mongoose to close this connectio
      return;
    }

    // Send request
    mg_printf(c,
      "POST /api/quote HTTP/1.1\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: %ld\r\n"
      "\r\n"
      "%s\n",
      buff_length,
      buff
    );

  } else if (ev == MG_EV_HTTP_MSG) {
    agent_list *agent_data = (agent_list *) c->fn_data;
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    int n = load_challenge_reply(hm, &rpl);
    if(n < 0){
      agent_data->trust_value = n;
      c->is_draining = 1;        // Tell mongoose to close this connection
      agent_data->continue_polling = false;  // Tell event loop to stop
      return;
    } 

    agent_data->trust_value = ra_challenge_verify(&rpl, agent_data);

    c->is_draining = 1;        // Tell mongoose to close this connection
    agent_data->continue_polling = false;  // Tell event loop to stop
  } else if (ev == MG_EV_ERROR) {
    agent_list *agent_data = (agent_list *) c->fn_data;
    agent_data->continue_polling = false;  // Error, tell event loop to stop
    fprintf(stdout, "INFO: unreachable agent uuid %s, retry number %d\n", agent_data->uuid, agent_data->connection_retry_number);
    fflush(stdin);

    agent_data->connection_retry_number++;
    agent_data->trust_value = RETRY;
  }
}

void *attest_agent(void *arg) {
  agent_list * agent = (agent_list *) arg;
  struct mg_mgr mgr;
  struct mg_connection *c;
  char topic[25];
  char buff[4096]; 
  
  mg_mgr_init(&mgr);  
  sprintf(topic, "%s%d", STATUS_TOPIC_PREFIX, id);
    
  agent->byte_rcv = 0;
  agent->pcr10_sha256 = NULL;
  agent->continue_polling = true;
  agent->sleep_value = 5; /*TODO config*/
  agent->connection_retry_number = 0;
  if(agent->max_connection_retry_number == 0)
    agent->max_connection_retry_number = 3; /*TODO config and/or js*/

  while (agent->running) {
    c = mg_http_connect(&mgr, agent->ip_addr, remote_attestation, (void *) agent);
    if (c == NULL) {
      MG_ERROR(("CLIENT cant' open a connection"));
      fflush(stdout);
      continue;
    }

    while (agent->continue_polling) mg_mgr_poll(&mgr, 100); //10ms
    agent->continue_polling = true;
    if(agent->connection_retry_number == agent->max_connection_retry_number && agent->trust_value == RETRY){
      /*Unreachable agent =>  untrusted*/
      agent->trust_value = UNREACHABLE;
    }
        
    create_integrity_report(agent, buff);
    mqtt_publish(c_mqtt, topic, buff);
    if(agent->trust_value != TRUSTED && agent->trust_value != RETRY){
      /*Remove from DB*/
      remove_agent(agent);
      /*stop the attestation process*/
      agent->running = false;
    }
    else
      sleep(agent->sleep_value); 
  }

  fprintf(stdout, "INFO: attestation thread stopped for agent uuid:%s\n", agent->uuid);
  fflush(stdout);

  agent_list_remove(agent);
  pthread_exit(NULL);
}


void create_attestation_thread(agent_list * agent){
  pthread_t thread;
  pthread_attr_t attr;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  
  int result = pthread_create(&thread, &attr, attest_agent, (void *) agent);
  if (result != 0) {
    fprintf(stderr, "ERROR: pthread_create\n");
    exit(EXIT_FAILURE);
  }

  pthread_attr_destroy(&attr);
  fprintf(stdout, "INFO: attestation thread created for agent uuid:%s\n", agent->uuid);

}

static int init_database(void){
  sqlite3_stmt *res= NULL;
  sqlite3 *db = NULL;
  char *sql = "CREATE TABLE IF NOT EXISTS attesters (\
                    uuid TEXT NOT NULL,\
                    ak_pub TEXT NOT NULL,\
                    ip_addr TEXT NOT NULL,\
                    goldenvalue_database  NOT NULL,\
                    PRIMARY KEY (uuid)\
  );";
  char *sql_select = "SELECT * FROM attesters";

  int rc = sqlite3_open_v2(verifier_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
  if ( rc != SQLITE_OK) {
    printf("Cannot open or create the verifier database, error %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  rc = sqlite3_prepare_v2(db, sql_select, -1, &res, NULL);
  if (rc == SQLITE_OK) {
    /*db alredy present, try to recontatct old agents*/

    while ((rc = sqlite3_step(res)) == SQLITE_ROW) {
      char *uuid = ( char *)sqlite3_column_text(res, 0);
      char *ak = ( char *)sqlite3_column_text(res, 1);
      char *ip = ( char *)sqlite3_column_text(res, 2);
      char *whitelist = ( char *)sqlite3_column_text(res, 3);

      agent_list *last_ptr;
      last_ptr = agent_list_new();

      // Get attester data /
      strcpy(last_ptr->ip_addr, ip);
      strcpy(last_ptr->ak_pub, ak);
      strcpy(last_ptr->uuid, uuid);
      strcpy(last_ptr->gv_path, whitelist);
      last_ptr->running = true;
      last_ptr->max_connection_retry_number = 1;

      create_attestation_thread(last_ptr); 

    }

    sqlite3_close(db);
    return 0;

  }

  //attesters table
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  rc = sqlite3_exec(db, sql, NULL, NULL, NULL);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }
  
  sqlite3_close(db);
  return 0;
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;  // Event manager
  struct mg_connection *c;
  char s_conn[250];
  char mqtt_conn[281];
  struct stat st = {0};

  mg_mgr_init(&mgr_mqtt);
  
  if (stat("/var/embrave", &st) == -1) {
    if(!mkdir("/var/embrave", 0711)) {
      fprintf(stdout, "INFO: /var/embrave directory successfully created\n");
    }
    else {
      fprintf(stderr, "ERROR: cannot create /var/embrave directory\n");
      exit(-1);
    }
  } 
  
  if (stat("/var/embrave/verifier", &st) == -1) {
    if(!mkdir("/var/embrave/verifier", 0711)) {
      fprintf(stdout, "INFO: /var/embrave/verifier directory successfully created\n");
    }
    else {
      fprintf(stderr, "ERROR: cannot create /var/embrave/verifier directory\n");
    }
  }

  /* read configuration from config file */
  if(read_config(/* verifier */ 1, (void * ) &verifier_config)){
    int err = errno;
    fprintf(stderr, "ERROR: could not read configuration file\n");
    exit(err);
  }

  if (stat(verifier_config.whitelist_path, &st) == -1) {
    if(!mkdir(verifier_config.whitelist_path, 0711)) {
      fprintf(stdout, "INFO: %s directory successfully created\n", verifier_config.whitelist_path);
    }
    else {
      fprintf(stderr, "ERROR: cannot create %s directory\n", verifier_config.whitelist_path);
    }
  }

  snprintf(mqtt_conn, 280, "http://%s:%d", verifier_config.mqtt_broker_ip, verifier_config.mqtt_broker_port);

  c_mqtt = mqtt_connect(&mgr_mqtt, mqtt_handler, "verifier", mqtt_conn);

#ifdef DEBUG
  printf("verifier_config->ip: %s\n", verifier_config.ip);
  printf("verifier_config->port: %d\n", verifier_config.port);
  printf("verifier_config->tls_port: %d\n", verifier_config.tls_port);
  printf("verifier_config->tls_cert: %s\n", verifier_config.tls_cert);
  printf("verifier_config->tls_key: %s\n", verifier_config.tls_key);
  printf("verifier_config->db: %s\n", verifier_config.db);
#endif

  /* Contact the join service */
  snprintf(s_conn, 280, "http://%s:%d", verifier_config.join_service_ip, verifier_config.join_service_port);

  mg_mgr_init(&mgr);

  /* request to join (receive tpm_makecredential output) */
  c = mg_http_connect(&mgr, s_conn, request_join_verifier, NULL);

  if (c == NULL) {
    MG_ERROR(("CLIENT cant' open a connection"));
    return -1;
  }

  while (Continue) mg_mgr_poll(&mgr, 1); //1ms

  /* init database */
  if(init_database()){
    fprintf(stderr, "ERROR: could not init the db\n");
    exit(-1);
  }

  Continue = true;

  mg_log_set(MG_LL_INFO);  /* Set log level */
  mg_mgr_init(&mgr);        /* Initialize event manager */

  snprintf(s_conn, 500, "http://%s:%d", verifier_config.ip, verifier_config.port);
  c = mg_http_listen(&mgr, s_conn, verifier_manager, &mgr);  /* Create server connection */

  if (c == NULL) {
    MG_ERROR(("Cannot listen on http://%s:%d", verifier_config.ip, verifier_config.port));
    exit(EXIT_FAILURE);
  }

  MG_INFO(("Listening on http://%s:%d", verifier_config.ip, verifier_config.port));

  Continue = true;

  while (Continue) {
    mg_mgr_poll(&mgr, 100);     
    mg_mgr_poll(&mgr_mqtt, 100);
  }

  mg_mgr_free(&mgr);        
  mg_mgr_free(&mgr_mqtt); 

  return 0;
}

//Print received data
void print_data(tpm_challenge_reply *rpl){
  
  printf("DEBUG: Nonce received:");
  for(int i= 0; i< (int) NONCE_SIZE * sizeof(uint8_t); i++)
    printf("%02X", rpl->nonce[i]);
  printf("\n");

  TPML_PCR_SELECTION pcr_select;
  if (!pcr_parse_selections("sha1:10+sha256:all", &pcr_select, NULL)) {
    printf("pcr_parse_selections print client failed\n");
    return;
  }
  pcr_print_(&pcr_select, &(rpl->pcrs)); 

  print_signature(&rpl->sig_size, rpl->sig);
  
  print_quoted(rpl->quoted);

  printf("DEBUG: IMA log size received: %d\n", rpl->ima_log_size);
  printf("DEBUG: IMA whole log %d\n", rpl->wholeLog);
  fflush(stdin);
}


