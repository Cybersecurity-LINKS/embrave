// Copyright (C) 2023 Fondazione LINKS 

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
static bool end = false;
static int verify_val;
static bool send_all_log = false;

static tpm_challenge_reply rpl;

static struct verifier_conf verifier_config;
static agent_list *agents = NULL;
static const uint64_t s_timeout_ms = 1500;  // Connect timeout in milliseconds

struct mg_mgr mgr_mqtt;
struct mg_connection *c_mqtt;
int id;

int load_challenge_reply(struct mg_http_message *hm, tpm_challenge_reply *rpl);
void print_data(tpm_challenge_reply *rpl);
int encode_challenge(tpm_challenge *chl, char* buff, size_t *buff_length);
void creat_attestation_thread(agent_list * agent);
int add_agent_data(agent_list * ptr);
// Load the AK path, the TLS certificate, the last PCR10 if present, 
// and the goldenvalue db path for a certain agent

/*   char *sql = "CREATE TABLE IF NOT EXISTS attesters (\
                    uuid TEXT NOT NULL,\
                    ak_pub TEXT NOT NULL,\
                    ip_addr TEXT NOT NULL,\
                    goldenvalue_database  NOT NULL,\
                    pcr10_sha256 TEXT,\
                    pcr10_sha1 TEXT,\
                    resetCount INT,\
                    byte_rcv INT,\
                    PRIMARY KEY (uuid, ak_pub)\
  );"; */

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

            /*
          {
            "uuid": "aaaaaaaaa",
            "ip_port": "aaaaaaaaa",
            "ak_pub_b64": "aaaaaaaa"
          }
      */

    char* uuid = mg_json_get_str(mm->data, "$.uuid");
      char* ak_pub = mg_json_get_str(mm->data, "$.ak_pem");
      char* ip_addr = mg_json_get_str(mm->data, "$.ip_addr");

      agent_list *last_ptr = agents;

      last_ptr = agent_list_last(last_ptr);
      
      last_ptr = agent_list_new();
      
      /* Get attester data */
      strcpy(last_ptr->ip_addr, ip_addr);
      strcpy(last_ptr->ak_pub, ak_pub);
      strcpy(last_ptr->uuid, uuid);
      strcpy(last_ptr->gv_path, "file:/var/lemon/verifier/goldenvalues.db");
      last_ptr->running = true;

      printf("%s \n%s \n%s\n", last_ptr->uuid, last_ptr->ak_pub, last_ptr->ip_addr);

      /*add attester dato to verifier db*/
      add_agent_data(last_ptr);

      creat_attestation_thread(last_ptr);

      
    

      mg_http_reply(c, 200, NULL, "\n");

      //#endif

     

     

      free(uuid);
      free(ak_pub);
      free(ip_addr);












  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("%lu CLOSED", c->id));
    //s_conn = NULL;  // Mark that we're closed
  }
  (void) c->fn_data;
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

  char *sql = "INSERT INTO attesters values (?, ?, ?, ?, ?, ?, ?, ?);";

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
        /*SHA256*/
        rc = sqlite3_bind_null(res, 5);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
            return -1;
        }
        /*SHA1*/
        rc = sqlite3_bind_null(res, 6);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
            return -1;
        }
        /*resetCount*/
        rc = sqlite3_bind_null(res, 7);
        if (rc != SQLITE_OK ) {
            sqlite3_close(db);
            return -1;
        }
        /*byte_rcv*/
        rc = sqlite3_bind_int(res, 7, 0);
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



/* int get_agent_data(char *uuid, agent_list * ptr){
  sqlite3_stmt *res= NULL;
  sqlite3 *db = NULL;
  int byte;
  char *sql = "SELECT * FROM attesters WHERE uuid = @uuid";
  int step, idx;

  ptr->pcr10_old_sha256 = NULL;
  agent_data.pcr10_old_sha1 = NULL;
  agent_data.ak_pub = NULL;
  agent_data.gv_path = NULL;
  agent_data.tls_path = NULL;
  //agent_data.timestamp = NULL;
  agent_data.ca = NULL;
  agent_data.resetCount = 0;
  agent_data.ip_addr = NULL;

  int rc = sqlite3_open_v2(verifier_config.db, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
  if ( rc != SQLITE_OK) {
    printf("Cannot open the agent  database, error %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  //convert the sql statament
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    //Set the parametrized input
    idx = sqlite3_bind_parameter_index(res, "@uuid");
    sqlite3_bind_text(res, idx, uuid, -1, NULL);

  } else {
    fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
  }

  //Execute the sql query
  step = sqlite3_step(res);
  if (step == SQLITE_ROW) {
    //N byte entry -> malloc -> memcpy

    //ID
    agent_data.id = sqlite3_column_int(res, 0);
    
    //SHA256 of AK
    //byte = sqlite3_column_bytes(res, 1);
    //agent_data.sha_ak = malloc(byte);
    //memcpy(agent_data.sha_ak, (char *) sqlite3_column_text(res, 1), byte);

    //Ak file path
    byte = sqlite3_column_bytes(res, 2);
    agent_data.ak_pub = malloc((byte + 1) * sizeof(char));
    memcpy(agent_data.ak_pub, (char *) sqlite3_column_text(res, 2), byte);
    agent_data.ak_pub[byte] = '\0';

    //Goldenvalue db path
    byte = sqlite3_column_bytes(res, 5);
    agent_data.gv_path = malloc((byte + 1) * sizeof(char));
    memcpy(agent_data.gv_path, (char *) sqlite3_column_text(res, 5), byte);
    agent_data.gv_path[byte] = '\0';
    //printf("%s\n", agent_data.gv_path);

    //TLS cert path
    byte = sqlite3_column_bytes(res, 6);
    agent_data.tls_path = malloc((byte + 1) *sizeof(char));
    memcpy(agent_data.tls_path, (char *) sqlite3_column_text(res, 6), byte);
    agent_data.tls_path[byte] = '\0';

    //CA cert path
    byte = sqlite3_column_bytes(res, 7);
    agent_data.ca = malloc((byte + 1) *sizeof(char));
    memcpy(agent_data.ca, (char *) sqlite3_column_text(res, 7), byte);
    agent_data.ca[byte] = '\0';
    //printf("%s\n", agent_data.ca);

    //Agent ip address
    byte = sqlite3_column_bytes(res, 11);
    printf("%d\n", byte);
    if(byte == 0){
      printf("ERROR: missing ip address in the agent db");
      sqlite3_finalize(res);
      sqlite3_close(db);
    return -1;
    }
    agent_data.ip_addr = malloc((byte + 1) * sizeof(char));
    memcpy(agent_data.ip_addr, (char *) sqlite3_column_text(res, 11), byte);  
    agent_data.ip_addr[byte] = '\0';

    //PCR10s sha256, could be null
    byte = sqlite3_column_bytes(res, 3);
    if(byte != 0){
      //SHA256
      agent_data.pcr10_old_sha256 = malloc((byte + 1) * sizeof(char));
      memcpy(agent_data.pcr10_old_sha256, (char *) sqlite3_column_text(res, 3), byte);  
      agent_data.pcr10_old_sha256[byte] = '\0';
      
      //SHA1
      byte = sqlite3_column_bytes(res, 4);
      agent_data.pcr10_old_sha1 = malloc((byte + 1) * sizeof(char));
      memcpy(agent_data.pcr10_old_sha1, (char *) sqlite3_column_text(res, 4), byte);
      agent_data.pcr10_old_sha1[byte] = '\0';
    } else {
      //Possibile to have valid timestamp and no pcr10?
      send_all_log = true;
    }

    //Reset count
    agent_data.resetCount = sqlite3_column_int(res, 9);
        
    //Received bytes
    agent_data.byte_rcv = sqlite3_column_int(res, 10);

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 0;
        
  } 
  
  printf("No id found in the agent databse for uuid: %s\n", uuid);
  sqlite3_finalize(res);
  sqlite3_close(db);
  return -1;
}
 */

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
   // if(send_all_log){
      chl.send_wholeLog = 1;
    //} else {
      //chl.send_wholeLog = 0;
   // }

    //Create nonce
    if(ra_explicit_challenge_create(&chl, agent_data)!= 0){
      Continue = false;
      return;
    }

    //Encode it in json form
    if(encode_challenge(&chl, buff, &buff_length)!= 0){
      Continue = false;
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
    printf("CHALLANGE %s\n", buff);
    fflush(stdout);

  } else if (ev == MG_EV_HTTP_MSG) {
    agent_list *agent_data = (agent_list *) c->fn_data;
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    int n = load_challenge_reply(hm, &rpl);
    if(n < 0){
      end = true;
      verify_val = n;
      ra_free(&rpl, agent_data);
      return;
    } 

    //End timer 1
    //get_finish_timer();
    //print_timer(1);
    
    verify_val = ra_explicit_challenge_verify(&rpl, agent_data, verifier_config.db);

    end = true;
    ra_free(&rpl, agent_data);

    c->is_draining = 1;        // Tell mongoose to close this connection
    Continue = false;  // Tell event loop to stop
  } else if (ev == MG_EV_ERROR) {
    Continue = false;  // Error, tell event loop to stop
  }
}

// Print HTTP response and signal that we're done
static void fn_tls(struct mg_connection *c, int ev, void *ev_data) {
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

    //struct mg_tls_opts opts = {.ca = mg_str(agent_data.ca)};
   // mg_tls_init(c, &opts);

    //If PCRs10 from agent db are null, ask all ima log
    if(send_all_log){
      chl.send_wholeLog = 1;
    } else {
      chl.send_wholeLog = 0;
    }

    //Create nonce
    if(ra_explicit_challenge_create(&chl, agent_data)!= 0){
      Continue = false;
      return;
    }

    //Encode it in json form
    if(encode_challenge(&chl, buff, &buff_length)!= 0){
      Continue = false;
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
      end = true;
      verify_val = n;
      ra_free(&rpl, agent_data);
      return;
    } 

    //End timer 1
    //get_finish_timer();
    //print_timer(1);
    
    verify_val = ra_explicit_challenge_verify_TLS(&rpl, agent_data, verifier_config.db);

    end = true;
    ra_free(&rpl, agent_data);

    c->is_draining = 1;        // Tell mongoose to close this connection
    Continue = false;  // Tell event loop to stop
  } else if (ev == MG_EV_ERROR) {
    Continue = false;  // Error, tell event loop to stop
  }
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

  //Read the buffer
  
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
  print_data(rpl) ;
  return 0;

}

int encode_challenge(tpm_challenge *chl, char* buff, size_t *buff_length){
  size_t sz = B64ENCODE_OUT_SAFESIZE(sizeof(tpm_challenge));

  printf("CHALLANGE %d %d\n", chl->send_wholeLog, chl->send_from_byte);
  fflush(stdout);

  *buff_length = mg_base64_encode((const unsigned char *)chl, sizeof(tpm_challenge), buff, sz);
  if(buff_length == 0){
    printf("mg_base64_encode error\n");
    return -1;
  }


  printf("buff_length %d\n", *buff_length);
  printf("buff_length %d\n", strlen(buff));
  fflush(stdout);
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
      "POST /request_join_verifier HTTP/1.1\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: %ld\r\n"
      "\r\n"
      "%s\n",
      strlen(buff),
      buff);
      fprintf(stdout, "INFO: %s\n", buff);
  } else if (ev == MG_EV_HTTP_MSG) {
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

#ifdef DEBUG
    printf("%.*s", (int) hm->message.len, hm->message.ptr);
#endif
    int status = mg_http_status(hm);
    printf("%d\n", status);
    if(status == 403){ /* forbidden */
      /*TODO ERRORI*/
      fprintf(stderr, "ERROR: join service response code is not 403 (forbidden)\n");
      c->is_draining = 1;        // Tell mongoose to close this connection
      Continue = false;  // Tell event loop to stop
      return;
    } else if (status == OK){
      
      //verifier_config.topic_id = mg_json_get_long(hm->body, "$.topic_id", -1);
      id = mg_json_get_long(hm->body, "$.topic_id", -1);

      char topic[25];
      sprintf(topic, "attest/%d", id);
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
/*  if (mg_http_match_uri(hm, API_ATTEST) && !strncmp(hm->method.ptr, POST, hm->method.len)) {
      

      

      char* uuid = mg_json_get_str(hm->body, "$.uuid");
      char* ak_pub = mg_json_get_str(hm->body, "$.ak_pem");
      char* ip_addr = mg_json_get_str(hm->body, "$.ip_addr");

      agent_list *last_ptr = agents;

      last_ptr = agent_list_last(last_ptr);
      
      last_ptr = agent_list_new();
      
      // Get attester data 
      strcpy(last_ptr->ip_addr, ip_addr);
      strcpy(last_ptr->ak_pub, ak_pub);
      strcpy(last_ptr->uuid, uuid);
      strcpy(last_ptr->gv_path, "file:/var/lemon/verifier/goldenvalues.db");
      last_ptr->running = true;

      printf("%s \n%s \n%s\n", last_ptr->uuid, last_ptr->ak_pub, last_ptr->ip_addr);

      //add attester dato to verifier db
      add_agent_data(last_ptr);

      creat_attestation_thread(last_ptr);

      
    

      mg_http_reply(c, 200, NULL, "\n");

      //#endif

     

     

      free(uuid);
      free(ak_pub);
      free(ip_addr); 
    }
    else {
      mg_http_reply(c, 500, NULL, "\n");
    }*/
  }
}

void *attest_agent(void *arg) {
  agent_list * agent = (agent_list *) arg;
  struct mg_mgr mgr;
  struct mg_connection *c;
  //char s_conn[280];
  bool continue_polling = true;
  
  mg_mgr_init(&mgr);

  //snprintf(s_conn, 280, "http://%s", agent->ip_addr);
  //printf("%s\n", agent->ip_addr);
  //fflush(stdout);
  agent->byte_rcv = 0;
  agent->pcr10_sha256 = NULL;
  while (agent->running) {
    c = mg_http_connect(&mgr, agent->ip_addr, remote_attestation, (void *) agent);
    if (c == NULL) {
      MG_ERROR(("CLIENT cant' open a connection"));
      continue;
    }
    while (continue_polling) mg_mgr_poll(&mgr, 100); //10ms
        
    printf("QUIII NO...\n");
    fflush(stdout);


    sleep(2); // 1 secondo di sleep
    
  }

  fprintf(stdout, "INFO: attestation thread stopped for agent uuid:%s\n", agent->uuid);
  fflush(stdout);
  pthread_exit(NULL);
}



void creat_attestation_thread(agent_list * agent){
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
                    pcr10_sha256 TEXT,\
                    pcr10_sha1 TEXT,\
                    resetCount INT,\
                    byte_rcv INT,\
                    PRIMARY KEY (uuid, ak_pub)\
  );";

  /*
    tls_pem_path text NOT NULL,
      ca_pem_path text NOT NULL,
  */

  int rc = sqlite3_open_v2(verifier_config.db, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
  if ( rc != SQLITE_OK) {
    printf("Cannot open or create the verifier database, error %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
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
  struct stat st = {0};

  mg_mgr_init(&mgr_mqtt);
  c_mqtt = mqtt_connect(&mgr_mqtt, mqtt_handler, "verifier");
  
  if (stat("/var/lemon", &st) == -1) {
    if(!mkdir("/var/lemon", 0711)) {
      fprintf(stdout, "INFO: /var/lemon directory successfully created\n");
    }
    else {
      fprintf(stderr, "ERROR: cannot create /var/lemon directory\n");
      exit(-1);
    }
  } 
  
  if (stat("/var/lemon/verifier", &st) == -1) {
    if(!mkdir("/var/lemon/verifier", 0711)) {
      fprintf(stdout, "INFO: /var/lemon/verifier directory successfully created\n");
    }
    else {
      fprintf(stderr, "ERROR: cannot create /var/lemon/verifier directory\n");
    }
  }

  /* read configuration from cong file */
  if(read_config(/* verifier */ 1, (void * ) &verifier_config)){
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
  printf("verifier_config->ip: %s\n", verifier_config.ip);
  printf("verifier_config->port: %d\n", verifier_config.port);
  printf("verifier_config->tls_port: %d\n", verifier_config.tls_port);
  printf("verifier_config->tls_cert: %s\n", verifier_config.tls_cert);
  printf("verifier_config->tls_key: %s\n", verifier_config.tls_key);
  printf("verifier_config->db: %s\n", verifier_config.db);
#endif

  /* Contact the join service */
  snprintf(s_conn, 280, "http://%s:%d", verifier_config.join_service_ip, verifier_config.join_service_port);
  //printf("%s\n", s_conn);
  mg_mgr_init(&mgr);

  /* request to join (receive tpm_makecredential output) */
  c = mg_http_connect(&mgr, s_conn, request_join_verifier, NULL);

  if (c == NULL) {
    MG_ERROR(("CLIENT cant' open a connection"));
    return -1;
  }

  while (Continue) mg_mgr_poll(&mgr, 1); //1ms

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
  
  printf("NONCE Received:");
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

  printf("IMA log size recived:%d\n", rpl->ima_log_size);
  printf("IMA whole log %d\n", rpl->wholeLog);
  fflush(stdin);
}


