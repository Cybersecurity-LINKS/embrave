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
static verifier_database tpa_data;

static struct verifier_conf verifier_config;
static struct agent_list *agents = NULL;

int load_challenge_reply(struct mg_http_message *hm, tpm_challenge_reply *rpl);
int try_read(struct mg_iobuf *r, size_t size, void * dst);
void print_data(tpm_challenge_reply *rpl);
int encode_challenge(tpm_challenge *chl, char* buff, size_t *buff_length);

// Load the AK path, the TLS certificate, the last PCR10 if present, 
// and the goldenvalue db path for a certain tpa
int get_paths(int id){
  sqlite3_stmt *res= NULL;
  sqlite3 *db = NULL;
  int byte;
  char *sql = "SELECT * FROM tpa WHERE id = @id";
  int step, idx;
  time_t ltime_now;
  struct tm t;
  double fresh = (double) FRESH;

  tpa_data.pcr10_old_sha256 = NULL;
  tpa_data.pcr10_old_sha1 = NULL;
  tpa_data.ak_path = NULL;
  tpa_data.gv_path = NULL;
  tpa_data.tls_path = NULL;
  tpa_data.timestamp = NULL;
  tpa_data.ca = NULL;
  tpa_data.resetCount = 0;
  tpa_data.ip_addr = NULL;

  int rc = sqlite3_open_v2(verifier_config.db, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
  if ( rc != SQLITE_OK) {
    printf("Cannot open the tpa  database, error %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  //convert the sql statament 
  rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
  if (rc == SQLITE_OK) {
    //Set the parametrized input
    idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_int(res, idx, id);

  } else {
    fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
  }
    
  //Execute the sql query
  step = sqlite3_step(res);
  if (step == SQLITE_ROW) {
    //N byte entry -> malloc -> memcpy

    //ID
    tpa_data.id = sqlite3_column_int(res, 0);
    
    //SHA256 of AK
    //byte = sqlite3_column_bytes(res, 1);
    //tpa_data.sha_ak = malloc(byte);
    //memcpy(tpa_data.sha_ak, (char *) sqlite3_column_text(res, 1), byte);

    //Ak file path
    byte = sqlite3_column_bytes(res, 2);
    tpa_data.ak_path = malloc((byte + 1) * sizeof(char));
    memcpy(tpa_data.ak_path, (char *) sqlite3_column_text(res, 2), byte);
    tpa_data.ak_path[byte] = '\0';

    //Goldenvalue db path
    byte = sqlite3_column_bytes(res, 5);
    tpa_data.gv_path = malloc((byte + 1) * sizeof(char));
    memcpy(tpa_data.gv_path, (char *) sqlite3_column_text(res, 5), byte);
    tpa_data.gv_path[byte] = '\0';
    //printf("%s\n", tpa_data.gv_path);

    //TLS cert path
    byte = sqlite3_column_bytes(res, 6);
    tpa_data.tls_path = malloc((byte + 1) *sizeof(char));
    memcpy(tpa_data.tls_path, (char *) sqlite3_column_text(res, 6), byte);
    tpa_data.tls_path[byte] = '\0';

    //CA cert path
    byte = sqlite3_column_bytes(res, 7);
    tpa_data.ca = malloc((byte + 1) *sizeof(char));
    memcpy(tpa_data.ca, (char *) sqlite3_column_text(res, 7), byte);
    tpa_data.ca[byte] = '\0';
    //printf("%s\n", tpa_data.ca);

    //Agent ip address
    byte = sqlite3_column_bytes(res, 11);
    printf("%d\n", byte);
    if(byte == 0){
      printf("ERROR: missing ip address in the tpa db");
      sqlite3_finalize(res);
      sqlite3_close(db);
    return -1;
    }
    tpa_data.ip_addr = malloc((byte + 1) * sizeof(char));
    memcpy(tpa_data.ip_addr, (char *) sqlite3_column_text(res, 11), byte);  
    tpa_data.ip_addr[byte] = '\0';

    //Timestamp, could be null    
    byte = sqlite3_column_bytes(res, 8);
    if(byte != 0){
      tpa_data.timestamp = malloc((byte + 1) *sizeof(char));
      memcpy(tpa_data.timestamp, (char *) sqlite3_column_text(res, 8), byte);
      tpa_data.timestamp[byte] = '\0';
      //printf("%s\n", tpa_data.timestamp);

      //Check if still fresh
      memset(&t, 0, sizeof t);  // set all fields to 0
      sscanf(tpa_data.timestamp,"%d %d %d %d %d %d %d", &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec, &t.tm_isdst);
      ltime_now = time(NULL);
   
      //printf("%s\n", s)
      //double x = difftime(ltime_now, mktime(&t));
      difftime(ltime_now, mktime(&t));
      
      //printf("%f\n", x);
      if(difftime(ltime_now, mktime(&t)) > fresh){
        printf("Entry too old, send all IMA log\n");
        send_all_log = true;
      } else {
        //Entry still fresh so read old pcr10
            
        //PCR10s sha256, could be null
        byte = sqlite3_column_bytes(res, 3);
        if(byte != 0){
          //SHA256
          tpa_data.pcr10_old_sha256 = malloc((byte + 1) * sizeof(char));
          memcpy(tpa_data.pcr10_old_sha256, (char *) sqlite3_column_text(res, 3), byte);  
          tpa_data.pcr10_old_sha256[byte] = '\0';
          //SHA1
          byte = sqlite3_column_bytes(res, 4);
          tpa_data.pcr10_old_sha1 = malloc((byte + 1) * sizeof(char));
          memcpy(tpa_data.pcr10_old_sha1, (char *) sqlite3_column_text(res, 4), byte);
          tpa_data.pcr10_old_sha1[byte] = '\0';
        } else {
          //Possibile to have valid timestamp and no pcr10?
          send_all_log = true;
        }

        //Reset count
        tpa_data.resetCount = sqlite3_column_int(res, 9);
        
        //Received bytes
        tpa_data.byte_rcv = sqlite3_column_int(res, 10);

      }
    } else {
      //No previus timestamp in the db
      send_all_log = true;
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 0;
        
  } 
  
  printf("No id found in the tpa databse for %d\n", id);
  sqlite3_finalize(res);
  sqlite3_close(db);
  return -1;
}

static const uint64_t s_timeout_ms = 1500;  // Connect timeout in milliseconds

// Print HTTP response and signal that we're done
static void fn(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_OPEN) {
    // Connection created. Store connect expiration time in c->data
    *(uint64_t *) c->data = mg_millis() + s_timeout_ms;
  } else if (ev == MG_EV_POLL) {
    if (mg_millis() > *(uint64_t *) c->data &&
        (c->is_connecting || c->is_resolving)) {
      mg_error(c, "Connect timeout");
    }
  } else if (ev == MG_EV_CONNECT) {
    tpm_challenge chl;
    size_t buff_length = 0;
    char buff [B64ENCODE_OUT_SAFESIZE(sizeof(tpm_challenge))];

    //If PCRs10 from tpa db are null, ask all ima log
    if(send_all_log){
      chl.send_wholeLog = 1;
    } else {
      chl.send_wholeLog = 0;
    }

    //Create nonce
    if(ra_explicit_challenge_create(&chl, &tpa_data)!= 0){
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
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    int n = load_challenge_reply(hm, &rpl);
    if(n < 0){
      end = true;
      verify_val = n;
      ra_free(&rpl, &tpa_data);
      return;
    } 

    //End timer 1
    //get_finish_timer();
    //print_timer(1);
    
    verify_val = ra_explicit_challenge_verify(&rpl, &tpa_data);

    end = true;
    ra_free(&rpl, &tpa_data);

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
    tpm_challenge chl;
    size_t buff_length = 0;
    char buff [B64ENCODE_OUT_SAFESIZE(sizeof(tpm_challenge))];

    struct mg_tls_opts opts = {.ca = mg_str(tpa_data.ca)};
    mg_tls_init(c, &opts);

    //If PCRs10 from tpa db are null, ask all ima log
    if(send_all_log){
      chl.send_wholeLog = 1;
    } else {
      chl.send_wholeLog = 0;
    }

    //Create nonce
    if(ra_explicit_challenge_create(&chl, &tpa_data)!= 0){
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
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    int n = load_challenge_reply(hm, &rpl);
    if(n < 0){
      end = true;
      verify_val = n;
      ra_free(&rpl, &tpa_data);
      return;
    } 

    //End timer 1
    //get_finish_timer();
    //print_timer(1);
    
    verify_val = ra_explicit_challenge_verify_TLS(&rpl, &tpa_data);

    end = true;
    ra_free(&rpl, &tpa_data);

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

  return 0;

}

int encode_challenge(tpm_challenge *chl, char* buff, size_t *buff_length){
  *buff_length = mg_base64_encode((const unsigned char *)chl, sizeof(tpm_challenge), buff, *buff_length);
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
      
      verifier_config.topic_id = mg_json_get_long(hm->body, "$.topic_id", -1);  

      fprintf(stdout, "INFO: Topic id: %d\n", verifier_config.topic_id);
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
    if (mg_http_match_uri(hm, API_ATTEST) && !strncmp(hm->method.ptr, POST, hm->method.len)) {
      
      //#ifdef DEBUG
      //printf("%.*s\n", (int) hm->message.len, hm->message.ptr);
      /* Read post  */
        /*
          {
            "uuid": "aaaaaaaaa",
            "ip_port": "aaaaaaaaa",
            "ak_pub_b64": "aaaaaaaa"
          }
      */

      char* uuid = mg_json_get_str(hm->body, "$.uuid");
      char* ak_pub = mg_json_get_str(hm->body, "$.ak_pem");
      char* ip_addr = mg_json_get_str(hm->body, "$.ip_addr");

      struct agent_list *ptr = agents;
      while (ptr != NULL){
        ptr = ptr->next_ptr;
      }
      
      ptr = agent_list_new();

      /* Get attester data */
      memcpy(ptr->ip_addr, ip_addr, strlen(ip_addr));
      memcpy(ptr->ak_pub, ak_pub, strlen(ak_pub));
      memcpy(ptr->uuid, uuid, strlen(uuid));

      printf("%s \n%s \n%s\n", ptr->uuid, ptr->ak_pub, ptr->ip_addr);

      /*add attester dato to verifier db*/
    

      mg_http_reply(c, 200, NULL, "\n");

      //#endif

     

     

      free(uuid);
      free(ak_pub);
      free(ip_addr);
    }
    else {
      mg_http_reply(c, 500, NULL, "\n");
    }
  }
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
                    timestamp TEXT,\
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
  struct mg_mgr mgr_mqtt;
  struct mg_connection *c;
  char s_conn[250];
  struct stat st = {0};

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

  /* setup mqtt connection */
  mg_mgr_init(&mgr_mqtt);
  mg_timer_add(&mgr_mqtt, 3000, MG_TIMER_REPEAT | MG_TIMER_RUN_NOW, timer_fn, &mgr_mqtt);

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
    mg_mgr_poll(&mgr, 1);     
    mg_mgr_poll(&mgr_mqtt, 1000);
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
  
}


