// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "mongoose.h"
#include "RA.h"
#include "config_parse.h"
#include "common.h"
// client resources
static struct c_res_s {
  int i;
  //struct mg_connection *c;
} c_res;

static bool Continue = true;
static size_t last_read = 0;
static size_t to_read = 0;
static bool end = false;
static int error_val;
static bool send_all_log = false;
static char* temp_buff = NULL;
static int last_rcv = 0;
static tpm_challenge_reply rpl;
static Tpa_data tpa_data;

static struct verifier_conf verifier_config;


int load_challenge_reply( struct mg_iobuf *r, tpm_challenge_reply *rpl);
int try_read(struct mg_iobuf *r, size_t size, void * dst);
void print_data(tpm_challenge_reply *rpl);
int encode_challenge(tpm_challenge *chl, struct mg_str *json);
/* static void explicit_ra(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  int *i = &((struct c_res_s *) fn_data)->i;
  if (ev == MG_EV_OPEN) {
    MG_INFO(("CLIENT has been initialized"));
  } else if (ev == MG_EV_CONNECT) {
    MG_INFO(("CLIENT connected"));
    *i= *i+1;  // do something
  } else if (ev == MG_EV_READ) {
    //printf("Client received data\n");
    int n = 0;
    struct mg_iobuf *r = &c->recv;
    n = load_challenge_reply(r, &rpl);
    if(n < 0){
      r->len = 0;
      end = true;
      error_val = n;
      RA_free(&rpl, &tpa_data);
      return;
    } //waitng for more data from TPA
    else if(n == 1) return;
    

    //End timer 1
    //get_finish_timer();
    //print_timer(1);

    error_val = RA_explicit_challenge_verify(&rpl, &tpa_data);

    r->len = 0;
    end = true;
    RA_free(&rpl, &tpa_data);
  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("CLIENT disconnected"));

    // signal we are done
    //((struct c_res_s *) fn_data)->c = NULL;
    Continue = false;
  } else if (ev == MG_EV_ERROR) {
    MG_INFO(("CLIENT error: %s", (char *) ev_data));
    Continue = false;
  } else if (ev == MG_EV_POLL && *i == 1) {//CHALLENGE CREATE
    //int tag = 0;
    tpm_challenge chl;

    //If PCR10 are empty from tpa db, make tpa send all ima log
    if(send_all_log){
      chl.send_wholeLog = 1;
    } else {
      chl.send_wholeLog = 0;
    }

    //Create nonce
    if(RA_explicit_challenge_create(&chl, &tpa_data)!= 0){
      Continue = false;
      return;
    }

    //Send Explict tag
    //mg_send(c, &tag, sizeof(int));

    //Send nonce
    mg_send(c, &chl, sizeof(tpm_challenge));
    //printf("CLIENT sent data\n");
    *i= *i+1;
  }else if (end){
      c->is_draining = 1;
      Continue = false;
    }
}

static void explicit_ra_TLS(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  int *i = &((struct c_res_s *) fn_data)->i;
  if (ev == MG_EV_OPEN) {
    MG_INFO(("CLIENT has been initialized"));
  } else if (ev == MG_EV_CONNECT) {
    MG_INFO(("CLIENT connected"));

    struct mg_tls_opts opts = {.ca = tpa_data.ca};
    mg_tls_init(c, &opts);
    MG_INFO(("CLIENT initialized TLS"));
    *i= *i+1;  // do something
  } else if (ev == MG_EV_READ) {
    //printf("Client received data\n");
    int n = 0;
    
    struct mg_iobuf *r = &c->recv;
    n = load_challenge_reply(r, &rpl);
    if(n < 0){
      r->len = 0;
      end = true;
      error_val = n;
      RA_free(&rpl, &tpa_data);
      return;
    } //waitng for more data from TPA
    else if(n == 1) return;
    

    //End timer 1
    //get_finish_timer();
    //print_timer(1);
    
    error_val = RA_explicit_challenge_verify_TLS(&rpl, &tpa_data);

    r->len = 0;
    end = true;
    RA_free(&rpl, &tpa_data);
  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("CLIENT disconnected"));

    // signal we are done
    //((struct c_res_s *) fn_data)->c = NULL;
    Continue = false;
  } else if (ev == MG_EV_ERROR) {
    MG_INFO(("CLIENT error: %s", (char *) ev_data));
    Continue = false;
  } else if (ev == MG_EV_POLL && *i == 1) {//CHALLENGE CREATE
    //int tag = 0;
    tpm_challenge chl;
    
    //If PCR10 are empty from tpa db, make tpa send all ima log
    if(send_all_log){
      chl.send_wholeLog = 1;
    } else {
      chl.send_wholeLog = 0;
    }
    
    //Create nonce
    if(RA_explicit_challenge_create(&chl, &tpa_data)!= 0){
      Continue = false;
      return;
    }

    //Send nonce
    mg_send(c, &chl, sizeof(tpm_challenge));
    //printf("CLIENT sent data\n");
    *i= *i+1;
  }else if (end){
      c->is_draining = 1;
      Continue = false;
    }
} */

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

static const char *s_post_data = NULL;      // POST data
static const uint64_t s_timeout_ms = 1500;  // Connect timeout in milliseconds

// Print HTTP response and signal that we're done
static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_OPEN) {
    // Connection created. Store connect expiration time in c->data
    *(uint64_t *) c->data = mg_millis() + s_timeout_ms;
  } else if (ev == MG_EV_POLL) {
    if (mg_millis() > *(uint64_t *) c->data &&
        (c->is_connecting || c->is_resolving)) {
      mg_error(c, "Connect timeout");
    }
  } else if (ev == MG_EV_CONNECT) {
    char content[250];
    tpm_challenge chl;
    struct mg_str json;
    size_t json_length = 0;
    // Connected to server. Extract host name from URL
    //struct mg_str host = mg_url_host(s_url);

    //If PCRs10 from tpa db are null, ask all ima log
    if(send_all_log){
      chl.send_wholeLog = 1;
    } else {
      chl.send_wholeLog = 0;
    }

/*     if (mg_url_is_ssl(s_url)) {
      struct mg_tls_opts opts = {.ca = mg_unpacked("/certs/ca.pem"),
                                 .name = mg_url_host(s_url)};
      mg_tls_init(c, &opts);
    } */

    //Create nonce
    if(RA_explicit_challenge_create(&chl, &tpa_data)!= 0){
      Continue = false;
      return;
    }

    //Encode it in json form
    if(encode_challenge(&chl, &json)!= 0){
      Continue = false;
      return;
    }

    json_length = strlen(json.ptr);
    printf("%ld\n", json_length);
    // Send request
  
     mg_printf(c,
              "POST /api/quote HTTP/1.1\r\n"
              "Content-Type: application/json\r\n"
              "Content-Length: %ld\r\n"
              "\r\n"
              "%s\n",
              json_length,
              json.ptr
              );
    //mg_http_upload
    //mg_send(c, &json, json_length);
    //printf("%s\n", json.ptr);
    //c->is_resp = 0;

    //??
    //free(json);
  } else if (ev == MG_EV_HTTP_MSG) {
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    printf("%.*s", (int) hm->message.len, hm->message.ptr);
    c->is_draining = 1;        // Tell mongoose to close this connection
    *(bool *) fn_data = true;  // Tell event loop to stop
  } else if (ev == MG_EV_ERROR) {
    *(bool *) fn_data = true;  // Error, tell event loop to stop
  }
}

int encode_challenge(tpm_challenge *chl, struct mg_str *json){
  char buff [B64ENCODE_OUT_SAFESIZE(sizeof(tpm_challenge))];
  
  mg_base64_encode((const unsigned char *)chl, sizeof(tpm_challenge), buff);

  char *tmp = mg_mprintf("{ %m: \"%s\"}", MG_ESC("challenge"), buff);

  *json = mg_str(tmp);

  printf("encoded challenge\n");
  printf("%s\n", json->ptr);
  

  return 0;

}



int main(int argc, char *argv[]) {
  struct mg_mgr mgr;  // Event manager
  struct mg_connection *c;
  char s_conn[250];
  int n, id;

  /* read configuration from cong file */
  if(read_config(/* verifier */ 1, (void * ) &verifier_config)){
    int err = errno;
    fprintf(stderr, "ERROR: could not read configuration file\n");
    exit(err);
  }

  #ifdef VERBOSE
  printf("verifier_config->ip: %s\n", verifier_config.ip);
  printf("verifier_config->port: %d\n", verifier_config.port);
  printf("verifier_config->tls_port: %d\n", verifier_config.tls_port);
  printf("verifier_config->tls_cert: %s\n", verifier_config.tls_cert);
  printf("verifier_config->tls_key: %s\n", verifier_config.tls_key);
  printf("verifier_config->db: %s\n", verifier_config.db);
  #endif

  if(argc != 3){
    printf("Not enough arguments\n");
    return -1;
  }
  //Start Timer 1
  //get_start_timer();

  id = strtol(argv[2], NULL, 10);
  if (get_paths(id) != 0){
    printf("Error from tpa.db\n");
    return -1;
  }

  n = strtol(argv[1], NULL, 10);

  if(n == 0)
    snprintf(s_conn, 250, "%s:%d", tpa_data.ip_addr, verifier_config.port);
  else if(n == 1)
    snprintf(s_conn, 250, "%s:%d", tpa_data.ip_addr, verifier_config.tls_port);
  else{
    printf("Error wrong parameters TLS: usage 0 no TLS 1 TLS\n");
    return -1;
  }
  
  mg_mgr_init(&mgr);
  c_res.i = 0;

   if(n == 0){
    //Explict RA
    c = mg_http_connect(&mgr, s_conn, fn, NULL);   
   }
   else {
    //Explict RA TLS
    //c = mg_http_connect(&mgr, s_conn, fn_TLS, NULL);
   }

  if (c == NULL) {
    MG_INFO(("CLIENT cant' open a connection"));
    return 0;
  }

  while (Continue) mg_mgr_poll(&mgr, 1); //1ms
  //printf("%d\n", error_val);//
  return error_val;
}

int load_challenge_reply(struct mg_iobuf *r, tpm_challenge_reply *rpl){

  int ret;
  if(r == NULL) return -1;
  //printf("Received %d data from socket\n", r->len);
  
  while(r->len > 0) {
    //printf("buffer len %d case %d\n", r->len, last_rcv);
    switch (last_rcv)
    {
    case 0: 
      //Signature size
      try_read(r, sizeof(UINT16),  &rpl->sig_size);
      //Signature
      rpl->sig = malloc(rpl->sig_size);
      if(rpl->sig == NULL) return -1;
      ret = try_read(r, rpl->sig_size,  rpl->sig);
      if(ret == 0) last_rcv = 1;
      else return 1;
    break;
    case 1:
      //Nonce
      ret = try_read(r, NONCE_SIZE * sizeof(uint8_t), &rpl->nonce);
      if(ret == 0) last_rcv = 2;
      else return 1;
    break;
    case 2:
      //Quoted data size
      if(rpl->quoted == NULL) rpl->quoted = malloc(sizeof(TPM2B_ATTEST ));
      ret = try_read(r, sizeof(UINT16), &rpl->quoted->size);
      if(ret == 0) last_rcv = 3;
      else return 1;
    break;
    case 3:
      //Quoted data
      ret = try_read(r, rpl->quoted->size, &rpl->quoted->attestationData);
      if(ret == 0) last_rcv = 4;
      else return 1;
    break;
    case 4:
      //PCRs count
      ret = try_read(r, sizeof(uint32_t),  &rpl->pcrs.count);
      if(ret == 0) last_rcv = 5;
      else return 1;
    break;
    case 5:
      //PCRs
      ret = try_read(r, sizeof(rpl->pcrs.pcr_values), &rpl->pcrs.pcr_values);  
      if(ret == 0) last_rcv = 6;
      else return 1;
    break;
    case 6:
      //IMA log size
      ret = try_read(r, sizeof(uint32_t), &rpl->ima_log_size);
      if (rpl->ima_log_size == 0){
        last_rcv = 0;
        return 0;
      }
      if(ret == 0) last_rcv = 7;
      else return 1;
    break;
    case 7:
      if(rpl->ima_log == NULL) rpl->ima_log = malloc(rpl->ima_log_size);
      ret = try_read(r, rpl->ima_log_size, rpl->ima_log);
      if(ret == 0) last_rcv = 8;
      else return 1;
    break;
    case 8:
      ret = try_read(r, sizeof(uint8_t), &rpl->wholeLog);
      if(ret != 0) return 1;
    break;
    default:
      break;
    }

  }

  last_rcv = 0;
  
#ifdef  DEBUG
  print_data(rpl);
#endif 
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

  /* Try reading data from the received data buffer. 
  If the buffer does not contain all of it, it saves the data in
  a temporary buffer and on the next read cycle reads the remaining 
  0 full read 1 remaining data to wait -1 error*/
int try_read(struct mg_iobuf *r, size_t size, void * dst)
{
  //printf("size to read %d, to_read %d last read %d r->len %d\n",size, to_read, last_read, r->len);
  if(to_read == 0){
    if(r->len >= size){
        //no segmentation
        memcpy(dst, r->buf, size);
        mg_iobuf_del(r,0, size);
        return 0;
    }
    else{
      //alloc the buffer if needed
      if(temp_buff == NULL){
        temp_buff = malloc(size);
      }
      //read the available data and save in the buffer
      to_read = (size - r->len);
      last_read = r->len;
      memcpy(temp_buff, r->buf, r->len);
      mg_iobuf_del(r,0, r->len);
      return 1;
    }
  }
  //in the buffere there is the remaining data
  if(to_read <= r->len){
    memcpy(dst, temp_buff, last_read);
    memcpy(dst + last_read,  r->buf, to_read);
    mg_iobuf_del(r,0, to_read);
    to_read = 0;
    last_read = 0;
    free(temp_buff);
    temp_buff = NULL;
    return 0;
  } else{
    memcpy(temp_buff + last_read, r->buf, r->len);
    to_read = (to_read - r->len);
    last_read = last_read + r->len;
    mg_iobuf_del(r,0, r->len);
    return 1;
  }
  
  return 0;
}