// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "mongoose.h"
#include "attester_agent.h"
#include "config_parse.h"

static bool Continue = true;
static struct attester_conf attester_config;


int load_challenge_request(struct mg_http_message *hm , tpm_challenge *chl);
int send_challenge_reply(struct mg_connection *c, tpm_challenge_reply *rpl);
void print_sent_data(tpm_challenge_reply *rpl);

int load_challenge_request(struct mg_http_message *hm , tpm_challenge *chl)
{
#ifdef debug
  printf("load challenge request\n");
  printf("%s\n", hm->body.ptr);
#endif

  mg_base64_decode(hm->body.ptr, hm->body.len, (char *) chl->nonce);
  if(chl == NULL && chl->nonce == NULL){
    printf("Transmission challenge data error \n");
    return -1;
  }

#ifdef debug
  printf("NONCE Received:");
  for(int i= 0; i< (int) NONCE_SIZE; i++)
    printf("%02X", chl->nonce[i]);
  printf("\n");
  printf("Send all IMA LOG? %d\n", chl->send_wholeLog);
#endif

  return 0;
} 


int send_challenge_reply(struct mg_connection *c, tpm_challenge_reply *rpl)
{
  char * byte_buff;
  char * b64_buff;
  size_t total_sz = 0, i = 0;
  int n;

  //Total size to send
  total_sz = sizeof(UINT16) + rpl->sig_size + (NONCE_SIZE * sizeof(uint8_t)) 
          + sizeof(UINT16) + rpl->quoted->size + sizeof(uint32_t) 
          + sizeof(rpl->pcrs.pcr_values) + sizeof(uint32_t) 
          + rpl->ima_log_size + sizeof(uint8_t);

  //Allocate byte buffer
  byte_buff = malloc(total_sz);
  if(byte_buff == NULL) return -1;

  //Allocate buffer for encoded b64 buffer
  b64_buff = malloc(B64ENCODE_OUT_SAFESIZE(total_sz));
  if(b64_buff == NULL) {
    free(byte_buff);
    return -1;
  }

  //Copy all data in the buffer

  //Signature
  memcpy(byte_buff , &rpl->sig_size,  sizeof(UINT16));
  i += sizeof(UINT16);
  
  memcpy(byte_buff + i, rpl->sig,  rpl->sig_size);
  i += rpl->sig_size;

  //Nonce
  memcpy(byte_buff + i, &rpl->nonce, NONCE_SIZE * sizeof(uint8_t));
  i += NONCE_SIZE * sizeof(uint8_t);

  //Data quoted
  memcpy(byte_buff + i, &rpl->quoted->size, sizeof(UINT16));
  i += sizeof(UINT16);
  memcpy(byte_buff + i, &rpl->quoted->attestationData, rpl->quoted->size);
  i += rpl->quoted->size;

  //Pcr
  memcpy(byte_buff + i, &rpl->pcrs.count, sizeof(uint32_t));
  i += sizeof(uint32_t);
  memcpy(byte_buff + i, &rpl->pcrs.pcr_values, sizeof(rpl->pcrs.pcr_values));
  i += sizeof(rpl->pcrs.pcr_values);

  //IMA Log
  memcpy(byte_buff + i, &rpl->ima_log_size, sizeof(uint32_t));
  i += sizeof(uint32_t);
  if(rpl->ima_log_size != 0){
    memcpy(byte_buff + i, rpl->ima_log, rpl->ima_log_size);
    i += rpl->ima_log_size;
    memcpy(byte_buff + i, &rpl->wholeLog, sizeof(uint8_t));
    i += sizeof(uint8_t);
    
  }

  //Encode in b64
  n = mg_base64_encode((const unsigned char *)byte_buff, total_sz, b64_buff);
  if(n == 0){
    printf("mg_base64_encode error\n");
    return -1;
  }

  //Send http reply OK
  mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "%s\n", b64_buff);

  free(byte_buff);
  free(b64_buff);

#ifdef  debug
  print_sent_data(rpl);
#endif     

  return 0;
}

void print_sent_data(tpm_challenge_reply *rpl){
  printf("NONCE:");
  for(int i= 0; i< (int) NONCE_SIZE; i++)
    printf("%02X", rpl->nonce[i]);
  printf("\n");

  TPML_PCR_SELECTION pcr_select;
  if (!pcr_parse_selections("sha1:10+sha256:all", &pcr_select, NULL)) {
    printf("pcr_parse_selections print server failed\n");
    return;
  }
  pcr_print_(&pcr_select, &(rpl->pcrs)); 

  print_signature(&rpl->sig_size, rpl->sig);
  
  print_quoted(rpl->quoted);
  
  printf("IMA log size sent:%d\n", rpl->ima_log_size);
  printf("IMA whole log size sent:%d\n", rpl->wholeLog);
}

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (mg_http_match_uri(hm, API_QUOTE)) {
      tpm_challenge chl;
      tpm_challenge_reply rpl;
    
      //load challenge data from http body
      if(load_challenge_request(hm, &chl) != 0){
        printf("Load challenge error\n");
        c->is_closing = 1;
        Continue = false;
        return;
      }

      //Compute the challenge
      if ((tpa_explicit_challenge(&chl, &rpl)) != 0){
        printf("Explicit challenge error\n");
        c->is_closing = 1;
        Continue = false;
        tpa_free(&rpl);
        return;
      }

      //Send the challenge reply
      if (send_challenge_reply(c, &rpl) != 0){
        printf("Send challenge reply error\n");
        c->is_closing = 1;
        Continue = false;
      }

      tpa_free(&rpl);

      } else {
        mg_http_reply(c, 500, NULL, "\n");
      }
    }
}

static void fn_tls(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if(ev == MG_EV_ACCEPT){
        struct mg_tls_opts opts = {
        .cert = attester_config.tls_cert,
        .certkey = attester_config.tls_key
    };
    mg_tls_init(c, &opts);
  }
  else if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (mg_http_match_uri(hm, API_QUOTE)) {
      tpm_challenge chl;
      tpm_challenge_reply rpl;
    
      //load challenge data from http body
      if(load_challenge_request(hm, &chl) != 0){
        printf("Load challenge error\n");
        c->is_closing = 1;
        Continue = false;
        return;
      }

      //Compute the challenge
      if ((tpa_explicit_challenge(&chl, &rpl)) != 0){
        printf("Explicit challenge error\n");
        c->is_closing = 1;
        Continue = false;
        tpa_free(&rpl);
        return;
      }

      //Send the challenge reply
      if (send_challenge_reply(c, &rpl) != 0){
        printf("Send challenge reply error\n");
        c->is_closing = 1;
        Continue = false;
      }

      tpa_free(&rpl);

      } else {
        mg_http_reply(c, 500, NULL, "\n");
      }
    }
}

static const uint64_t s_timeout_ms = 1500;  // Connect timeout in milliseconds

/* Print HTTP response and signal that we're done
   set the value of the ip address of the CA (fn_data)*/
static void get_join_service(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_OPEN) {
    // Connection created. Store connect expiration time in c->data
    *(uint64_t *) c->data = mg_millis() + s_timeout_ms;
  } else if (ev == MG_EV_POLL) {
    if (mg_millis() > *(uint64_t *) c->data &&
        (c->is_connecting || c->is_resolving)) {
      mg_error(c, "Connect timeout");
    }
  } else if (ev == MG_EV_CONNECT) {
    //size_t buff_length = 0;
    //char buff [B64ENCODE_OUT_SAFESIZE(sizeof(tpm_challenge))];
    
    /* Send request */
    mg_printf(c,
      "GET /join HTTP/1.1\r\n"
      "\r\n"
    );

  } else if (ev == MG_EV_HTTP_MSG) {
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    //char response_body[1024];
    //memcpy((void *) response_body, (void *) hm->body.ptr, hm->body.len);

    int ip_len = 0;
    char **ca_ip_addr = (char **) fn_data;
    //*ca_ip_addr = (char *) malloc(ip_len + 1);

    //mg_json_get(hm->body, "$.ca_ip_addr", &ip_len);
    //printf("ip_len = %d\n", ip_len);
    //memcpy((void *) *ca_ip_addr, (void *) (hm->body, "$.ca_ip_addr"), ip_len);
    //(*ca_ip_addr)[ip_len] = '\0';
    *ca_ip_addr = mg_json_get_str(hm->body, "$.ca_ip_addr");
    //printf("ip_addr = %s\n", (char *) *ca_ip_addr);

    //free(ca_ip_addr);
    
    //response_body[hm->body.len] = '\0';
    //fprintf(stdout, "%s\n", response_body);

    c->is_draining = 1;        // Tell mongoose to close this connection
    Continue = false;  // Tell event loop to stop
  } else if (ev == MG_EV_ERROR) {
    Continue = false;  // Error, tell event loop to stop
  }
}

static int join_procedure(){
  struct mg_mgr mgr;  // Event manager
  struct mg_connection *c;
  char s_conn[250];
  char *ca_ip_addr;

  /* Contact the join service */
  snprintf(s_conn, 250, "%s:%d/%s", "http://localhost", 8000, "join");
  //printf("%s\n", s_conn);
  mg_mgr_init(&mgr);

  c = mg_http_connect(&mgr, s_conn, get_join_service, (void *) &ca_ip_addr);

  if (c == NULL) {
    MG_ERROR(("CLIENT cant' open a connection"));
    return 0;
  }

  while (Continue) mg_mgr_poll(&mgr, 1); //1ms

  printf("ca_ip_addr = %s\n", ca_ip_addr);

  

  return 0;
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;  /* Event manager */
  struct mg_connection *c;
  struct mg_connection *c_tls;
  char s_conn[500];
  char s_conn_tls[500];
  int a;

  /* read configuration from cong file */
  if(read_config(/* attester */ 0, (void * ) &attester_config)){
    int err = errno;
    fprintf(stderr, "ERROR: could not read configuration file\n");
    exit(err);
  }
  
  #ifdef VERBOSE
  printf("attester_config->ip: %s\n", attester_config.ip);
  printf("attester_config->port: %d\n", attester_config.port);
  printf("attester_config->tls_port: %d\n", attester_config.tls_port);
  printf("attester_config->tls_cert: %s\n", attester_config.tls_cert);
  printf("attester_config->tls_key: %s\n", attester_config.tls_key);
  #endif

  /* Check TPM keys and extend PCR9 */
  if((a = attester_init(&attester_config)) != 0) return -1;

  /* Perform the join procedure */
  join_procedure();

  mg_log_set(MG_LL_INFO);  /* Set log level */
  mg_mgr_init(&mgr);        /* Initialize event manager */

  snprintf(s_conn, 500, "http://%s:%d", attester_config.ip, attester_config.port);
  snprintf(s_conn_tls, 500, "https://%s:%d", attester_config.ip, attester_config.tls_port);

  c = mg_http_listen(&mgr, s_conn, fn, &mgr);  /* Create server connection */

  if (c == NULL) {
    MG_INFO(("SERVER cant' open a connection"));
    return 0;
  }

  /* Or TLS server */ /* Create server connection */

  c_tls = mg_http_listen(&mgr, s_conn_tls, fn_tls, NULL); 
  if (c_tls == NULL) {
    MG_INFO(("SERVER cant' open a connection"));
    return 0;
  } 

  fprintf(stdout, "Server listen to %s without TLS and to %s with TLS\n", s_conn, s_conn_tls);

  Continue = true;

  while (Continue)
    mg_mgr_poll(&mgr, 1);     /* Infinite event loop, blocks for upto 1ms
                              unless there is network activity */
  mg_mgr_free(&mgr);         /* Free resources */
  return 0;
}

