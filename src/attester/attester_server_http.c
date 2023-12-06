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
/* 
// SERVER event handler
static void event_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_OPEN && c->is_listening == 1) {
    MG_INFO(("SERVER is listening"));
  } else if (ev == MG_EV_ACCEPT) {
    MG_INFO(("SERVER accepted a connection"));
  } else if (ev == MG_EV_READ) {
    //Challenge Tag arrived to the TPA
    struct mg_iobuf *r = &c->recv;
    //int tag;
    tpm_challenge chl;
    tpm_challenge_reply rpl;

    //Read Tag
    //memcpy(&tag, r->buf, sizeof(int));
    //mg_iobuf_del(r,0,sizeof(int)); //remove tag from buffer
    
    //load challenge data from socket
    load_challenge_request(c,r,&chl);
      
    //Compute the challenge
    if ((tpa_explicit_challenge(&chl, &rpl)) != 0){
      printf("Explicit challenge error\n");
      c->is_closing = 1;
      Continue = false;
      tpa_free(&rpl);
      return;
    }
    //Send the challenge reply
    if (send_challenge_reply(c, r, &rpl) != 0){
      printf("Send challenge reply error\n");
      c->is_closing = 1;
      Continue = false;
    }

    tpa_free(&rpl);
    //mg_send(c, r->buf, r->len);  // echo it back
                     // Tell Mongoose we've consumed data
  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("SERVER disconnected"));
  } else if (ev == MG_EV_ERROR) {
    MG_INFO(("SERVER error: %s", (char *) ev_data));
  }
  (void) fn_data;
}

// SERVER event handler with TLS
static void event_handler_tls(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_OPEN && c->is_listening == 1) {
    MG_INFO(("SERVER is listening"));
  } else if (ev == MG_EV_ACCEPT) {
    MG_INFO(("SERVER accepted a connection"));
    struct mg_tls_opts opts = {
        //.ca = "ss_ca.pem",         // Uncomment to enable two-way SSL
        .cert = attester_config.tls_cert,
        //.cert = "/home/pi/lemon/certs/server.crt",     // Certificate PEM file
        .certkey = attester_config.tls_key,
        //.certkey = "/home/pi/lemon/certs/server.key",  // This pem contains both cert and key
    };
    mg_tls_init(c, &opts);
    MG_INFO(("SERVER initialized TLS"));
  } else if (ev == MG_EV_READ) {
    //Challenge Tag arrived to the TPA
    struct mg_iobuf *r = &c->recv;
    //int tag;
    tpm_challenge chl;
    tpm_challenge_reply rpl;

    //Read Tag
    //memcpy(&tag, r->buf, sizeof(int));
    //mg_iobuf_del(r,0,sizeof(int)); //remove tag from buffer

    //load challenge data from socket
    load_challenge_request(c,r,&chl);
      
    //Compute the challenge
    if ((tpa_explicit_challenge(&chl, &rpl)) != 0){
      printf("Explicit challenge error\n");
      c->is_closing = 1;
      Continue = false;
      tpa_free(&rpl);
      return;
      }

    //Send the challenge reply
    if (send_challenge_reply(c, r, &rpl) != 0){
      printf("Send challenge reply error\n");
      c->is_closing = 1;
      Continue = false;
    }
    tpa_free(&rpl);

    //mg_send(c, r->buf, r->len);  // echo it back
                     // Tell Mongoose we've consumed data
  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("SERVER disconnected"));
  } else if (ev == MG_EV_ERROR) {
    MG_INFO(("SERVER error: %s", (char *) ev_data));
  }
  (void) fn_data;
} */


/* int load_challenge_request(struct mg_connection *c,struct mg_iobuf *r, tpm_challenge *chl)
{
  //chl = (tpm_challenge *) r->buf;
  memcpy(chl, r->buf, sizeof(tpm_challenge));
  mg_iobuf_del(r,0,sizeof(tpm_challenge));
  if(chl == NULL && chl->nonce_blob.buffer == NULL && chl->nonce_blob.size != NONCE_SIZE){
    printf("Transmission challenge data error \n");
    return -1;
  }

#ifdef debug
  printf("NONCE Received:");
  for(int i= 0; i< (int) chl->nonce_blob.size; i++)
    printf("%02X", chl->nonce_blob.buffer[i]);
  printf("\n");
  printf("Send all IMA LOG? %d\n", chl->send_wholeLog);
#endif
  return 0;
} */

int load_challenge_request(struct mg_http_message *hm , tpm_challenge *chl)
{
  char buff[250];
  char * tmp;
 // struct mg_str *json = mg_str(hm->body);;

  printf("load_challenge_request\n");
  printf("%s\n", hm->body.ptr);

  tmp = mg_json_get_str(hm->body, "$.challenge");
  if(tmp == NULL){
    printf("mg_json_get_str error \n");
    return -1;
  }

  printf("%s\n", tmp);
  
  mg_base64_decode(tmp, strlen(tmp), (char *) chl->nonce);
  if(chl == NULL && chl->nonce == NULL){
    printf("Transmission challenge data error \n");
    return -1;
  }

//#ifdef debug
  printf("NONCE Received:");
  for(int i= 0; i< (int) NONCE_SIZE; i++)
    printf("%02X", chl->nonce[i]);
  printf("\n");
  printf("Send all IMA LOG? %d\n", chl->send_wholeLog);
//#endif
  return 0;
} 


int send_challenge_reply(struct mg_connection *c, tpm_challenge_reply *rpl)
{
  char * byte_buff;
  char * b64_buff;
  size_t total_sz = 0, i = 0;
  
  print_sent_data(rpl);

  total_sz = sizeof(UINT16) + rpl->sig_size + (NONCE_SIZE * sizeof(uint8_t)) 
          + sizeof(UINT16) + rpl->quoted->size + sizeof(uint32_t) 
          + sizeof(rpl->pcrs.pcr_values) + sizeof(uint32_t) 
          + rpl->ima_log_size + sizeof(uint8_t);

  printf("%d\n", total_sz );

  byte_buff = malloc(total_sz);
  if(byte_buff == NULL) return -1;

  b64_buff = malloc(B64ENCODE_OUT_SAFESIZE(total_sz));
  if(b64_buff == NULL) {
    free(byte_buff);
    return -1;
  }
  //Copy all data in the buffer

  //Signature
  memcpy(byte_buff + i, &rpl->sig_size,  sizeof(UINT16));
  i += sizeof(UINT16);

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
  printf("sz %d %d\n", total_sz, i );




  //memcpy buff

  //encode b64

  //create json
  //char *json = mg_mprintf("{%m:%s}", MG_ESC("challenge_reply"), buff);

  //send http reply OK
  //mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", json);
  
  //free(json);

  free(byte_buff);
  free(b64_buff);





  

    
#ifdef  DEBUG
  print_sent_data(rpl);
#endif     
  

  return 0;
}

void print_sent_data(tpm_challenge_reply *rpl){
  printf("NONCE:");
  for(int i= 0; i< (int) NONCE_SIZE; i++)
    printf("%02X", rpl->nonce);
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


       // double num1, num2;
       // if (mg_json_get_num(hm->body, "$[0]", &num1) &&
       //     mg_json_get_num(hm->body, "$[1]", &num2)) {
            // Success! create JSON response
       //     mg_http_reply(c, OK, APPLICATION_JSON,
          //              "{%m:%g}\n",
         //               mg_print_esc, 0, "result", num1 + num2);
         //   MG_INFO(("%s %s %d", GET, API_QUOTE, OK));
       // } else {
        //    mg_http_reply(c, 500, NULL, "Parameters missing\n");
        //}
      } else {
        mg_http_reply(c, 500, NULL, "\n");
      }
    }
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

  mg_log_set(MG_LL_INFO);  /* Set log level */
  mg_mgr_init(&mgr);        /* Initialize event manager */

  snprintf(s_conn, 500, "tcp://%s:%d", attester_config.ip, attester_config.port);
  snprintf(s_conn_tls, 500, "tcp://%s:%d", attester_config.ip, attester_config.tls_port);

  c = mg_http_listen(&mgr, s_conn, fn, &mgr);  /* Create server connection */

  if (c == NULL) {
    MG_INFO(("SERVER cant' open a connection"));
    return 0;
  }

  /* Or TLS server */ /* Create server connection */

/*   c_tls = mg_http_listen(&mgr, s_conn_tls, event_handler_tls, NULL); 
  if (c_tls == NULL) {
    MG_INFO(("SERVER cant' open a connection"));
    return 0;
  } */

  fprintf(stdout, "Server listen to %s without TLS and to %s with TLS\n", s_conn, s_conn_tls);

  while (Continue)
    mg_mgr_poll(&mgr, 1);     /* Infinite event loop, blocks for upto 1ms
                              unless there is network activity */
  mg_mgr_free(&mgr);         /* Free resources */
  return 0;
}

