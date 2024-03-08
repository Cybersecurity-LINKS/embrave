// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include "mongoose.h"
#include "attester_agent.h"
#include "config_parse.h"
#include "join_service.h"

struct mkcred_out {
  unsigned char *value;
  unsigned int len;
};

static bool Continue = true;
static const uint64_t s_timeout_ms = 1500;  // Connect timeout in milliseconds

int load_challenge_request(struct mg_http_message *hm , tpm_challenge *chl);
int send_challenge_reply(struct mg_connection *c, tpm_challenge_reply *rpl);
void print_sent_data(tpm_challenge_reply *rpl);

int load_challenge_request(struct mg_http_message *hm , tpm_challenge *chl)
{
#ifdef DEBUG
  printf("load challenge request\n");
  printf("%s\n", hm->body.ptr);
  printf("%d\n", hm->body.len);
#endif
  size_t dec = B64DECODE_OUT_SAFESIZE(hm->body.len);

  size_t sz = mg_base64_decode(hm->body.ptr, hm->body.len,(char *) chl, dec);
  if(sz == 0){
    printf("Transmission challenge data error \n");
    return -1;
  }

#ifdef DEBUG
  printf("NONCE Received:");
  for(int i= 0; i< (int) NONCE_SIZE; i++)
    printf("%02X", chl->nonce[i]);
  printf("\n");
  printf("send all IMA LOG? %d\n", chl->send_wholeLog);
  printf("from byte %d\n", chl->send_from_byte);
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
  n = mg_base64_encode((const unsigned char *)byte_buff, total_sz, b64_buff, B64ENCODE_OUT_SAFESIZE(total_sz));
  if(n == 0){
    printf("ERROR: mg_base64_encode error\n");
    return -1;
  }

  //Send http reply OK
  mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "%s\n", b64_buff);

  free(byte_buff);
  free(b64_buff);

#ifdef DEBUG
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

static void fn(struct mg_connection *c, int ev, void *ev_data) {
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
      if ((tpm_challenge_create(&chl, &rpl)) != 0){
        printf("Explicit challenge error\n");
        c->is_closing = 1;
        Continue = false;
        tpm_challenge_free(&rpl);
        return;
      }

      //Send the challenge reply
      if (send_challenge_reply(c, &rpl) != 0){
        printf("Send challenge reply error\n");
        c->is_closing = 1;
        Continue = false;
      }

      tpm_challenge_free(&rpl);

      } else {
        mg_http_reply(c, 500, NULL, "\n");
      }
    }
}

int create_request_body(size_t *object_length, char *object){
  long size;
  struct stat st;
  size_t ret, tot_sz = 0;
  int fd, n;
  unsigned char *ek_cert = NULL, *ak_pub = NULL, *ak_name = NULL;
  char *b64_buff_ek = NULL, *ak_name_b64 = NULL;
  char buff[500];

  /* Read EK certificate */
  FILE *fd_ek_cert = fopen(attester_config.ek_ecc_cert, "r");
  if(fd_ek_cert == NULL){
    fprintf(stdout, "INFO: EK ECC certificate not present, looking for RSA certificate\n");
    fd_ek_cert = fopen(attester_config.ek_rsa_cert, "r");
    if(fd_ek_cert == NULL){
      fprintf(stderr, "ERROR: EK RSA certificate not found\n");
      return -1;
    }
  }

  fd = fileno(fd_ek_cert);
  fstat(fd, &st);
  size = st.st_size;

  ek_cert = (unsigned char *) malloc(size);
  if(ek_cert == NULL){
    fprintf(stderr, "ERROR: cannot allocate ek_cert buffer for certificate request\n");
    fclose(fd_ek_cert);
    return -1;
  }

  //printf("EK cert size: %ld\n", size);

  ret = fread(ek_cert, 1, (size_t) size, fd_ek_cert);
  if(ret != size){
    fclose(fd_ek_cert);
    free(ek_cert);
    fprintf(stderr, "ERROR: cannot read the whole EK certificate. %ld/%ld bytes read\n", ret, size);
    return -1;
  }

  fclose(fd_ek_cert);

  //Encode in b64
  //Allocate buffer for encoded b64 buffer
  tot_sz = B64ENCODE_OUT_SAFESIZE(size);
  b64_buff_ek = malloc(tot_sz);
  if(b64_buff_ek == NULL) {
    fprintf(stderr, "ERROR: b64_buff malloc error\n");
    free(ek_cert);
    return -1;
  }

  n = mg_base64_encode((const unsigned char *)ek_cert, size, b64_buff_ek, tot_sz);
  if(n == 0){
    fprintf(stderr, "ERROR: mg_base64_encode error\n");
    free(ek_cert);
    free(b64_buff_ek);
    return -1;
  }
#ifdef DEBUG
  fprintf(stdout, "INFO: EK cert base64: %s\n", b64_buff_ek);
#endif
  free(ek_cert);

  /* Read AK pub key */
  FILE *fd_ak_pub = fopen(attester_config.ak_pub, "r");
  if(fd_ak_pub == NULL){
    fprintf(stderr, "ERROR: AK pub key pem not present\n");
    free(b64_buff_ek);
    return -1;
  }

  fd = fileno(fd_ak_pub);
  fstat(fd, &st);
  size = st.st_size;

  ak_pub = (unsigned char *) malloc(size + 1); /* add +1 for '\0' */
  if(ak_pub == NULL){
    fprintf(stderr, "ERROR: cannot allocate ak_pub buffer\n");
    free(b64_buff_ek);
    fclose(fd_ak_pub);
    return -1;
  }
#ifdef DEBUG
  fprintf(stdout, "INFO: AK pem size: %ld\n", size);
#endif
  ret = fread(ak_pub, 1, (size_t) size, fd_ak_pub);
  ak_pub[size] = '\0';
  if(ret != size){
    free(b64_buff_ek);
    fclose(fd_ak_pub);
    free(ak_pub);
    fprintf(stderr, "ERROR: cannot read the whole AK pem. %ld/%ld bytes read\n", ret, size);
    return -1;
  }

  fclose(fd_ak_pub);
#ifdef DEBUG
  fprintf(stdout, "INFO: AK pem \n%s\n", ak_pub);
#endif
  tot_sz += size;
  //Encode in b64
  //Allocate buffer for encoded b64 buffer

  /* Read AK name */
  FILE *fd_ak_name = fopen(attester_config.ak_name, "r");
  if(fd_ak_name == NULL){
    fprintf(stderr, "ERROR: EK RSA certificate not found\n");
    return -1;
  }

  fd = fileno(fd_ak_name);
  fstat(fd, &st);
  size = st.st_size;

  ak_name = (unsigned char *) malloc(size);
  if(ak_name == NULL){
    fprintf(stderr, "ERROR: cannot allocate ak_name buffer\n");
    fclose(fd_ak_name);
    return -1;
  }

  ret = fread(ak_name, 1, (size_t) size, fd_ak_name);
  if(ret != size){
    fclose(fd_ak_name);
    free(ak_name);
    fprintf(stderr, "ERROR: cannot read the whole AK name. %ld/%ld bytes read\n", ret, size);
    return -1;
  }

  fclose(fd_ak_name);

  size_t size_b64 = B64ENCODE_OUT_SAFESIZE(size);
  ak_name_b64 = malloc(size_b64);
  if(ak_name_b64 == NULL) {
    fprintf(stderr, "ERROR: ak_name_b64 malloc error\n");
    free(ak_name);
    return -1;
  }

  n = mg_base64_encode((const unsigned char *)ak_name, size, ak_name_b64, size_b64);
  if(n == 0){
    fprintf(stderr, "ERROR: mg_base64_encode error\n");
    free(ak_name);
    free(ak_name_b64);
    return -1;
  }

  free(ak_name);
  tot_sz += size_b64;

  if(object == NULL) {
    fprintf(stderr, "ERROR: object buff is NULL\n");
    free(b64_buff_ek);
    return -1;
  }

  snprintf(buff, 500, "http://%s:%d", attester_config.ip, attester_config.port);

  sprintf(object, "{\"uuid\":\"%s\",\"ek_cert_b64\":\"%s\",\"ak_pub_b64\":\"%s\",\"ak_name_b64\":\"%s\",\"ip_addr\":\"%s\"}", attester_config.uuid, b64_buff_ek, ak_pub, ak_name_b64, buff);
  *object_length = strlen(object);

#ifdef DEBUG
  printf("Final object : %s\n", object);
#endif
  free(b64_buff_ek);
  free(ak_pub);
  free(ak_name_b64);
  return 0;
}

static void request_join(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_OPEN) {
    // Connection created. Store connect expiration time in c->data
    *(uint64_t *) c->data = mg_millis() + s_timeout_ms;
  } else if (ev == MG_EV_POLL) {
    if (mg_millis() > *(uint64_t *) c->data &&
        (c->is_connecting || c->is_resolving)) {
      mg_error(c, "Connect timeout");
    }
  } else if (ev == MG_EV_CONNECT) {
    size_t object_length = 0;
    char object[4096];

    if (create_request_body(&object_length, object) != 0){
      fprintf(stderr, "ERROR: cannot create the http body contacting the join_service\n");
      exit(-1);
    }

#ifdef DEBUG
    printf("%s\n", object);
#endif

    /* Send request */
    mg_printf(c,
      "POST /api/request_join HTTP/1.1\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: %ld\r\n"
      "\r\n"
      "%s\n",
      object_length,
      object);

  } else if (ev == MG_EV_HTTP_MSG) {
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct mkcred_out *mkcred_out = (struct mkcred_out *) c->fn_data;
#ifdef DEBUG
    printf("%.*s", (int) hm->message.len, hm->message.ptr);
#endif
    int status = mg_http_status(hm);
    
    if(status == FORBIDDEN){ /* forbidden */
      fprintf(stderr, "ERROR: join service response code is not 403 (forbidden)\n");
      //mg_http_reply(c, 500, NULL, "\n");
      return;
    } else if (status == CREATED){

      unsigned char *mkcred_out_b64 = (unsigned char *) mg_json_get_str(hm->body, "$.mkcred_out");
      size_t mkcred_out_len = B64DECODE_OUT_SAFESIZE(strlen((char *) mkcred_out_b64));
      #ifdef DEBUG
      fprintf(stdout, "INFO: MKCRED_OUT b64: %s\n", mkcred_out_b64);
      fprintf(stdout, "INFO: MKCRED_OUT len:%d\n", mkcred_out_len);
      #endif
      mkcred_out->value = (unsigned char *) malloc(mkcred_out_len);
      if(mkcred_out->value == NULL) {
          fprintf(stderr, "ERROR: cannot allocate mkcred_out buffer\n");
          free(mkcred_out_b64);
          //mg_http_reply(c, 500, NULL, "\n");
          return;
      }
      mkcred_out->len = mg_base64_decode((char *) mkcred_out_b64, strlen((char *) mkcred_out_b64), (char *) mkcred_out->value, mkcred_out_len);
      //Decode b64
      if(mkcred_out->len == 0){
          fprintf(stderr, "ERROR: base64 decoding mkcred ouput received from join service.\n");
          free(mkcred_out_b64);
          //mg_http_reply(c, 500, NULL, "\n");
          return;
      }

      #ifdef DEBUG
      fprintf(stdout, "INFO: MKCRED_OUT: ");
      for(int i=0; i<mkcred_out->len; i++){
        printf("%02x", mkcred_out->value[i]);
      }
      printf("\n");
      fprintf(stdout, "INFO: MKCRED_OUT len:%d\n", mkcred_out->len); 
      fprintf(stdout, "INFO: mkcred_out received from join service.\n");
      #endif
      free(mkcred_out_b64);

      c->is_draining = 1;        // Tell mongoose to close this connection
      Continue = false;  // Tell event loop to stop

    }
  } else if (ev == MG_EV_ERROR) {
    Continue = false;  // Error, tell event loop to stop
  }
}

static void confirm_credential(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_OPEN) {
    // Connection created. Store connect expiration time in c->data
    *(uint64_t *) c->data = mg_millis() + s_timeout_ms;
  } else if (ev == MG_EV_POLL) {
    if (mg_millis() > *(uint64_t *) c->data &&
        (c->is_connecting || c->is_resolving)) {
      mg_error(c, "Connect timeout");
    }
  } else if (ev == MG_EV_CONNECT) {
    char object[4096];
    unsigned char *secret;
    unsigned char *secret_b64;
    unsigned int secret_len, secret_b64_len;
    struct mkcred_out *mkcred_out = (struct mkcred_out *) c->fn_data;
    
    int rc = attester_activatecredential(mkcred_out->value, mkcred_out->len, &secret, &secret_len);
    if (rc != 0) {
      fprintf(stderr, "ERROR: cannot activate credential\n");
      return;
    }

#ifdef DEBUG
    for(int i=0; i<secret_len; i++){
      printf("%c", secret[i]);
    }
    printf("\n");
#endif

    secret_b64_len = B64ENCODE_OUT_SAFESIZE(secret_len);
    secret_b64 = malloc(secret_b64_len+1);
    if(secret_b64 == NULL){
      fprintf(stderr, "ERROR: cannot allocate secret_b64 buffer\n");
      return;
    }

    if(mg_base64_encode((const unsigned char *)secret, secret_len, (char *) secret_b64, secret_b64_len+1) == 0){
      fprintf(stderr, "ERROR: base64 encoding secret\n");
      free(secret_b64);
      return;
    }

    /* Read AK pub key */
    FILE *fd_ak_pub = fopen(attester_config.ak_pub, "r");
    if(fd_ak_pub == NULL){
      fprintf(stderr, "ERROR: AK pub key pem not present\n");
      return;
    }

    struct stat st;
    int fd = fileno(fd_ak_pub);
    fstat(fd, &st);
    size_t size = st.st_size;

    unsigned char *ak_pub = (unsigned char *) malloc(size + 1); /* add +1 for '\0' */
    if(ak_pub == NULL){
      fprintf(stderr, "ERROR: cannot allocate ak_pub buffer\n");
      fclose(fd_ak_pub);
      return;
    }

    int ret = fread(ak_pub, 1, (size_t) size, fd_ak_pub);
    ak_pub[size] = '\0';
    if(ret != size){
      fclose(fd_ak_pub);
      free(ak_pub);
      fprintf(stderr, "ERROR: cannot read the whole AK pem. %d/%ld bytes read\n", ret, size);
      return;
    }

    fclose(fd_ak_pub);

    snprintf(object, 4096, "{\"secret_b64\":\"%s\",\"uuid\":\"%s\",\"ak_pub_b64\":\"%s\"}", secret_b64, attester_config.uuid, ak_pub);

    free(secret_b64);

    /* Send request */
    mg_printf(c,
    "POST /api/confirm_credential HTTP/1.1\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: %ld\r\n"
    "\r\n"
    "%s\n",
    strlen(object),
    object); 

  } else if (ev == MG_EV_HTTP_MSG) {
    // Response is received. Print it
#ifdef DEBUG
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    printf("%.*s", (int) hm->message.len, hm->message.ptr);
#endif
    c->is_draining = 1;        // Tell mongoose to close this connection
    Continue = false;  // Tell event loop to stop
  } else if (ev == MG_EV_ERROR) {
    Continue = false;  // Error, tell event loop to stop
  }
}

static int join_procedure(){
  struct mg_mgr mgr;  // Event manager
  struct mg_connection *c;
  char s_conn[280];
  struct mkcred_out mkcred_out;

  /* Contact the join service */
  snprintf(s_conn, 280, "http://%s:%d", attester_config.join_service_ip, attester_config.join_service_port);
  mg_mgr_init(&mgr);

  /* request to join (receive tpm_makecredential output) */
  c = mg_http_connect(&mgr, s_conn, request_join, (void *) &mkcred_out);

  if (c == NULL) {
    MG_ERROR(("CLIENT cant' open a connection"));
    return -1;
  }

  while (Continue) mg_mgr_poll(&mgr, 10); //10ms
  
  /* send back the value calculated with tpm_activatecredential */
  Continue = true;
  c = mg_http_connect(&mgr, s_conn, confirm_credential, (void *) &mkcred_out);

  if (c == NULL) {
      MG_ERROR(("CLIENT cant' open a connection"));
      return -1;
  }

  while (Continue) mg_mgr_poll(&mgr, 10); //10ms

  return 0;
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;  /* Event manager */
  struct mg_connection *c;
  char s_conn[500];
  struct stat st = {0};

  if (stat("/var/embrave", &st) == -1) {
    if(!mkdir("/var/embrave", 0711)) {
        fprintf(stdout, "INFO: /var/embrave directory successfully created\n");
      }
      else {
        fprintf(stderr, "ERROR: cannot create /var/embrave directory\n");
      }
  }

  if (stat("/var/embrave/attester", &st) == -1) {
      if(!mkdir("/var/embrave/attester", 0711)) {
        fprintf(stdout, "INFO: /var/embrave/attester directory successfully created\n");
      }
      else {
        fprintf(stderr, "ERROR: cannot create /var/embrave/attester directory\n");
      }
  }

  /* read configuration from cong file */
  if(read_config(/* attester */ 0, (void * ) &attester_config)){
    int err = errno;
    fprintf(stderr, "ERROR: could not read configuration file\n");
    exit(err);
  }
  
  #ifdef DEBUG
  printf("attester_config->ip: %s\n", attester_config.ip);
  printf("attester_config->port: %d\n", attester_config.port);
  #endif

  /* Create TPM keys*/
  if((attester_init(&attester_config)) != 0) return -1;
 
  /* Perform the join procedure */
  if (join_procedure() != 0){
    fprintf(stderr, "ERROR: could not reach the join service\n");
    exit(-1);
  };

  mg_log_set(MG_LL_INFO);  /* Set log level */
  mg_mgr_init(&mgr);        /* Initialize event manager */

  snprintf(s_conn, 500, "http://%s:%d", attester_config.ip, attester_config.port);

  c = mg_http_listen(&mgr, s_conn, fn, &mgr);  /* Create server connection */

  if (c == NULL) {
    MG_INFO(("SERVER cant' open a connection"));
    return 0;
  }

  fprintf(stdout, "INFO: Server listen to %s \n", s_conn);

  Continue = true;

  while (Continue)
    mg_mgr_poll(&mgr, 1);     /* Infinite event loop, blocks for upto 1ms
                              unless there is network activity */
  mg_mgr_free(&mgr);         /* Free resources */
  return 0;
}

