#include "../Mongoose/mongoose.h"
#include "../../Agents/TPA/TPA.h"

static bool Continue = true;


int load_challenge_request(struct mg_connection *c, struct mg_iobuf *r, Ex_challenge *chl);
int send_challenge_reply(struct mg_connection *c, struct mg_iobuf *r, Ex_challenge_reply *rpl);
void print_sent_data(Ex_challenge_reply *rpl);

// SERVER event handler
static void event_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_OPEN && c->is_listening == 1) {
    MG_INFO(("SERVER is listening"));
  } else if (ev == MG_EV_ACCEPT) {
    MG_INFO(("SERVER accepted a connection"));
  } else if (ev == MG_EV_READ) {
    //Challenge Tag arrived to the TPA
    struct mg_iobuf *r = &c->recv;
    int tag;
    Ex_challenge chl;
    Ex_challenge_reply rpl;

    //Read Tag
    memcpy(&tag, r->buf, sizeof(int));
    mg_iobuf_del(r,0,sizeof(int)); //remove tag from buffer
    
    switch (tag){
    case RA_TYPE_EXPLICIT:
      //load challenge data from socket
      load_challenge_request(c,r,&chl);
      
      //Compute the challenge
      if ((TPA_explicit_challenge(&chl, &rpl)) != 0){
        printf("Explicit challenge error\n");
        c->is_closing = 1;
        Continue = false;
        TPA_free(&rpl);
        break;
      }
      //Send the challenge reply
      if (send_challenge_reply(c, r, &rpl) != 0){
        printf("Send challenge reply error\n");
        c->is_closing = 1;
        Continue = false;
      }

      TPA_free(&rpl);
      break;
    case RA_TYPE_DAA:

      break;
    default:
      printf("Unknown tag close connection\n");
      c->is_closing = 1;
      break; 
    }
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
        .cert = "../certs/server.crt",     // Certificate PEM file
        .certkey = "../certs/server.key",  // This pem contains both cert and key
    };
    mg_tls_init(c, &opts);
    MG_INFO(("SERVER initialized TLS"));
  } else if (ev == MG_EV_READ) {
    //Challenge Tag arrived to the TPA
    struct mg_iobuf *r = &c->recv;
    int tag;
    Ex_challenge chl;
    Ex_challenge_reply rpl;

    //Read Tag
    memcpy(&tag, r->buf, sizeof(int));
    mg_iobuf_del(r,0,sizeof(int)); //remove tag from buffer

    switch (tag){
    case RA_TYPE_EXPLICIT:
      //load challenge data from socket
      load_challenge_request(c,r,&chl);
      
      //Compute the challenge
      if ((TPA_explicit_challenge(&chl, &rpl)) != 0){
        printf("Explicit challenge error\n");
        c->is_closing = 1;
        Continue = false;
        TPA_free(&rpl);
        break;
      }

      //Send the challenge reply
      if (send_challenge_reply(c, r, &rpl) != 0){
        printf("Send challenge reply error\n");
        c->is_closing = 1;
        Continue = false;
      }
      TPA_free(&rpl);
    break;
    case RA_TYPE_DAA:

    break;
    default:
      printf("Unknown tag close connection\n");
      c->is_closing = 1;
    break; 
    }
    //mg_send(c, r->buf, r->len);  // echo it back
                     // Tell Mongoose we've consumed data
  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("SERVER disconnected"));
  } else if (ev == MG_EV_ERROR) {
    MG_INFO(("SERVER error: %s", (char *) ev_data));
  }
  (void) fn_data;
}


int load_challenge_request(struct mg_connection *c,struct mg_iobuf *r, Ex_challenge *chl)
{
  //chl = (Ex_challenge *) r->buf;
  memcpy(chl, r->buf, sizeof(Ex_challenge));
  mg_iobuf_del(r,0,sizeof(Ex_challenge));
  if(chl == NULL && chl->nonce_blob.buffer == NULL && chl->nonce_blob.size != NONCE_SIZE){
    printf("Transmission challenge data error \n");
    return -1;
  }
  //printf("NONCE Received:");
  //for(int i= 0; i< (int) chl->nonce_blob.size; i++)
    //printf("%02X", chl->nonce_blob.buffer[i]);
  //printf("\n");
  //printf("r buf :%ld\n", r->len);
  return 0;
}

int send_challenge_reply(struct mg_connection *c, struct mg_iobuf *r, Ex_challenge_reply *rpl)
{
  //Signature is dynamic memory=> cant send all structure in one time
  //Signature size
  mg_send(c, &rpl->sig_size, sizeof(UINT16));

  //Signature
  mg_send(c, rpl->sig, rpl->sig_size);

  //Nonce
  mg_send(c, &rpl->nonce_blob, sizeof(Nonce));
  
  //Data quoted
  mg_send(c, &rpl->quoted->size, sizeof(UINT16));
  mg_send(c, &rpl->quoted->attestationData, rpl->quoted->size);

  //Pcr
  mg_send(c, &rpl->pcrs.count, sizeof(uint32_t)); //size_t is different beetween cpu arch, bettere send a fixed type of int and cast it
  mg_send(c, &rpl->pcrs.pcr_values, sizeof(rpl->pcrs.pcr_values));

  //IMA Log
  mg_send(c, &rpl->ima_log_size, sizeof(uint32_t));
  if(rpl->ima_log_size != 0){
    mg_send(c, rpl->ima_log, rpl->ima_log_size);
    mg_send(c, &rpl->wholeLog, sizeof(uint8_t));
  }
    
  //print_sent_data(rpl);

  return 0;
}

void print_sent_data(Ex_challenge_reply *rpl){
  printf("NONCE:");
  for(int i= 0; i< (int) rpl->nonce_blob.size; i++)
    printf("%02X", rpl->nonce_blob.buffer[i]);
  printf("\n");

  TPML_PCR_SELECTION pcr_select;
  if (!pcr_parse_selections("sha1:10+sha256:all", &pcr_select)) {
    printf("pcr_parse_selections print server failed\n");
    return;
  }
  pcr_print_(&pcr_select, &(rpl->pcrs)); 

  print_signature(&rpl->sig_size, rpl->sig);
  
  print_quoted(rpl->quoted);
  
  printf("IMA log size sent:%d\n", rpl->ima_log_size);
  printf("IMA whole log size sent:%d\n", rpl->wholeLog);
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;  // Event manager
  struct mg_connection *c;
  struct mg_connection *c1;
  int a;

  if(argc != 3){
    printf("Error wrong parameters: usage ./TPA ip_1 ip_2\n");
    return -1;
  }

  //Check TPM keys and extend PCR9
  if((a = TPA_init()) != 0) return -1;

  mg_log_set(MG_LL_INFO);  // Set log level
  mg_mgr_init(&mgr);        // Initialize event manager
  c = mg_listen(&mgr, argv[1], event_handler, NULL);  // Create server connection

  if (c == NULL) {
    MG_INFO(("SERVER cant' open a connection"));
    return 0;
  } 
  //Or TLS server
  c1 = mg_listen(&mgr, argv[2], event_handler_tls, NULL);  // Create server connection
  if (c1 == NULL) {
    MG_INFO(("SERVER cant' open a connection"));
    return 0;
  }

  fprintf(stdout, "Server listen to %s without TLS and to %s with TLS\n", argv[1], argv[2]);

  while (Continue)
    mg_mgr_poll(&mgr, 1);  // Infinite event loop, blocks for upto 1ms
                             // unless there is network activity
  mg_mgr_free(&mgr);         // Free resources
  return 0;
}

