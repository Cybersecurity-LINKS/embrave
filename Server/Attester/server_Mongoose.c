#include "../Mongoose/mongoose.h"
#include "../../Agents/TPA/TPA.h"
static const char *s_lsn = "tcp://localhost:8765";   // Listening address
static bool Continue = true;

void ex_challenge_request(struct mg_connection *c, struct mg_iobuf *r);
int ex_challenge_reply(struct mg_connection *c, struct mg_iobuf *r);

// SERVER event handler
static void sfn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_OPEN && c->is_listening == 1) {
    MG_INFO(("SERVER is listening"));
  } else if (ev == MG_EV_ACCEPT) {
    MG_INFO(("SERVER accepted a connection"));
#if MG_ENABLE_MBEDTLS || MG_ENABLE_OPENSSL
    struct mg_tls_opts opts = {
        //.ca = "ss_ca.pem",         // Uncomment to enable two-way SSL
        .cert = "ss_server.pem",     // Certificate PEM file
        .certkey = "ss_server.pem",  // This pem contains both cert and key
    };
    mg_tls_init(c, &opts);
    MG_INFO(("SERVER initialized TLS"));
#endif
  } else if (ev == MG_EV_READ) {
    struct mg_iobuf *r = &c->recv;
    int tag, n;
    memcpy(&tag, r->buf, sizeof(int));
    mg_iobuf_del(r,0,sizeof(int)); //remove tag from buffer
/*     switch (tag){
    case RA_TYPE_EXPLICIT:
      ex_challenge_request(c,r);
      n = ex_challenge_reply(c,r);
      if (n!=0){
        //TODO
        printf("ERRORE\n");
        c->is_closing = 1;
        Continue = false;
      }
      break;
    case RA_TYPE_DAA:

      break;
    default:
    //disconnect
      break; */
    //}
    //mg_send(c, r->buf, r->len);  // echo it back
                     // Tell Mongoose we've consumed data
  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("SERVER disconnected"));
  } else if (ev == MG_EV_ERROR) {
    MG_INFO(("SERVER error: %s", (char *) ev_data));
  }
  (void) fn_data;
}


/* 
//load challenge data
void ex_challenge_request(struct mg_connection *c, struct mg_iobuf *r){
  CHALLENGE_BLOB *challenge = (CHALLENGE_BLOB *) r->buf;
  MG_INFO(("NONCE :"));
  for(int i= 0; i< (int) challenge->nonce_blob.size; i++)
    printf("%02X", challenge->nonce_blob.buffer[i]);
  printf("\n");
 //MG_INFO(("PCRS :%d\n", challenge->PCR));
  r->len = 0;  
}

//
int ex_challenge_reply(struct mg_connection *c, struct mg_iobuf *r){
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  ssize_t imaLogBytesSize = 0;
  CHALLENGE_BLOB *challenge = (CHALLENGE_BLOB *) r->buf;
  uint16_t ak_handle[HANDLE_SIZE];

  TO_SEND TpaData;
  TpaData.nonce_blob.size = NONCE_SIZE;
  memcpy(TpaData.nonce_blob.buffer, challenge->nonce_blob.buffer, TpaData.nonce_blob.size);
  snprintf((char *)ak_handle, HANDLE_SIZE, "%s", "0x81000004");

  tss_r = Tss2_TctiLdr_Initialize(NULL, &tcti_context);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize tcti context\n");
    return -1;
  }
  tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize esys context\n");
    return -1;
  }
  //Bind AK cert by extendind the PCR9
  if (pcr_check_if_zeros(esys_context)) {
    tss_r = ExtendPCR9(esys_context, "sha256"); 
    if (tss_r != TSS2_RC_SUCCESS) return -1;
    MG_INFO(("PCR9 sha256 extended\n"));
  }
  
  //TODO copy pcr 0-15 

  tss_r = tpm2_quote(esys_context, &TpaData, imaLogBytesSize, ak_handle, challenge);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Error while computing quote!\n");
    return -1;
  }
  
  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  MG_INFO(("Sending challenge reply %ld\n", sizeof(TO_SEND)));
  //TODO send AK
  if(!send_AK(c, &TpaData)) {
    fprintf(stdout, "Could not send AK pub on tangle\n");
    return -1;
  }
  
  mg_send(c, &TpaData, sizeof(TO_SEND));
   
  

 // free(TpaData.ak_digest_blob.buffer);

  return 0;
}

 */


int main(void) {
  struct mg_mgr mgr;  // Event manager
  struct mg_connection *c;
  int a;
  fprintf(stdout, "Init TPA\n");
  if((a = TPA_init()) != 0) return -1;

  mg_log_set(MG_LL_INFO);  // Set log level
  mg_mgr_init(&mgr);        // Initialize event manager
  c = mg_listen(&mgr, s_lsn, sfn, NULL);  // Create server connection
  if (c == NULL) {
    MG_INFO(("SERVER cant' open a connection"));
    return 0;
  }
  while (Continue)
    mg_mgr_poll(&mgr, 100);  // Infinite event loop, blocks for upto 100ms
                             // unless there is network activity
  mg_mgr_free(&mgr);         // Free resources
  return 0;
}