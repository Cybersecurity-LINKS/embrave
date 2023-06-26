//#include "../mongoose.h"
//#include "../RA/RA.h"
#include "../Mongoose/mongoose.h"
#include "../../Agents/Remote_Attestor/RA.h"

static const char *s_conn = "tcp://localhost:8765";  // Connect to address
// client resources
static struct c_res_s {
  int i;
  //struct mg_connection *c;
} c_res;

static bool Continue = true;
static bool end = false;
//dati statici ima log from to
//int challenge_create(struct mg_connection *c);
int load_challenge_reply( struct mg_iobuf *r, Ex_challenge_reply *rpl);

static void explicit_ra(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  int *i = &((struct c_res_s *) fn_data)->i;
  if (ev == MG_EV_OPEN) {
    MG_INFO(("CLIENT has been initialized"));
  } else if (ev == MG_EV_CONNECT) {
    MG_INFO(("CLIENT connected"));
#if MG_ENABLE_MBEDTLS || MG_ENABLE_OPENSSL
    struct mg_tls_opts opts = {.ca = "ss_ca.pem"};
    mg_tls_init(c, &opts);
    MG_INFO(("CLIENT initialized TLS"));
#endif
    *i= *i+1;  // do something
  } else if (ev == MG_EV_READ) {
    printf("Client received data\n");
    int n = 0;
    Ex_challenge_reply rpl;
    // AK_PUB_BLOB ak_pub;
    //read TPA challenge reply
    struct mg_iobuf *r = &c->recv;
    if(load_challenge_reply(r, &rpl) < 0){
      //TODO ERRORI
    }

    if(RA_explicit_challenge_verify(&rpl) < 0){
      
      //TODO ERRORI
    }
   // MG_INFO(("CLIENT got AK PUB PEM of size %ld\n: %s", ak_pub.size, ak_pub.ak_pem));
   // TO_SEND *TpaData = (TO_SEND*) r->buf;
   // n = verify(TpaData, &data, &ak_pub);

    //TODO FREE AK
    r->len = 0;
    //c->is_closing = 1;
    end = true;
    RA_free(&rpl);
  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("CLIENT disconnected"));

    // signal we are done
    //((struct c_res_s *) fn_data)->c = NULL;
    Continue = false;
  } else if (ev == MG_EV_ERROR) {
    MG_INFO(("CLIENT error: %s", (char *) ev_data));
    
    Continue = false;
  } else if (ev == MG_EV_POLL && *i == 1) {
    //CHALLENGE CREATE
    int n;
    int tag = 0;
    //Send Explict tag
    mg_send(c, &tag, sizeof(int));
    //Create nonce
    Ex_challenge chl;
    if(RA_explicit_challenge_create(&chl)!= 0){
      Continue = false;
      return;
    }
    //Send it
    mg_send(c, &chl, sizeof(Ex_challenge));
    //printf("CLIENT sent data\n");
    *i= *i+1;
  }else if (end){
      c->is_draining = 1;
      Continue = false;
    }
}


int main(void) {
  struct mg_mgr mgr;  // Event manager
  struct mg_connection *c;

  mg_mgr_init(&mgr);
  c_res.i = 0;
  //Explict RA
  c = mg_connect(&mgr, s_conn, explicit_ra, &c_res);
  if (c == NULL) {
    MG_INFO(("CLIENT cant' open a connection"));
    return 0;
  }
  //Or explict RA with TLS and softbindigs
  while (Continue) mg_mgr_poll(&mgr, 1000); 

  return 0;
}

int load_challenge_reply(struct mg_iobuf *r, Ex_challenge_reply *rpl)
{
  char pcrs[10] = "sha256:all";
  if(r == NULL) return -1;

  //Signature size
  memcpy(&rpl->sig_size, r->buf, sizeof(UINT16));
  mg_iobuf_del(r,0,sizeof(UINT16));
  //Signature
  rpl->sig = malloc(rpl->sig_size);
  if(rpl->sig == NULL) return -1;
  memcpy(rpl->sig, r->buf, rpl->sig_size);
  mg_iobuf_del(r,0, rpl->sig_size);
  printf("Received signature size %d\n", rpl->sig_size);
  print_signature(&rpl->sig_size, rpl->sig);

  //Nonce
 // memcpy(&rpl->nonce_blob.size, r->buf, sizeof(uint16_t));
 // mg_iobuf_del(r,0, sizeof(uint16_t));
  memcpy(&rpl->nonce_blob, r->buf, sizeof(Nonce));
  mg_iobuf_del(r,0, sizeof(Nonce));
  printf("NONCE Received:");
  for(int i= 0; i< (int) rpl->nonce_blob.size; i++)
    printf("%02X", rpl->nonce_blob.buffer[i]);
  printf("\n");

  //pcrs
  memcpy(&rpl->pcrs, r->buf, sizeof(tpm2_pcrs));
  mg_iobuf_del(r,0, sizeof(tpm2_pcrs));
  //Only to print pcr to quote 
  TPML_PCR_SELECTION pcr_select;
  if (!pcr_parse_selections(pcrs, &pcr_select)) {
    printf("pcr_parse_selections failed\n");
    return -1;
  }
  pcr_print_(&pcr_select, &(rpl->pcrs));

  //mg_send(c, &rpl->quoted, sizeof(TPM2B_ATTEST));
  rpl->quoted = malloc(sizeof(TPM2B_ATTEST ));
  if(rpl->quoted == NULL) return -1;
  memcpy(&rpl->quoted->size, r->buf, sizeof(UINT16));
  mg_iobuf_del(r,0, sizeof(UINT16));
  memcpy(&rpl->quoted->attestationData, r->buf, rpl->quoted->size);
  mg_iobuf_del(r,0, rpl->quoted->size);
  //printf("Received signature size %d\n", rpl->quoted->size);
  print_quoted(rpl->quoted);
//
//

  memcpy(&rpl->ak_size, r->buf, sizeof(long));
  mg_iobuf_del(r,0, sizeof(long));
  rpl->ak_pem = malloc(rpl->ak_size);
  if(rpl->ak_pem == NULL) return -1;
  memcpy(rpl->ak_pem, r->buf, rpl->ak_size);
  mg_iobuf_del(r,0, rpl->ak_size);
  printf("AK PEM file recived:\n");
  PEM_write(stdout, "PUBLIC KEY", "",rpl->ak_pem ,rpl->ak_size);
  printf("\n");

  return 0;
}
