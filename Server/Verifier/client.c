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
    int n = 0;
   // AK_PUB_BLOB ak_pub;
    //read TPA challenge reply
    struct mg_iobuf *r = &c->recv;
    //MG_INFO(("CLIENT got data: %.*s", sizeof(size_t), r->buf));
    //printf("%ld\n",r->len);
    //printf("%ld\n",sizeof(size_t));

   // n = load_ak(r,&ak_pub);
    if(n < 0){
      //TODO ERRORI

    }
   // MG_INFO(("CLIENT got AK PUB PEM of size %ld\n: %s", ak_pub.size, ak_pub.ak_pem));
   // TO_SEND *TpaData = (TO_SEND*) r->buf;
   // n = verify(TpaData, &data, &ak_pub);
    if(n < 0){
      //TODO ERRORI

    }

    //TODO FREE AK
    r->len = 0;
    //c->is_closing = 1;
    end = true;
   
  } else if (ev == MG_EV_CLOSE) {
    MG_INFO(("CLIENT disconnected"));

    // signal we are done
    //((struct c_res_s *) fn_data)->c = NULL;
    Continue = false;
  } else if (ev == MG_EV_ERROR) {
    MG_INFO(("CLIENT error: %s", (char *) ev_data));
    
    Continue = false;
  } else if (ev == MG_EV_POLL && *i == 1) {
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
