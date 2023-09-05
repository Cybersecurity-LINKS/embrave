#include "../Mongoose/mongoose.h"
#include "../../Agents/Remote_Attestor/RA.h"

// client resources
static struct c_res_s {
  int i;
  //struct mg_connection *c;
} c_res;

static bool Continue = true;
static size_t last_read = 0;
static size_t to_read = 0;
static bool end = false;
static bool error = false;
static bool send_all_log = false;
static char* temp_buff = NULL;
static int last_rcv = 0;
static Ex_challenge_reply rpl;
static Tpa_data tpa_data;

int load_challenge_reply( struct mg_iobuf *r, Ex_challenge_reply *rpl);
int try_read(struct mg_iobuf *r, size_t size, void * dst);
void print_data(Ex_challenge_reply *rpl);

static void explicit_ra(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
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
      error = true;
      RA_free(&rpl, &tpa_data);
      return;
    } //waitng for more data from TPA
    else if(n == 1) return;
    

    //End timer 1
    get_finish_timer();
    print_timer(1);

    if(RA_explicit_challenge_verify(&rpl, &tpa_data) < 0){
      error = true;
    }

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
    int tag = 0;
    Ex_challenge chl;

    //If PCR10 are empty from tpa db, make tpa send all ima log
    if(send_all_log){
      chl.send_wholeLog = 1;
    } else {
      chl.send_wholeLog = 0;
    }

    //Create nonce
    if(RA_explicit_challenge_create(&chl)!= 0){
      Continue = false;
      return;
    }

    //Send Explict tag
    mg_send(c, &tag, sizeof(int));

    //Send nonce
    mg_send(c, &chl, sizeof(Ex_challenge));
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

    struct mg_tls_opts opts = {.ca = "../certs/ca.crt"};
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
      error = true;
      RA_free(&rpl, &tpa_data);
      return;
    } //waitng for more data from TPA
    else if(n == 1) return;
    

    //End timer 1
    get_finish_timer();
    print_timer(1);
    
    if(RA_explicit_challenge_verify_TLS(&rpl, &tpa_data) < 0){
      error = true;
    }

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
    int tag = 0;
    Ex_challenge chl;
    
    //If PCR10 are empty from tpa db, make tpa send all ima log
    if(send_all_log){
      chl.send_wholeLog = 1;
    } else {
      chl.send_wholeLog = 0;
    }
    
    //Create nonce
    if(RA_explicit_challenge_create(&chl)!= 0){
      Continue = false;
      return;
    }

    //Send Explict tag
    mg_send(c, &tag, sizeof(int));

    //Send nonce
    mg_send(c, &chl, sizeof(Ex_challenge));
    //printf("CLIENT sent data\n");
    *i= *i+1;
  }else if (end){
      c->is_draining = 1;
      Continue = false;
    }
}

// Load the AK path, the TLS certificate, the last PCR10 if present, 
// and the goldenvalue db path for a certain tpa
int get_paths(int id){
  (void) id;

  sqlite3_stmt *res= NULL;
  sqlite3 *db = NULL;
  int byte;
  //char *sql = "SELECT * FROM tpa where ak = '605403c37ebf5d0e73cc4e1569724635ee77181e54eb258035afc914d9d10285'";
  char *sql = "SELECT * FROM tpa WHERE id = @id";
  //TODO
  int step, idx;

  tpa_data.pcr10_old_sha256 = NULL;
  tpa_data.pcr10_old_sha1 = NULL;
  tpa_data.ak_path = NULL;
  tpa_data.gv_path = NULL;
  tpa_data.tls_path = NULL;

  int rc = sqlite3_open_v2("file:../../Agents/Remote_Attestor/tpa.db", &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
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
printf("QUIIII\n");
    //Ak file path
    byte = sqlite3_column_bytes(res, 2);
    tpa_data.ak_path = malloc((byte + 1) * sizeof(char));
    memcpy(tpa_data.ak_path, (char *) sqlite3_column_text(res, 2), byte);
    tpa_data.ak_path[byte] = '\0';
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
      send_all_log = true;
    }

    //Goldenvalue db path
    byte = sqlite3_column_bytes(res, 5);
    printf("%d\n", byte);
    tpa_data.gv_path = malloc((byte + 1) * sizeof(char));
    memcpy(tpa_data.gv_path, (char *) sqlite3_column_text(res, 5), byte);
    tpa_data.gv_path[byte] = '\0';
    //printf("%s\n", tpa_data.gv_path);

    //TLS cert path
    byte = sqlite3_column_bytes(res, 6);
    printf("%d\n", byte);
    tpa_data.tls_path = malloc((byte + 1) *sizeof(char));
    memcpy(tpa_data.tls_path, (char *) sqlite3_column_text(res, 6), byte);
    tpa_data.tls_path[byte] = '\0';

    //Timestamp, could be null    
    //TODO
printf("QUIIII222\n");
    sqlite3_finalize(res);
    printf("QUIIII222\n");
    sqlite3_close(db);
    printf("QUIIII222\n");
    return 0;
        
  } 
  
  printf("No id found in the tpa databse for %d\n", id);
  sqlite3_finalize(res);
  sqlite3_close(db);
  return -1;
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;  // Event manager
  struct mg_connection *c;
  char s_conn[250];
  int n;
  //Start Timer 1
  get_start_timer();

  //TODO MORE IDs
  if (get_paths(1) != 0){
    printf("Error from tpa.db\n");
    return -1;
  }
  //printf("%d\n", argc);
  if(argc != 3){
    printf("Error wrong parameters: usage ./TPA ip_1 ip_2\n");
    return -1;
  }
  n = strtol(argv[2], NULL, 10) ;

  if(n == 0)
    snprintf(s_conn, 250, "tcp://%s:8765", argv[1]);
  else if(n == 1)
    snprintf(s_conn, 250, "tcp://%s:8766", argv[1]);
  else{
    printf("Error wrong parameters TLS: usage 0 no TLS 1 TLS\n");
    return -1;
  }
  
  mg_mgr_init(&mgr);
  c_res.i = 0;

   if(n == 0){
    //Explict RA
    c = mg_connect(&mgr, s_conn, explicit_ra, &c_res);
   }
   else {
    //Explict RA TLS
    c = mg_connect(&mgr, s_conn, explicit_ra_TLS, &c_res);
   }

  if (c == NULL) {
    MG_INFO(("CLIENT cant' open a connection"));
    return 0;
  }

  while (Continue) mg_mgr_poll(&mgr, 1); //1ms

  if(!error)
    return 0;
  else
    return -1;
}

int load_challenge_reply(struct mg_iobuf *r, Ex_challenge_reply *rpl){

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
      ret = try_read(r, sizeof(Nonce), &rpl->nonce_blob);
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
  
  //print_data(rpl);

  return 0;
}

//Print received data
void print_data(Ex_challenge_reply *rpl){
  
  printf("NONCE Received:");
  for(int i= 0; i< (int) rpl->nonce_blob.size; i++)
    printf("%02X", rpl->nonce_blob.buffer[i]);
  printf("\n");

  TPML_PCR_SELECTION pcr_select;
  if (!pcr_parse_selections("sha1:10+sha256:all", &pcr_select)) {
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
