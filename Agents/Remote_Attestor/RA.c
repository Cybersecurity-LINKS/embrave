#include "RA.h"

char *load_ak_bind(char * db_file_name);

int RA_explicit_challenge_create(Ex_challenge *chl)
{
  return nonce_create(&(chl->nonce_blob));
}

int RA_explicit_challenge_verify(Ex_challenge_reply *rpl)
{
  int ret;
  sqlite3 *db;
  char * pem_file_name, db_file_name[250];
  if(rpl == NULL) return -1;

  //FAIL TEST commented
  //rpl->quoted->attestationData[2] = 'a'; //TEST change a bit in the quoted data
  //rpl->quoted->size = 47488; //TEST change a bit in the quoted data size
  //rpl->sig[20] = 'a'; //TEST change a bit in the signature
  //rpl->sig_size = 59; //TEST change the signature size
  //rpl->nonce_blob.buffer[10] = 'a'; //TEST change a bit in the nonce received
  //rpl->pcrs.pcr_values[0].digests[0].buffer[2] = 'a'; //TEST change a bit in one pcr received
  //rpl->pcrs.pcr_values[0].digests[0].buffer[2] = 'a'; //TEST change a bit in one pcr received
  //rpl->ima_log_size = 56980; //TEST change ima log size TODO

  //Start timer 2
  get_start_timer();

  //TODO better version
  //load ak bind
  pem_file_name = load_ak_bind(db_file_name);
  if(pem_file_name == NULL){
    printf("AK loading faled\n");
    return -1;
  }

  //verify quote
  ret = verify_quote(rpl, pem_file_name);
  if (ret == -1){
    printf("Untrusted TPA\n");
    return -1;
  } else {
    printf("Quote signature verification OK\n");
  }

  //End timer 2
  get_finish_timer();
  print_timer(2);

  //Start timer 3
  get_start_timer();

  //Open the goldenvalues DB
  int rc = sqlite3_open_v2(db_file_name, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
  if ( rc != SQLITE_OK) {
    printf("Cannot open the golden values database, error %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    printf("Untrusted TPA\n");
    goto end;
  }

  //verify IMA log
  ret = verify_ima_log(rpl, db);
  if (ret == -1){
    printf("Untrusted TPA\n");
    goto end;
  } else {
    printf("Trusted TPA\n");
  }

  //End timer 3
  get_finish_timer();
  print_timer(3);
  save_timer();
end:
  //free(pem_file_name);
  sqlite3_close(db);
  if (ret == 0)
    return 0;
  else
    return -1;
}

int RA_explicit_challenge_verify_TLS(Ex_challenge_reply *rpl)
{
  //int ret;
  //verify pcr value
  
  //verfy soft binding

  //verify quote
  //ret = verify_quote(rpl);
  //verify IMA log
  
  return 0;
}

char *load_ak_bind(char * db_file_name){
  FILE*fp;
  char *a = NULL;
  char *b = NULL;
  //char *c = NULL;
  size_t sz;
  fp = fopen("../../Agents/Remote_Attestor/DB/ak_bind.txt", "r");
  char *buff;

  if(fp == NULL) return NULL;
  //The getline function uses the realloc function 
  //to automatically increase the memory block as required
  while(getline(&a, &sz, fp) != -1){
    buff = strtok(a, " ");
    //TODO dinamic ip 
    if(strcmp(buff, "tcp://localhost:8765") == 0){
      b = strtok(NULL, " ");
      if(b == NULL) return NULL;
     // db_file_name = malloc(strlen(b)+1);
     // if(db_file_name == NULL) return NULL;
      memcpy(db_file_name, b, strlen(b)+1);
      //printf("%s\n", db_file_name);
      //c = strtok(NULL, " ");
     // printf("%s\n", db_file_name);
     // printf("%s\n", c);
      //db_file_name = strtok(NULL, " ");
      return strtok(NULL, " ");
    }
      
  } 
  
  free(a);
  return NULL;
}

void RA_free(Ex_challenge_reply *rpl){
  free(rpl->sig);
  free(rpl->quoted);
}
