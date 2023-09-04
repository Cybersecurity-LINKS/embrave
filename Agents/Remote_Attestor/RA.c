#include "RA.h"

int RA_explicit_challenge_create(Ex_challenge *chl)
{
  return nonce_create(&(chl->nonce_blob));
}

int RA_explicit_challenge_verify(Ex_challenge_reply *rpl, Tpa_data *tpa_data)
{
  int ret;
  sqlite3 *db;
 // char * pem_file_name, db_file_name[250];
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

  //verify quote
  ret = verify_quote(rpl, tpa_data->ak_path );
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
  int rc = sqlite3_open_v2((const char *) tpa_data->gv_path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
  if ( rc != SQLITE_OK) {
    printf("Cannot open the golden values database, error %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    printf("Untrusted TPA\n");
    goto end;
  }

  //verify IMA log
  ret = verify_ima_log(rpl, db, tpa_data);
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

int RA_explicit_challenge_verify_TLS(Ex_challenge_reply *rpl, Tpa_data *tpa_data)
{
  int ret;
  sqlite3 *db;
  //char * pem_file_name, db_file_name[250];
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

  //verify quote
  ret = verify_quote(rpl, (const char *) tpa_data->ak_path);
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

  //Softbindings verify
  ret = PCR9softbindig_verify(rpl, tpa_data);
  if (ret != 0){
    printf("Untrusted TPA\n");
    return -1;
  }else {
    printf("Softbindings verification OK\n");
  }

  //Open the goldenvalues DB
  int rc = sqlite3_open_v2((const char *) tpa_data->gv_path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
  if ( rc != SQLITE_OK) {
    printf("Cannot open the golden values database, error %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    printf("Untrusted TPA\n");
    goto end;
  }

  //verify IMA log
  ret = verify_ima_log(rpl, db, tpa_data);
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

void RA_free(Ex_challenge_reply *rpl, Tpa_data *tpa_data){
  free(rpl->sig);
  free(rpl->quoted);
  free(tpa_data->ak_path);
  free(tpa_data->gv_path);
  free(tpa_data->tls_path);
  if(tpa_data->pcr10_old_sha1 != NULL){
    free(tpa_data->pcr10_old_sha1);
  }
  if(tpa_data->pcr10_old_sha256 != NULL){
    free(tpa_data->pcr10_old_sha256);
  }
}
