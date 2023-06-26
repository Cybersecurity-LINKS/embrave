#include "RA.h"

int RA_explicit_challenge_create(Ex_challenge *chl)
{
  return nonce_create(&(chl->nonce_blob));
}

int RA_explicit_challenge_verify(Ex_challenge_reply *rpl)
{
  int ret;
  if(rpl == NULL) return -1;

  //FAIL TEST commented
  //rpl->quoted->attestationData[2] = 'a'; //TEST change a bit in the quoted data
  //rpl->quoted->size = 47488; //TEST change a bit in the quoted data size
  //rpl->sig[20] = 'a'; //TEST change a bit in the signature
  //rpl->sig_size = 59; //TEST change the signature size
  //rpl->nonce_blob.buffer[10] = 'a'; //TEST change a bit in the nonce received
  //rpl->pcrs.pcr_values[0].digests[0].buffer[2] = 'a'; //TEST change a bit in one pcr received
  //rpl->ak_pem[28] ='z'; //TEST change a bit in the AK public PEM received
  
  //verify pcr value
  
  //verify quote
  ret = verify_quote(rpl);
  if (ret == -1){
    printf("Untrusted TPA\n");
    return -1;
  } else {
    printf("Quote signature verification OK\n");
  }

  //verify IMA log

  return 0;
}

int RA_explicit_challenge_verify_TLS(Ex_challenge_reply *rpl)
{
  int ret;
  //verify pcr value
  
  //verfy soft binding

  //verify quote
  ret = verify_quote(rpl);
  //verify IMA log
  
  return 0;
}

void RA_free(Ex_challenge_reply *rpl){
  free(rpl->sig);
  free(rpl->quoted);
}
