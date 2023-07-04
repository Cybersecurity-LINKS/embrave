#include "RA.h"

char *load_ak_bind(void);

int RA_explicit_challenge_create(Ex_challenge *chl)
{
  return nonce_create(&(chl->nonce_blob));
}

int RA_explicit_challenge_verify(Ex_challenge_reply *rpl)
{
  int ret;
  char * pem_file_name;
  if(rpl == NULL) return -1;

  //FAIL TEST commented
  //rpl->quoted->attestationData[2] = 'a'; //TEST change a bit in the quoted data
  //rpl->quoted->size = 47488; //TEST change a bit in the quoted data size
  //rpl->sig[20] = 'a'; //TEST change a bit in the signature
  //rpl->sig_size = 59; //TEST change the signature size
  //rpl->nonce_blob.buffer[10] = 'a'; //TEST change a bit in the nonce received
  //rpl->pcrs.pcr_values[0].digests[0].buffer[2] = 'a'; //TEST change a bit in one pcr received
  //rpl->ak_pem[28] ='z'; //TEST change a bit in the AK public PEM received
  
  //Load AK pem
  //ret = load_ak(ak_pem, "ak.pub.pem");
/*   if(ret != 0) {
    printf("Untrusted TPA\n");
    return -1;
  }  */
  //TODO better version
  //load ak bind
  pem_file_name = load_ak_bind();
  if(pem_file_name == NULL){
    printf("AK loading faled\n");
    return -1;
  }
  printf("%s\n",pem_file_name);
  //verify quote
  ret = verify_quote(rpl, pem_file_name);
  if (ret == -1){
    printf("Untrusted TPA\n");
    goto end;
  } else {
    printf("Quote signature verification OK\n");
  }

  //verify IMA log
  ret = verify_ima_log(rpl);
  if (ret == -1){
    printf("Untrusted TPA\n");
    goto end;
  } else {
    printf("IMA Log verification OK\n");
  }


end:
  //free(pem_file_name);
  if (ret == 0)
    return 0;
  else
    return -1;
}

int RA_explicit_challenge_verify_TLS(Ex_challenge_reply *rpl)
{
  int ret;
  //verify pcr value
  
  //verfy soft binding

  //verify quote
  //ret = verify_quote(rpl);
  //verify IMA log
  
  return 0;
}

char *load_ak_bind(void){
  FILE*fp;
  char *a = NULL;
  size_t sz, ret;
  fp = fopen("../../Agents/Remote_Attestor/DB/ak_bind.txt", "r");
  char *buff;

  if(fp == NULL) return NULL;
  //The getline function uses the realloc function 
  //to automatically increase the memory block as required
  while(getline(&a, &sz, fp) != -1){
    buff = strtok(a, " ");
    //TODO dinamic ip 
    if(strcmp(buff, "tcp://localhost:8765") == 0)
      return strtok(NULL, " ");
  }  
  free(a);
  return NULL;
}

void RA_free(Ex_challenge_reply *rpl){
  free(rpl->sig);
  free(rpl->quoted);
}
