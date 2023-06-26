#include "TPA.h"


static long ima_byte_sent = 0;
int load_ak(Ex_challenge_reply *rpl);
int load_ima_log(const char *path, Ex_challenge_reply *rpl);

int TPA_init(void) {
  uint16_t ek_handle[HANDLE_SIZE];
  uint16_t ak_handle[HANDLE_SIZE];

  snprintf((char *)ek_handle, HANDLE_SIZE, "%s", "0x81000003");
  snprintf((char *)ak_handle, HANDLE_SIZE, "%s", "0x81000004");
  if(!check_keys(ek_handle, ak_handle)) {
    printf("Could not initialize the TPM Keys\n");
    return -1;
  }
  return 0;
}

int TPA_explicit_challenge(Ex_challenge *chl, Ex_challenge_reply *rpl)
{
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  uint16_t ak_handle[HANDLE_SIZE];
  int ret;
  snprintf((char *)ak_handle, HANDLE_SIZE, "%s", "0x81000004");

  tss_r = Tss2_TctiLdr_Initialize("tabrmd", &tcti_context);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize tcti context\n");
    return -1;
  }
  tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize esys context\n");
    Tss2_TctiLdr_Finalize (&tcti_context);
    return -1;
  }
  
  ret = create_quote(chl, rpl, esys_context);
  if(ret != 0) goto end;
  //load AK pem
  ret = load_ak(rpl);
  if(ret != 0) goto end;
  //load IMA log
  //Real path
  //ret = load_ima_log("/sys/kernel/security/integrity/ima/binary_runtime_measurements", rpl);
  //dev path
  printf("WARNING: IMA LOG DEV PATH\n");
  ret = load_ima_log("/home/ale/Scrivania/TPA/ascii_runtime_measurements", rpl);
end: 
  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  if(ret != 0)
    return -1;
  return 0;
}

int TPA_explicit_challenge_TLS(Ex_challenge *chl, Ex_challenge_reply *rpl){
  return 0;
}

void TPA_free(Ex_challenge_reply *rpl)
{
  free_data (rpl);
}

int load_ak(Ex_challenge_reply *rpl){
  char * name, *header;
  FILE *ak_pub = fopen("/etc/tc/ak.pub.pem", "r");
  if(ak_pub == NULL){
    printf("Could not open AK PEM file\n");
    return false;
  }

  if (PEM_read(ak_pub, &name, &header, &rpl->ak_pem, &rpl->ak_size)  != 1) {
    printf("Failed to open AK public key output file \n");
    return -1;
  }
  printf("AK PEM file sent:\n");
  PEM_write(stdout, "PUBLIC KEY", "",rpl->ak_pem ,rpl->ak_size);
  printf("\n");

  OPENSSL_free(name);
  OPENSSL_free(header);
  return 0;
}


/* 
  Read the IMA log and send it all, starting from position ima_byte_sent byte
 */


int load_ima_log(const char *path, Ex_challenge_reply *rpl)
{
  FILE *fp;
  long rc;
  fp = fopen(path, "rb");
	if (!fp) {
	  printf("Unable to open IMA file\n");
		return -1;
	}
  
  rc = fseek(fp, 0, SEEK_END);
  if(rc == -1){
    printf("fseek error\n");
    fclose(fp);
    return -1;
  }

  rc = ftell(fp);
  if(rc == -1){
    printf("ftell error\n");
    fclose(fp);
    return -1;
  }
  
  rpl->ima_log_size = (rc - ima_byte_sent);

  rc = fseek(fp, 0, SEEK_SET);
  if(rc == -1){
    printf("fseek error\n");
    fclose(fp);
    return -1;
  }

  printf("%ld\n", rpl->ima_log_size);
  rpl->ima_log = malloc(rpl->ima_log_size +1);
  rpl->ima_log[rpl->ima_log_size] = '\n';

  fread(rpl->ima_log, rpl->ima_log_size, 1, fp);

  printf("%s\n", rpl->ima_log);
  fclose(fp);
  return 0;
}
