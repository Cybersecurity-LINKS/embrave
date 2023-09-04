#include "TPA.h"


static uint32_t ima_byte_sent = 0;

int load_ima_log(const char *path, Ex_challenge_reply *rpl, int all_log);

int TPA_init(void) {
  // TPM
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  uint16_t ek_handle[HANDLE_SIZE];
  uint16_t ak_handle[HANDLE_SIZE];
  int ret;
  fprintf(stdout, "Init TPA\n");
  //tss_r = Tss2_TctiLdr_Initialize("swtpm", &tcti_context);
  //tss_r = Tss2_TctiLdr_Initialize("NULL", &tcti_context);
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

  snprintf((char *)ek_handle, HANDLE_SIZE, "%s", "0x81000003");
  snprintf((char *)ak_handle, HANDLE_SIZE, "%s", "0x81000004");
  if(!check_keys(ek_handle, ak_handle, esys_context)) {
    printf("Could not initialize the TPM Keys\n");
    goto error;
  }

  ret = check_pcr9(esys_context);
  //Check if PCR9 is zero
  if(ret == 0){
    //PCR9 is zero => softbinding
    ret = PCR9softbindig(esys_context);
    if(ret != 0) goto error;
  } else if(ret == -1){
    goto error;
  }

  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  return 0;
error:
  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  return -1;

}

int TPA_explicit_challenge(Ex_challenge *chl, Ex_challenge_reply *rpl)
{
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  uint16_t ak_handle[HANDLE_SIZE];
  int ret;
  snprintf((char *)ak_handle, HANDLE_SIZE, "%s", "0x81000004");

  //Set NULL pointers for safety
  rpl->ima_log = NULL;
  rpl->sig = NULL;
  rpl->quoted = NULL;

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
  
  //TPM Quote creation
  ret = create_quote(chl, rpl, esys_context);
  if(ret != 0) goto end;

  //Load IMA log
  ret = load_ima_log("/sys/kernel/security/integrity/ima/binary_runtime_measurements", rpl, chl->send_wholeLog);//Real path
  
  //printf("WARNING: IMA LOG DEV PATH\n");
  //ret = load_ima_log("/home/pi/tpa/binary_runtime_measurements", rpl); //Dev path
end: 
  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  if(ret != 0)
    return -1;
  return 0;
}

void TPA_free(Ex_challenge_reply *rpl)
{
  free_data (rpl);
}

/* 
  Read the IMA log and send it all, starting from position ima_byte_sent byte
  ret value
  0 ima log read ok
  -1 error
 */

int load_ima_log(const char *path, Ex_challenge_reply *rpl, int all_log)
{
  FILE *fp;
  size_t read_bytes, buff_sz;
  fp = fopen(path, "rb");
	if (!fp) {
	  printf("Unable to open IMA file\n");
		return -1;
	}

  if(ima_byte_sent != 0 && all_log != 1){
    int ret = fseek(fp, ima_byte_sent, SEEK_SET);
    printf("fseek ret %d\n", ret);
    if (ret != 0){
      printf("Unable to fseek IMA file\n");
      return -1;
    }
    rpl->wholeLog = 0;
  }
  else {
    rpl->wholeLog = 1;
    ima_byte_sent = 0;
  }
  
  rpl->ima_log_size = 0;
  buff_sz = 2048;
  rpl->ima_log = (unsigned char *)malloc(buff_sz);

  while (1) {
    char block[2048];
    read_bytes = fread(block, 1, sizeof(block), fp);

    if (read_bytes == 0) {
      printf("%ld\n", rpl->ima_log_size);
      // Eof or error
      if (feof(fp)) {
        if(rpl->ima_log_size != 0){
          //Eof, save the number of byte read
          ima_byte_sent += rpl->ima_log_size;
          break;
        }
        else{
          //No new entry in the IMA log, no need to re send it
          //TODO
          printf("No need to send the IMA log\n");
          //fclose(fp);
          //free(rpl->ima_log);
          //return 1;
          break;
        }
      } else {
        printf("Error reading the IMA log\n");
        free(rpl->ima_log);
        fclose(fp);
        return -1;
        }
    }

    //Realloc buffer if needed
    if(buff_sz < rpl->ima_log_size + read_bytes){
      rpl->ima_log = (unsigned char *)realloc(rpl->ima_log, 2 * buff_sz);
      if (rpl->ima_log == NULL) {
        printf("Error realloc the IMA log buffer\n");
        fclose(fp);
        return -1;
      }
      buff_sz = 2 * buff_sz;
    }
    memcpy(rpl->ima_log + rpl->ima_log_size, block, read_bytes);
    rpl->ima_log_size += read_bytes;
    }

  fclose(fp);
  return 0;
}
