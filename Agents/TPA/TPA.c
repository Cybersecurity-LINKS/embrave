#include "TPA.h"




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


  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  return 0;
}

int TPA_explicit_challenge_TLS(Ex_challenge *chl, Ex_challenge_reply *rpl){
  return 0;
}

void TPA_free(Ex_challenge_reply *rpl)
{
  free_data (rpl);
}
