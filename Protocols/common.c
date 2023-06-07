#include "common.h"




bool check_keys(uint16_t *ek_handle, uint16_t  *ak_handle) {
  // TPM
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  int persistent_handles = 0, n, i;

  tss_r = Tss2_TctiLdr_Initialize("tabrmd", &tcti_context);
  //tss_r = Tss2_TctiLdr_Initialize("swtpm", &tcti_context);
  //tss_r = Tss2_TctiLdr_Initialize("NULL", &tcti_context);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize tcti context\n");
    return false;
  }
  
  tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
  if (tss_r != TSS2_RC_SUCCESS) {
    printf("Could not initialize esys context\n");
    return false;
  }
  // Read the # of persistent handles and check that created/existing handles really exist
  persistent_handles = getCap_handles_persistent(esys_context, ek_handle, ak_handle);
  if (persistent_handles == -1 ) {
    printf("Error while reading persistent handles!\n");
    goto error;
  }
  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  return true;
error:
  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  return false;
}

int getCap_handles_persistent(ESYS_CONTEXT *esys_context, uint16_t *ek_handle, uint16_t *ak_handle) {
  TSS2_RC tss_r;
  TPM2_CAP capability = TPM2_CAP_HANDLES;
  UINT32 property = TPM2_HR_PERSISTENT;
  UINT32 propertyCount = TPM2_MAX_CAP_HANDLES;
  TPMS_CAPABILITY_DATA *capabilityData;
  TPMI_YES_NO moreData;
  char handle_hex[HANDLE_SIZE];
  int h1 = 0, h2 = 0;

  tss_r = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
    ESYS_TR_NONE, capability, property,
    propertyCount, &moreData, &capabilityData);
    if (tss_r != TSS2_RC_SUCCESS) {
      printf("Error while Esys_GetCapability\n");
      return -1;
    }

    for (int i = 0; i < capabilityData->data.handles.count; i++) {
      snprintf(handle_hex, HANDLE_SIZE, "0x%X", capabilityData->data.handles.handle[i]);
      if(strcmp((char *) ek_handle, handle_hex) == 0) h1 = 1;
      if(strcmp((char *) ak_handle, handle_hex) == 0) h2 = 1;
    }
    if(h1 && h2)
      return 0;
    return -1;
}