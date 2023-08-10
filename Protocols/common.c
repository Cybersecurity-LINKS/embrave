#include "common.h"




bool check_keys(uint16_t *ek_handle, uint16_t  *ak_handle) {
  // TPM
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  int persistent_handles = 0;
  //int n, i;

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


/* void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_free(mdctx);
}
 */

int digest_message(unsigned char *message, size_t message_len, int sha_alg, unsigned char *digest, int *digest_len) {
  EVP_MD_CTX *mdctx;
  //const EVP_MD *md;
 // unsigned int md_len, i;

	if((mdctx = EVP_MD_CTX_new()) == NULL){
      printf("EVP_MD_CTX_new error\n");
      return -1;
  }

  switch (sha_alg){
    case 0: 
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)){
      printf("EVP_DigestInit_ex error\n");
      return -1;
    }
    break;
    case 1: 
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL)){
      printf("EVP_DigestInit_ex error\n");
      return -1;
    }
    break;
    default:
    printf("unsupported digest\n");
    return -1;
    break;
  }

  if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		return -1;

  if(1 != EVP_DigestFinal_ex(mdctx, digest,(unsigned int *) digest_len))
		return -1;

  EVP_MD_CTX_free(mdctx);

  return 0;
}