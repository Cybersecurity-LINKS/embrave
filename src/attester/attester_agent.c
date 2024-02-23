// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "attester_agent.h"
#include "tpm_ek.h"
#include "tpm_ak.h"
#include "ek_cert.h"
#include "tpm_activatecredential.h"
#include "tpm_startauthsession.h"
#include "tpm_policysecret.h"
#include "tpm_flushcontext.h"

struct attester_conf attester_config;

int load_ima_log(const char *path, tpm_challenge_reply *rpl, int all_log, uint32_t from_bytes);

int attester_init(/* struct attester_conf* conf */) {
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  tool_rc rc_tool;
  uint16_t ek_handle[HANDLE_SIZE];

  fprintf(stdout, "INFO: agent init\n");

  tss_r = Tss2_TctiLdr_Initialize(NULL, &tcti_context);
  if (tss_r != TSS2_RC_SUCCESS) {
    fprintf(stderr, "ERROR: Could not initialize tcti context\n");
    return -1;
  }
  
  tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
  if (tss_r != TSS2_RC_SUCCESS) {
    fprintf(stderr, "ERROR: Could not initialize esys context\n");
    Tss2_TctiLdr_Finalize (&tcti_context);
    return -1;
  }

  /* set ek fixed handle */
  memcpy((void *) ek_handle, (void *) "0x81000003", HANDLE_SIZE);
  
  /* check certificate algo for saved ek certificates */
  unsigned char rc = check_ek_cert_algo(esys_context);
  char *algo = NULL;
  switch (rc)
  {
  case RSA_CHECK:
    algo = "rsa";
    fprintf(stdout, "RSA certificate found in tpm nv ram\n");
    break;
  
  case ECC_CHECK:
    algo = "ecc";
    fprintf(stdout, "ECC certificate found in tpm nv ram\n");
    break;

  case ECC_AND_RSA_CHECK:
    algo = "ecc";
    fprintf(stdout, "ECC and RSA certificates found in tpm nv ram\n");
    break;

  case NO_CERT_CHECK:
    fprintf(stdout, "No certificate found in tpm nv ram\n");
    break;

  case ERR_CHECK:
    fprintf(stderr, "ERROR: Error retriving certificates from tpm nv ram\n");
    break;

  default:
    fprintf(stdout, "Unknown returned code\n");
    break;
  }

  if(check_ek(ek_handle, esys_context)) {

    /* tpm_createak */
    rc_tool = attester_create_ak(esys_context, &attester_config);
    if(rc_tool != TPM2_RC_SUCCESS){
      fprintf(stderr, "ERROR: attester_create_ak error\n");
    goto error;
  }
    /* Check if present EK cert */
    FILE *fd = fopen(attester_config.ek_ecc_cert, "r");
    if(fd == NULL){
      fd = fopen(attester_config.ek_rsa_cert, "r");
      if(fd == NULL){
        fprintf(stdout, "INFO: EK certificate not found, generating it\n");
        rc_tool = get_ek_certificates(esys_context, &attester_config);
        if(rc_tool != tool_rc_success)
          goto error;
        return 0;
      }
    }
    
    fclose(fd);

    return 0;
  }

  /* tpm_createek */
  rc_tool = attester_create_ek(esys_context, algo);
  if(rc_tool != TPM2_RC_SUCCESS){
    fprintf(stderr, "ERROR: attester_create_ek error\n");
    goto error;
  }

  /* tpm_createak */
  rc_tool =  attester_create_ak(esys_context, &attester_config);
  if(rc_tool != TPM2_RC_SUCCESS){
    fprintf(stderr, "ERROR: attester_create_ak error\n");
    goto error;
  }

  /* tpm_getekcertificate */
  rc_tool =  get_ek_certificates(esys_context, &attester_config);
  if(rc_tool != TPM2_RC_SUCCESS){
    fprintf(stderr, "ERROR: get_ek_certificates error\n");
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

int attester_activatecredential(unsigned char *mkcred_out, unsigned int mkcred_out_len, unsigned char **secret, unsigned int *secret_len){
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  tool_rc rc_tool;

#ifdef DEBUG
  printf("MKCRED_OUT: ");
    for(int i=0; i<mkcred_out_len; i++){
      printf("%02x", mkcred_out[i]);
    }
  printf("\n"); 
#endif

  tss_r = Tss2_TctiLdr_Initialize(NULL, &tcti_context);
  if (tss_r != TSS2_RC_SUCCESS) {
    fprintf(stderr, "ERROR: Could not initialize tcti context\n");
    return -1;
  }
  
  tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
  if (tss_r != TSS2_RC_SUCCESS) {
    fprintf(stderr, "ERROR: Could not initialize esys context\n");
    Tss2_TctiLdr_Finalize (&tcti_context);
    return -1;
  }

  rc_tool = tpm_startauthsession(esys_context);
  if(rc_tool != tool_rc_success){
    fprintf(stderr, "ERROR: Could not start auth session\n");
    goto error;
  }
  
  rc_tool = tpm_policysecret(esys_context);
  if(rc_tool != tool_rc_success){
    fprintf(stderr, "ERROR: Could not set policy secret\n");
    goto error;
  }

  rc_tool = tpm_activatecredential(esys_context, &attester_config, mkcred_out, mkcred_out_len, secret, secret_len);
  if(rc_tool != tool_rc_success){
    fprintf(stderr, "ERROR: Could not activate credential\n");
    goto error;
  }

  rc_tool = tpm_flushcontext(esys_context);
  if(rc_tool != tool_rc_success){
    fprintf(stderr, "ERROR: Could not flush context\n");
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

int tpm_challenge_create(tpm_challenge *chl, tpm_challenge_reply *rpl)
{
  TSS2_RC tss_r;
  ESYS_CONTEXT *esys_context = NULL;
  TSS2_TCTI_CONTEXT *tcti_context = NULL;
  int ret;

  //Set NULL pointers for safety
  rpl->ima_log = NULL;
  rpl->sig = NULL;
  rpl->quoted = NULL;

  tss_r = Tss2_TctiLdr_Initialize(NULL, &tcti_context);
  if (tss_r != TSS2_RC_SUCCESS) {
    fprintf(stderr, "ERROR: Could not initialize tcti context\n");
    return -1;
  }

  tss_r = Esys_Initialize(&esys_context, tcti_context, NULL);
  if (tss_r != TSS2_RC_SUCCESS) {
    fprintf(stderr, "ERROR: Could not initialize esys context\n");
    Tss2_TctiLdr_Finalize (&tcti_context);
    return -1;
  }
  
  //TPM Quote creation
  ret = create_quote(chl, rpl, esys_context);
  if(ret != 0) goto end;

  //Load IMA log
  ret = load_ima_log("/sys/kernel/security/integrity/ima/binary_runtime_measurements", rpl, chl->send_wholeLog, chl->send_from_byte);
  
end: 
  Esys_Finalize(&esys_context);
  Tss2_TctiLdr_Finalize (&tcti_context);
  if(ret != 0)
    return -1;
  return 0;
}

void tpm_challenge_free(tpm_challenge_reply *rpl)
{
  free_data (rpl);
}

/* 
  Read the IMA log and send it all, starting from position ima_byte_sent byte
  ret value
  0 ima log read ok
  -1 error
 */

int load_ima_log(const char *path, tpm_challenge_reply *rpl, int all_log, uint32_t from_bytes)
{
  FILE *fp;
  size_t read_bytes, buff_sz;
  uint32_t ima_byte_sent;

  fprintf(stdout, "INFO; request all ima log%d or from byte %d\n", all_log, from_bytes);
  fp = fopen(path, "rb");
	if (!fp) {
	  fprintf(stderr, "ERROR: Unable to open IMA file\n");
		return -1;
	}

  if(all_log != 1){
    int ret = fseek(fp, from_bytes, SEEK_SET);
    
    if (ret != 0){
      fprintf(stderr, "ERROR: Unable to fseek IMA file\n");
      return -1;
    }
    rpl->wholeLog = 0;
    ima_byte_sent = from_bytes;
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
      // Eof or error
      if (feof(fp)) {
        if(rpl->ima_log_size != 0){
          //Eof, save the number of byte read
          ima_byte_sent += rpl->ima_log_size;
          break;
        }
        else{
          //No new entry in the IMA log, no need to re send it
          printf("No need to send the IMA log\n");
          break;
        }
      } else {
        fprintf(stderr, "ERROR: Error reading the IMA log\n");
        free(rpl->ima_log);
        fclose(fp);
        return -1;
        }
    }

    //Realloc buffer if needed
    if(buff_sz < rpl->ima_log_size + read_bytes){
      rpl->ima_log = (unsigned char *)realloc(rpl->ima_log, 2 * buff_sz);
      if (rpl->ima_log == NULL) {
        fprintf(stderr, "ERROR: Error realloc the IMA log buffer\n");
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
