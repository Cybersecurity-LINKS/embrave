// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


#include "common.h"

static struct timespec start, finish, delta_1, delta_2, delta_3, delta_4, delta_5, delta_6;
static int t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0;

void set_flag(int n);

void sub_timespec(struct timespec t1, struct timespec t2, struct timespec *td){

    td->tv_nsec = t2.tv_nsec - t1.tv_nsec;
    td->tv_sec  = t2.tv_sec - t1.tv_sec;
    if (td->tv_sec > 0 && td->tv_nsec < 0){
        td->tv_nsec += NS_PER_SECOND;
        td->tv_sec--;
    }
    else if (td->tv_sec < 0 && td->tv_nsec > 0)
    {
        td->tv_nsec -= NS_PER_SECOND;
        td->tv_sec++;
    }
}

void get_start_timer(){
  clock_gettime(CLOCK_REALTIME, &start);
}

void get_finish_timer(int n){
  clock_gettime(CLOCK_REALTIME, &finish);
  print_timer(n);
  set_flag(n);
}

void set_flag(int n){

  switch(n){
    case 1:
      t1 = 1;
    break;
    case 2:
      t2=1;
    break;
    case 3:
      t3=1;
    break;
    case 4:
      t4=1;
    break;
    case 5:
      t5=1;
    break;
    case 6:
      t6=1;
    break;
  }

}

void print_timer(int n){

  switch(n){
    case 1:
      sub_timespec(start, finish, &delta_1);
      fprintf(stdout,"%d.%.9ld\n", (int) delta_1.tv_sec, delta_1.tv_nsec);
    break;
    case 2:
      sub_timespec(start, finish, &delta_2);
      fprintf(stdout,"%d.%.9ld\n", (int) delta_2.tv_sec, delta_2.tv_nsec);
    break;
    case 3:
      sub_timespec(start, finish, &delta_3);
      fprintf(stdout,"%d.%.9ld\n", (int) delta_3.tv_sec, delta_3.tv_nsec);
    break;
    case 4:
      sub_timespec(start, finish, &delta_4);
      fprintf(stdout,"%d.%.9ld\n", (int) delta_4.tv_sec, delta_4.tv_nsec);
    break;
    case 5:
      sub_timespec(start, finish, &delta_5);
      fprintf(stdout,"%d.%.9ld\n", (int) delta_5.tv_sec, delta_5.tv_nsec);
    break;
    case 6:
      sub_timespec(start, finish, &delta_6);
      fprintf(stdout,"%d.%.9ld\n", (int) delta_6.tv_sec, delta_6.tv_nsec);
    break;
  }

}

void save_timer(char * path){
  FILE* fp = NULL;
  fp = fopen(path, "a");
  if(t1)
    fprintf(fp,"%d.%.9ld ", (int) delta_1.tv_sec, delta_1.tv_nsec);
  if(t2)
    fprintf(fp,"%d.%.9ld ", (int) delta_2.tv_sec, delta_2.tv_nsec);
  if(t3)
    fprintf(fp,"%d.%.9ld ", (int) delta_3.tv_sec, delta_3.tv_nsec);
  if(t4)
    fprintf(fp,"%d.%.9ld ", (int) delta_4.tv_sec, delta_4.tv_nsec);
  if(t5)
    fprintf(fp,"%d.%.9ld ", (int) delta_5.tv_sec, delta_5.tv_nsec);
  if(t6)
    fprintf(fp,"%d.%.9ld ", (int) delta_6.tv_sec, delta_6.tv_nsec);
  fprintf(fp,"\n");
  fclose(fp);
}

bool check_ek(uint16_t *ek_handle, ESYS_CONTEXT *esys_context) {

  int persistent_handles = 0;
  
  // Read the # of persistent handles and check that created/existing handles really exist
  persistent_handles = getCap_handles_persistent(esys_context, ek_handle);
  if (persistent_handles == -1 ) {
    printf("Error while reading persistent handles!\n");
    goto error;
  }
  return true;
error:
  return false;
}

int getCap_handles_persistent(ESYS_CONTEXT *esys_context, uint16_t *ek_handle) {
  TSS2_RC tss_r;
  TPM2_CAP capability = TPM2_CAP_HANDLES;
  UINT32 property = TPM2_HR_PERSISTENT;
  UINT32 propertyCount = TPM2_MAX_CAP_HANDLES;
  TPMS_CAPABILITY_DATA *capabilityData;
  TPMI_YES_NO moreData;
  char handle_hex[HANDLE_SIZE];
  int h1 = 0;

  tss_r = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
    ESYS_TR_NONE, capability, property,
    propertyCount, &moreData, &capabilityData);
    if (tss_r != TSS2_RC_SUCCESS) {
      printf("Error while Esys_GetCapability\n");
      return -1;
    }

    for (int i = 0; i < capabilityData->data.handles.count; i++) {
      snprintf(handle_hex, HANDLE_SIZE, "0x%X", capabilityData->data.handles.handle[i]);
      if(memcmp((void *) ek_handle, handle_hex, HANDLE_SIZE) == 0) h1 = 1;
    }
    free(capabilityData);

    if(h1)
      return 0;
    return -1;
}

int digest_message(unsigned char *message, size_t message_len, int sha_alg, unsigned char *digest, int *digest_len) {
  EVP_MD_CTX *mdctx;

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

  if(1 != EVP_DigestUpdate(mdctx, message, message_len)){
    printf("EVP_DigestUpdate error\n");
    return -1;
  }

  if(1 != EVP_DigestFinal_ex(mdctx, digest,NULL)){
    printf("EVP_DigestFinal_ex error\n");
    return -1;
  }

  EVP_MD_CTX_free(mdctx);

  return 0;
}
const char* errorMessages[MAX_TRUST_VALUES] = {
    "Trusted",
    "Unknown, agent is unreachable. Attempting to reconnect",
    "Untrusted, agent is unreachable after the connection retries",
    "Untrusted, the given AK public pem is not a valid public key",
    "Untrusted, error during conversion from TPM2B to TPMS format from the quote internal data",
    "Untrusted, TPM quote verification failed",
    "Untrusted, nonce mismatch",
    "Untrusted, PCR digest mismatch",
    "Untrusted, unknown IMA template",
    "Untrusted, IMA parsing error",
    "Untrusted, Golden value mismatch",
    "Untrusted, PCR10 value mismatch",
    "Unknown, verifier internal error"
    // Add more error messages here...
};


char* get_error(int errorCode) {
  errorCode = - errorCode;
  if (errorCode >= 0 && errorCode < MAX_TRUST_VALUES) {
    return (char *) errorMessages[errorCode];
  } else {
    return "Unknown error";
  }
}

/*Open (or create) the log file "log_path" add appends the string "buff" at the end*/
void log_event(char * log_path, char * buff){

  FILE* fp = NULL;
  fp = fopen(log_path, "a");
  fprintf(fp,"%s\n\n", buff);
  fclose(fp);

}

bool get_ipaddr_from_interface(char * interface_name, char * buff){

  struct ifaddrs *ifaddr, *ifa;
  char host[NI_MAXHOST];
  bool found = false;

  if (getifaddrs(&ifaddr) == -1){
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }  

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next){
    if (ifa->ifa_addr == NULL)
      continue;  

    getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

    if((strcmp(ifa->ifa_name, interface_name)==0)&&(ifa->ifa_addr->sa_family==AF_INET)){
      strcpy(buff, host);
      found = true;
      break;
    }
  }

  freeifaddrs(ifaddr);
  return found;
}