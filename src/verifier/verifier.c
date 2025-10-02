// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "verifier.h"

agent_list *agents = NULL;

int ra_challenge_create(tpm_challenge *chl, agent_list *agent_data)
{
  if(agent_data->pcr10_sha256 != NULL)
    chl->send_from_byte = agent_data->byte_rcv;
  else
    chl->send_from_byte = 0;
  
  return nonce_create(chl->nonce);
}

int ra_challenge_verify(tpm_challenge_reply *rpl, agent_list *agent_data)
{
  int ret;
  sqlite3 *db;

  if(rpl == NULL) return -1;
  
  fprintf(stdout, "[%s Attestation] Verify TPM Quote\n", agent_data->uuid);
  //verify quote
  ret = verify_quote(rpl, agent_data->ak_pub,  agent_data);
  if (ret != 0){
    fprintf(stderr, "ERROR: Untrusted agent. Reason: %s\n", get_error(ret));
    return ret;
  } else {
    fprintf(stdout, "[%s Attestation] TPM Quote verification: OK\n", agent_data->uuid);
  }

  //Open the goldenvalues DB
  int rc = sqlite3_open_v2((const char *) agent_data->gv_path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
  if ( rc != SQLITE_OK) {
    fprintf(stderr, "ERROR: Cannot open the golden values database. Reason: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    ret = VERIFIER_INTERNAL_ERROR;
    goto end;
  }

  fprintf(stdout, "[%s Attestation] Verify IMA log and PCR10.\n", agent_data->uuid);
  //verify IMA log
  ret = verify_ima_log(rpl, db, agent_data);
  fflush(stdout);
  if (ret == 0){
    fprintf(stdout, "[%s Attestation] Verify IMA log and PCR10: OK\n", agent_data->uuid);
  } else {
    fprintf(stderr, "[%s Attestation] Untrusted agent. Reason: %s\n", agent_data->uuid, get_error(ret));
  }

end:
  sqlite3_close(db);
  return ret;
}

agent_list *agent_list_new(){
  agent_list *ptr, *previous_ptr;
  ptr = agents;
  previous_ptr = NULL;

  while(ptr != NULL){
    previous_ptr = ptr;
    ptr = ptr->next_ptr;
  }
  ptr = malloc(sizeof(agent_list));
  ptr->next_ptr = NULL;
  ptr->previous_ptr = previous_ptr;

  if(agents == NULL)
    agents = ptr;

  return ptr;
}

void agent_list_remove(agent_list * ptr){

  agent_list * next_ptr = NULL;
  agent_list * previous_ptr = NULL;

  if(ptr == NULL)
    return;

  next_ptr = ptr->next_ptr;
  previous_ptr = ptr->previous_ptr;
  
  if(previous_ptr != NULL)
    previous_ptr->next_ptr = next_ptr;
  else
    agents = next_ptr;

  if(next_ptr != NULL)
    next_ptr->previous_ptr = previous_ptr;
  
  if(ptr->pcr10_sha1 != NULL)
    free(ptr->pcr10_sha1);
  if(ptr->pcr10_sha256 != NULL)
    free(ptr->pcr10_sha256);
  free(ptr);
}

agent_list * agent_list_find_uuid(char * uuid){
  agent_list *ptr = agents;

  while (ptr != NULL){
    if(strcmp(ptr->uuid, uuid) == 0)
      return ptr;
    ptr=ptr->next_ptr;
  } 

  return NULL;
}