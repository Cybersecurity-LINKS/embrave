#include "RA.h"


/* static CHALLENGE_BLOB data;
//mg_send does not push data to the network. 
//It only appends data to the output buffer.
// The data is being sent when mg_mgr_poll() is called. 
//If mg_send() is called multiple times, the output buffer grows
int challenge_create (struct mg_connection *c) {
  int tag = 0;
  //TAG TYPE || Npcr || IMA log (x,y) || nounce
  mg_send(c, &tag, sizeof(int));
  //CREATE NONCE
  if (!RAND_bytes(data.nonce_blob.buffer, NONCE_SIZE)){
    printf("Attestor client random generation error\n");
    
    return -1;
  }
  data.nonce_blob.size = NONCE_SIZE;
  MG_INFO(("NONCE :"));
  for(int i= 0; i< (int) 32; i++)
    printf("%02X", data.nonce_blob.buffer[i]);
  printf("\n");
  //CHOOSE PCR, FIXED FOR NOW
  set_PCR(&data.PCR);
  MG_INFO(("PCRS :%d\n", data.PCR));
  //CHOOSE IMA LOG SIZE
    
  mg_send(c, &data, sizeof(CHALLENGE_BLOB));
  MG_INFO(("CLIENT sent data"));

}
 */