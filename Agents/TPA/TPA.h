#ifndef TPA_H
#define TPA_H

#include <stdint.h> 
#include <stdio.h>

#include "../../Protocols/Explicit/Explicit.h"


int TPA_init(void);
int TPA_explicit_challenge(Ex_challenge *chl, Ex_challenge_reply *rpl);
//int TPA_explicit_challenge_TLS(Ex_challenge *chl, Ex_challenge_reply *rpl);
void TPA_free(Ex_challenge_reply *rpl);
#endif