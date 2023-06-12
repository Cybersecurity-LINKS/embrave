#ifndef TPA_H
#define TPA_H

#include <stdint.h> 
#include <stdio.h>

#include "../../Protocols/Explicit/Explicit.h"


int TPA_init(void);
int TPA_explicit_challenge(Ex_challenge *chl, Ex_challenge_reply *rpl);
#endif