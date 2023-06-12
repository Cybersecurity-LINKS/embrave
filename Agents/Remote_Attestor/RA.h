#ifndef RA_H
#define RA_H

#include <limits.h>    /* for CHAR_BIT */
#include <stdint.h>    /* for uint32_t */
#include <stdint.h> 
#include <stdio.h>

#include "../../Protocols/Explicit/Explicit.h"

int RA_explicit_challenge(Ex_challenge *chl);
int RA_explicit_challenge(Ex_challenge_reply *rpl);
#endif