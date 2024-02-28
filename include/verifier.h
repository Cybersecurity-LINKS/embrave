// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef RA_H
#define RA_H

#include <limits.h>    /* for CHAR_BIT */
#include <stdint.h>    /* for uint32_t */
#include <stdint.h> 
#include <stdio.h>
#include <string.h>

#include "tpm_quote.h"
#include "common.h"
/* APIs */
#define API_ATTEST "/request_attestation"

/* Trust status value */
#define TRUSTED 0
#define UNTRUSTED -1
#define UNREACHABLE -2

int ra_challenge_create(tpm_challenge *chl, agent_list *agent_data);
int ra_challenge_verify(tpm_challenge_reply *rpl, agent_list *agent_data);
void ra_free(tpm_challenge_reply *rpl, agent_list *tpa_data);
agent_list * agent_list_new();
agent_list * agent_list_find_uuid(char *uuid);
void agent_list_remove(agent_list *ptr);
#endif