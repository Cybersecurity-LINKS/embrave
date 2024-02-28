// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


#ifndef TPA_H
#define TPA_H

#include <stdint.h> 
#include <stdio.h>
#include "config_parse.h"
#include "tpm_quote.h"

extern struct attester_conf attester_config;

int attester_init(/* struct attester_conf* conf */);
int tpm_challenge_create(tpm_challenge *chl, tpm_challenge_reply *rpl);
void tpm_challenge_free(tpm_challenge_reply *rpl);
int attester_activatecredential(unsigned char *mkcred_out, unsigned int mkcred_out_len, unsigned char **secret, unsigned int *secret_len);
#endif