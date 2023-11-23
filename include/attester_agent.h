// Copyright (C) 2023 Fondazione LINKS 

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
#include "tpm.h"

int attetser_init(struct attester_conf* conf);
int tpa_explicit_challenge(tpm_challenge *chl, tpm_challenge_reply *rpl);
void tpa_free(tpm_challenge_reply *rpl);
#endif