// Copyright (C) 2023 Fondazione LINKS 

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

#include "tpm.h"

int RA_explicit_challenge_create(tpm_challenge *chl, Tpa_data *tpa_data);
int RA_explicit_challenge_verify(tpm_challenge_reply *rpl, Tpa_data *tpa_data);
int RA_explicit_challenge_verify_TLS(tpm_challenge_reply *rpl, Tpa_data *tpa_data);
void RA_free(tpm_challenge_reply *rpl, Tpa_data *tpa_data);
#endif