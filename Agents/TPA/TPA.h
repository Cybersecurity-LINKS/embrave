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

#include "../../Protocols/Explicit/Explicit.h"


int TPA_init(void);
int TPA_explicit_challenge(Ex_challenge *chl, Ex_challenge_reply *rpl);
//int TPA_explicit_challenge_TLS(Ex_challenge *chl, Ex_challenge_reply *rpl);
void TPA_free(Ex_challenge_reply *rpl);
#endif