// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef __JOIN_SERVICE__
#define __JOIN_SERVICE__

#include "mongoose.h"
#include <sqlite3.h>

#define SECRET_SIZE 8

/* methods */
#define GET "GET"
#define POST "POST"
#define PUT "PUT"
#define DELETE "DELETE"

/* codes */
#define OK 200
#define ALREDY_JOINED 200
#define CREATED 201
#define ANAUTHORIZED 401
#define FORBIDDEN 403


/* responses */
#define APPLICATION_JSON "Content-Type: application/json\r\n"

/* APIs */
#define API_JOIN "/request_join"
#define API_JOIN_VERIFIER "/request_join_verifier"
#define API_CONFIRM_CREDENTIAL "/confirm_credential"
#define API_REQUEST_ATTESTATION "/request_attestation"
#endif