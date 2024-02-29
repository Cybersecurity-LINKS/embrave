// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <openssl/evp.h>
#include <time.h>

#define HANDLE_EK 0x81000003
#define TCG_EVENT_NAME_LEN_MAX	255
#define MAX_TEXT_EVENT 1000
#define HANDLE_SIZE 11

/* methods */
#define GET "GET"
#define POST "POST"
#define PUT "PUT"
#define DELETE "DELETE"

/* codes */
#define OK 200

/* responses */
#define APPLICATION_JSON "Content-Type: application/json\r\n"

/* APIs */
#define API_QUOTE "/api/quote"

// calculate the size of 'output' buffer required for a 'input' buffer of length x during Base64 encoding operation
#define B64ENCODE_OUT_SAFESIZE(x) (((x / 3) + (x % 3 ? 1 : 0)) * 4 + 1)

// calculate the size of 'output' buffer required for a 'input' buffer of length x during Base64 decoding operation
#define B64DECODE_OUT_SAFESIZE(x) ((((x) / 4) * 3)  + 1)

#define MAX_BUF 255

enum { NS_PER_SECOND = 1000000000 };

typedef struct _agent_list agent_list;

struct  _agent_list{
    char ip_addr[MAX_BUF];
    char ak_pub[MAX_BUF];
    char uuid[MAX_BUF];
    char gv_path[MAX_BUF];
    bool running;
    char* pcr10_sha1;
    char* pcr10_sha256;
    int trust_value;
    int sleep_value;
    uint32_t resetCount;
    uint32_t byte_rcv;
    uint32_t connection_retry_number;
    uint32_t max_connection_retry_number;
    int attestation_value;
    bool continue_polling;
    agent_list * next_ptr;
    agent_list * previous_ptr;
};

bool check_ek(uint16_t *ek_handle, ESYS_CONTEXT *esys_context);
int getCap_handles_persistent(ESYS_CONTEXT *esys_context, uint16_t *ek_handle);
int digest_message(unsigned char *message, size_t message_len, int sha_alg, unsigned char *digest, int *digest_len);
void get_start_timer(void);
void get_finish_timer(void);
void print_timer(int n);
void save_timer(void);
#endif