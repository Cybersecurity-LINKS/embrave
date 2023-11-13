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
#define HANDLE_AK 0x81000004 
#define TCG_EVENT_NAME_LEN_MAX	255
#define MAX_TEXT_EVENT 1000
#define HANDLE_SIZE 11

#define RA_TYPE_EXPLICIT 0
#define RA_TYPE_DAA 1
#ifndef FRESH
    #define FRESH 60
#endif

enum { NS_PER_SECOND = 1000000000 };

typedef struct {
    int id;
    //char *sha_ak;
    char *ak_path;
    char *gv_path;
    char *tls_path;
    char *pcr10_old_sha1;
    char *pcr10_old_sha256;
    char *timestamp;
    char *ca;
    uint32_t resetCount;
    uint32_t byte_rcv;
} Tpa_data;

bool check_keys(uint16_t *ek_handle, uint16_t  *ak_handle, ESYS_CONTEXT *esys_context);
int getCap_handles_persistent(ESYS_CONTEXT *esys_context, uint16_t *ek_handle, uint16_t *ak_handle);
int digest_message(unsigned char *message, size_t message_len, int sha_alg, unsigned char *digest, int *digest_len);
void get_start_timer(void);
void get_finish_timer(void);
void print_timer(int n);
void save_timer(void);
#endif