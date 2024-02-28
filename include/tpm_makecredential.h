// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef __TPM_MAKECREDENTIAL__
#define __TPM_MAKECREDENTIAL__

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_identity_util.h"
#include "tpm2_options.h"
#include "tpm2_openssl.h"
#include "tpm2_util.h"
#include "tpm2_identity_util.h"

typedef struct tpm_makecred_ctx tpm_makecred_ctx;
struct tpm_makecred_ctx {
    TPM2B_NAME object_name;
    char *out_file_path;
    char *input_secret_data;
    char *public_key_path; /* path to the public portion of an object */
    TPM2B_PUBLIC public;
    TPM2B_DIGEST credential;
};

int tpm_makecredential (unsigned char* ek_cert_pem, int ek_cert_len, unsigned char* secret, unsigned char* name, size_t name_size, unsigned char **out_buff, size_t *out_buff_size);
#endif