// Copyright (C) 2023 Fondazione LINKS 

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
/*     struct {
        UINT8 e :1;
        UINT8 s :1;
        UINT8 n :1;
        UINT8 o :1;
    } flags; */

    char *key_type; //type of key attempting to load, defaults to auto attempt
};

int tpm_makecredential (void);
#endif