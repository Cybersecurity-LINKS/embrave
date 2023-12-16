// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef __TPM_EK__
#define __TPM_EK__

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include "files.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_ctx_mgmt.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

#define DEFAULT_KEY_ALG "rsa2048"

/* EK context */
struct createek_context {

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_owner_hierarchy;

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_endorse_hierarchy;

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_ek;

    const char *key_alg;
    tpm2_hierarchy_pdata objdata;
    char *out_file_path;
    tpm2_convert_pubkey_fmt format;
    struct {
        UINT8 f :1;
        UINT8 t :1;
    } flags;

    bool find_persistent_handle;
};

tool_rc attester_create_ek(ESYS_CONTEXT *ectx, const char *algo);

#endif