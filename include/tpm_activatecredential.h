// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef __TPM_ACTIVATECREDENTIAL__
#define __TPM_ACTIVATECREDENTIALL__

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "config_parse.h"

typedef struct tpm_activatecred_ctx tpm_activatecred_ctx;
#define MAX_AUX_SESSIONS 1 // two sessions provided by auth interface
#define MAX_SESSIONS 3
struct tpm_activatecred_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } credential_key; //Typically EK

    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } credentialed_key; //Typically AK

    TPM2B_ID_OBJECT credential_blob;
    const char *credential_blob_path;
    bool is_credential_blob_specified;
    TPM2B_ENCRYPTED_SECRET secret;

    /*
     * Outputs
     */
    const char *output_file;
    TPM2B_DIGEST *cert_info_data;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    const char *rp_hash_path;
    TPM2B_DIGEST rp_hash;
    TPMI_ALG_HASH parameter_hash_algorithm;
    bool is_command_dispatch;

    /*
     * Aux sessions
     */
    uint8_t aux_session_cnt;
    tpm2_session *aux_session[MAX_AUX_SESSIONS];
    const char *aux_session_path[MAX_AUX_SESSIONS];
    ESYS_TR aux_session_handle[MAX_AUX_SESSIONS];
};

tool_rc tpm_activatecredential(ESYS_CONTEXT *ectx, struct attester_conf *attester_config, unsigned char *mkcred_out, unsigned int mkcred_out_len, unsigned char **secret, unsigned int *secret_len);

#endif