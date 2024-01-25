// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef _TPM_POLICYSECRET_
#define _TPM_POLICYSECRET_

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"

#define MAX_SESSIONS 3
typedef struct tpm2_policysecret_ctx tpm2_policysecret_ctx;
struct tpm2_policysecret_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } auth_entity;

    INT32 expiration;
    const char *qualifier_data_arg;
    bool is_nonce_tpm;

    const char *extended_session_path;
    tpm2_session *extended_session;

    /*
     * Outputs
     */
    TPMT_TK_AUTH *policy_ticket;
    char *policy_ticket_path;
    TPM2B_TIMEOUT *timeout;
    char *policy_timeout_path;
    const char *policy_digest_path;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

tool_rc tpm_policysecret(ESYS_CONTEXT *ectx);

#endif