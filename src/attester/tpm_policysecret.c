// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "tpm_policysecret.h"

static tpm2_policysecret_ctx ctx= {
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

static tool_rc policysecret(ESYS_CONTEXT *ectx) {

    return tpm2_policy_build_policysecret(ectx, ctx.extended_session,
        &ctx.auth_entity.object, ctx.expiration, &ctx.policy_ticket,
        &ctx.timeout, ctx.is_nonce_tpm, ctx.qualifier_data_arg, &ctx.cp_hash,
        ctx.parameter_hash_algorithm);
}

static tool_rc process_output(ESYS_CONTEXT *ectx) {

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    rc = tpm2_policy_tool_finish(ectx, ctx.extended_session,
        ctx.policy_digest_path);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (ctx.policy_timeout_path) {
        if(!ctx.timeout->size) {
            LOG_WARN("Policy assertion did not produce timeout");
        } else {
            is_file_op_success = files_save_bytes_to_file(
                ctx.policy_timeout_path, ctx.timeout->buffer,
                ctx.timeout->size);
            
            if (!is_file_op_success) {
                LOG_ERR("Failed to save timeout to file.");
                return tool_rc_general_error;
            }
        }
    }

    if (ctx.policy_ticket_path) {
        if (!ctx.policy_ticket->digest.size) {
            LOG_WARN("Policy assertion did not produce auth ticket.");
        } else {
            is_file_op_success = files_save_authorization_ticket(
                ctx.policy_ticket, ctx.policy_ticket_path);
            
            if (!is_file_op_success) {
                LOG_ERR("Failed to save auth ticket");
                return tool_rc_general_error;
            }
        }
    }

    return rc;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /*
     * The auth string of the referenced object is strictly for
     * a password session
     */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_entity.ctx_path,
            ctx.auth_entity.auth_str, &ctx.auth_entity.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }
    
    rc = tpm2_session_restore(ectx, ctx.extended_session_path, false,
            &ctx.extended_session);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_entity.object.session,
        ctx.extended_session,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

tool_rc tpm_policysecret(ESYS_CONTEXT *ectx) {

    ctx.extended_session_path = "/var/lemon/attester/session.ctx";
    ctx.auth_entity.ctx_path = "e";

    /*
     * Process inputs
     */
    tool_rc rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * TPM2_CC_<command> call
     */
    rc = policysecret(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * Process outputs
     */
    rc = process_output(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * Free objects
     */
    free(ctx.policy_ticket);
    free(ctx.timeout);

    /*
     * Close authorization sessions
     */
    rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.auth_entity.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.extended_session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    return rc;
}