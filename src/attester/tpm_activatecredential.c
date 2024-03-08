// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "tpm_activatecredential.h"

static tpm_activatecred_ctx ctx = {
    .aux_session_handle[0] = ESYS_TR_NONE,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

bool files_save_bytes_to_buffer(unsigned char **secret, unsigned int *secret_len, UINT8 *buf, UINT16 size) {

    if (!buf) {
        return false;
    }

    *secret_len = size+1;
    *secret = malloc(*secret_len+1);
    if (!*secret) {
        LOG_ERR("Could not allocate memory for secret");
        return false;
    }

    FILE *fp = fmemopen(*secret, *secret_len, "wb");
    if (!fp) {
        LOG_ERR("Could not open buffer for secret \", error: %s", strerror(errno));
        return false;
    }

    bool result = files_write_bytes(fp, buf, size);
    if (!result) {
        LOG_ERR("Could not write data to secret buffer");
    }

    if (fp != stdout) {
        fclose(fp);
    }

    return result;
}

static tool_rc activate_credential_and_output(ESYS_CONTEXT *ectx) {

    /*
     * 1. TPM2_CC_<command> OR Retrieve cpHash
     */
    return tpm2_activatecredential(ectx, &ctx.credentialed_key.object,
        &ctx.credential_key.object, &ctx.credential_blob, &ctx.secret,
        &ctx.cert_info_data, &ctx.cp_hash, &ctx.rp_hash,
        ctx.parameter_hash_algorithm, ctx.aux_session_handle[0]);
}

static tool_rc process_output(ESYS_CONTEXT *ectx, unsigned char **secret, unsigned int *secret_len) {

    UNUSED(ectx);
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

    if (!ctx.is_command_dispatch) {
        return tool_rc_success;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    #ifdef DEBUG
    tpm2_tool_output("certinfodata:");
    size_t i;
    for (i = 0; i < ctx.cert_info_data->size; i++) {
        tpm2_tool_output("%.2x", ctx.cert_info_data->buffer[i]);
    }
    tpm2_tool_output("\n");
    #endif
    /* is_file_op_success = files_save_bytes_to_file(NULL,
        ctx.cert_info_data->buffer, ctx.cert_info_data->size); */ // -> this allow to print on stdout the secret
    is_file_op_success = files_save_bytes_to_buffer(secret, secret_len,
        ctx.cert_info_data->buffer, ctx.cert_info_data->size);
    free(ctx.cert_info_data);
    if (!is_file_op_success) {
        return tool_rc_general_error;
    }

    if (ctx.rp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.rp_hash, ctx.rp_hash_path);
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
}

static bool read_cert_secret(unsigned char *mkcred_out, unsigned int mkcred_out_len) {

    bool result = false;

    FILE *fp = fmemopen(mkcred_out, mkcred_out_len, "rb");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"",
        ctx.credential_blob_path, strerror(errno));
        return false;
    }

    uint32_t version;
    result = files_read_header(fp, &version);
    if (!result) {
        LOG_ERR("Could not read version header");
        goto out;
    }

    if (version != 1) {
        LOG_ERR("Unknown credential format, got %"PRIu32" expected 1", version);
        goto out;
    }

    result = files_read_16(fp, &ctx.credential_blob.size);
    if (!result) {
        LOG_ERR("Could not read credential size");
        goto out;
    }

    result = files_read_bytes(fp, ctx.credential_blob.credential, ctx.credential_blob.size);
    if (!result) {
        LOG_ERR("Could not read credential data");
        goto out;
    }

    result = files_read_16(fp, &ctx.secret.size);
    if (!result) {
        LOG_ERR("Could not read secret size");
        goto out;
    }

    result = files_read_bytes(fp, ctx.secret.secret, ctx.secret.size);
    if (!result) {
        LOG_ERR("Could not write secret data");
        goto out;
    }

    result = true;

out:
    fclose(fp);
    return result;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx, unsigned char *mkcred_out, unsigned int mkcred_out_len) {

    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */

    /* Object #1 */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.credential_key.ctx_path,
        ctx.credential_key.auth_str, &ctx.credential_key.object, false,
        TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Object #1: tpm2_util_object_load_auth failed");
        return rc;
    }
    /* Object #2 */
    rc = tpm2_util_object_load_auth(ectx, ctx.credentialed_key.ctx_path,
        ctx.credentialed_key.auth_str, &ctx.credentialed_key.object, false,
        TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Object #2: tpm2_util_object_load_auth failed");
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */
    rc = tpm2_util_aux_sessions_setup(ectx, ctx.aux_session_cnt,
        ctx.aux_session_path, ctx.aux_session_handle, ctx.aux_session);
    if (rc != tool_rc_success) {
        LOG_ERR("tpm2_util_aux_sessions_setup failed");
        return rc;
    }

    /*
     * 3. Command specific initializations
     */
    rc = read_cert_secret(mkcred_out, mkcred_out_len) ? tool_rc_success : tool_rc_general_error;
    if (rc != tool_rc_success) {
        LOG_ERR("read_cert_secret failed");
        return rc;
    }

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.credential_key.object.session,
        ctx.credentialed_key.object.session,
        ctx.aux_session[0]
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;
    const char **rphash_path = ctx.rp_hash_path ? &ctx.rp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, rphash_path, &ctx.rp_hash, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     * !rphash && !cphash [Y]
     * !rphash && cphash  [N]
     * rphash && !cphash  [Y]
     * rphash && cphash   [Y]
     */
    ctx.is_command_dispatch = (ctx.cp_hash_path && !ctx.rp_hash_path) ?
        false : true;

    return rc;
}

/* It responsability of the caller to free secret */
tool_rc tpm_activatecredential(ESYS_CONTEXT *ectx, struct attester_conf *attester_config, unsigned char *mkcred_out, unsigned int mkcred_out_len, unsigned char **secret, unsigned int *secret_len) {

    ctx.credentialed_key.ctx_path = attester_config->ak_ctx;
    ctx.credential_key.ctx_path = "0x81000003"; /* EK handle */
    ctx.credential_key.auth_str = "session:/var/embrave/attester/session.ctx";

    /* Where to read the mkcred_out */
    ctx.is_credential_blob_specified = 1;

    /*
     * Process inputs
     */
    tool_rc rc = process_inputs(ectx, mkcred_out, mkcred_out_len);
    if (rc != tool_rc_success) {
        LOG_ERR("process_inputs failed");
        return rc;
    }

    /*
     * TPM2_CC_<command> call
     */
    rc = activate_credential_and_output(ectx);
    if (rc != tool_rc_success) {
        LOG_ERR("activate_credential_and_output failed");
        return rc;
    }

    /*
     * Process outputs
     */
    rc = process_output(ectx, secret, secret_len);
    if (rc != tool_rc_success) {
        LOG_ERR("process_output failed");
        return rc;
    }

    /*
     * Close authorization sessions
     */
    rc = tool_rc_success;
    tool_rc tmp_rc = tpm2_session_close(&ctx.credentialed_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    tmp_rc = tpm2_session_close(&ctx.credential_key.object.session);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    /*
     * Close auxiliary sessions
     */
    size_t i = 0;
    for(i = 0; i < ctx.aux_session_cnt; i++) {
        if (ctx.aux_session_path[i]) {
            tmp_rc = tpm2_session_close(&ctx.aux_session[i]);
            if (tmp_rc != tool_rc_success) {
                rc = tmp_rc;
            }
        }
    }

    return rc;
}