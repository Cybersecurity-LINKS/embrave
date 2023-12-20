// Copyright (C) 2023 Fondazione LINKS 

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
    //.parameter_hash_algorithm = TPM2_ALG_ERROR,
};

//https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_activatecredential.1.md
//https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_activatecredential.c


tool_rc process_inputs(ESYS_CONTEXT *ectx);
tool_rc activate_credential_and_output(ESYS_CONTEXT *ectx);
tool_rc process_output(ESYS_CONTEXT *ectx) ;
static bool read_cert_secret(void);

//INPUT
//-i credendital challenge by CA (TPM2B_ID_OBJECT *cred, TPM2B_ENCRYPTED_SECRET *secret)
//-c AK handle
//-C EK handle
//OUTPUT
//-o The output file path to save the decrypted credential secret information
int tpm_activatecredential (ESYS_CONTEXT *ectx){
    tool_rc rc;

    //Set inputs

    //process it
    process_inputs(ectx);

    rc = activate_credential_and_output(ectx);
    if (rc != tool_rc_success) {
        return -1;
    }

    //process output
    process_output(ectx);




}

tool_rc process_output(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;


    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    tpm2_tool_output("certinfodata:");
    size_t i;
    for (i = 0; i < ctx.cert_info_data->size; i++) {
        tpm2_tool_output("%.2x", ctx.cert_info_data->buffer[i]);
    }
    tpm2_tool_output("\n");

    is_file_op_success = files_save_bytes_to_file(ctx.output_file,
        ctx.cert_info_data->buffer, ctx.cert_info_data->size);
    free(ctx.cert_info_data);
    if (!is_file_op_success) {
        return tool_rc_general_error;
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
}

tool_rc activate_credential_and_output(ESYS_CONTEXT *ectx) {

    
    //TPM2_CC_activatecredential
/*     return tpm2_activatecredential(ectx, &ctx.credentialed_key.object,
        &ctx.credential_key.object, &ctx.credential_blob, &ctx.secret,
        &ctx.cert_info_data, &ctx.cp_hash, &ctx.rp_hash,
        ctx.parameter_hash_algorithm, ctx.aux_session_handle[0]); */

    return tpm2_activatecredential(ectx, &ctx.credentialed_key.object,
        &ctx.credential_key.object, &ctx.credential_blob, &ctx.secret,
        &ctx.cert_info_data, NULL, NULL, NULL, ctx.aux_session_handle[0]);
}


tool_rc process_inputs(ESYS_CONTEXT *ectx) {

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
        return rc;
    }
    /* Object #2 */
    rc = tpm2_util_object_load_auth(ectx, ctx.credentialed_key.ctx_path,
        ctx.credentialed_key.auth_str, &ctx.credentialed_key.object, false,
        TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */
    rc = tpm2_util_aux_sessions_setup(ectx, ctx.aux_session_cnt,
        ctx.aux_session_path, ctx.aux_session_handle, ctx.aux_session);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. Command specific initializations
     */
    rc = read_cert_secret() ? tool_rc_success : tool_rc_general_error;
    if (rc != tool_rc_success) {
        return rc;
    }


    return rc;
}

//TODO CHANGE WITH A BUFFER RECEIVED FROM CA
static bool read_cert_secret(void) {

    bool result = false;
    FILE *fp = fopen(ctx.credential_blob_path, "rb");
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