// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "tpm_startauthsession.h"

static tpm2_startauthsession_ctx ctx = {
    .attrs = TPMA_SESSION_CONTINUESESSION,
    .is_real_policy_session =  true,
    .session = {
        .type = TPM2_SE_TRIAL,
        .halg = TPM2_ALG_SHA256,
        .sym = {
            .algorithm = TPM2_ALG_AES,
            .keyBits = { .aes = 128 },
            .mode = { .aes = TPM2_ALG_CFB }
        },
    },
    .name = {
        .size = BUFFER_SIZE(TPM2B_NAME, name)
    },
    .output = {
        .path = "/var/lemon/attester/session.ctx"
    }
};

static tool_rc setup_session_data(void) {

    if (ctx.is_real_policy_session) {
        ctx.session.type = TPM2_SE_POLICY;
    }

    if (ctx.is_hmac_session) {
        ctx.session.type = TPM2_SE_HMAC;
    }

    ctx.session_data = tpm2_session_data_new(ctx.session.type);
    if (!ctx.session_data) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    tpm2_session_set_path(ctx.session_data, ctx.output.path);

    tpm2_session_set_authhash(ctx.session_data, ctx.session.halg);

    if (ctx.is_session_encryption_possibly_needed) {

        tpm2_session_set_symmetric(ctx.session_data, &ctx.session.sym);
    }

    if (ctx.session.bind.bind_context_arg_str) {
        tpm2_session_set_bind(ctx.session_data,
        ctx.session.bind.bind_context_object.tr_handle);
    }

    if (ctx.session.tpmkey.key_context_arg_str) {
        tpm2_session_set_key(ctx.session_data,
        ctx.session.tpmkey.key_context_object.tr_handle);
    }

    tpm2_session_set_attrs(ctx.session_data, ctx.attrs);

    return tool_rc_success;
}

static tool_rc process_input_data(ESYS_CONTEXT *ectx) {

    if (ctx.name_path) {
        bool ret = files_load_bytes_from_path(ctx.name_path, ctx.name.name, &ctx.name.size);
        if (!ret) {
            LOG_ERR("Could load name from path: \"%s\"", ctx.name_path);
            return tool_rc_general_error;
        }
    }

    /*
     * Backwards compatibility behavior/ side-effect:
     *
     * The presence of a tpmkey and bind object should not result in setting up
     * the session for parameter encryption. It is not a requirement. IOW one
     * can have a salted and bounded session and not perform parameter
     * encryption.
     */

    if (ctx.session.tpmkey.key_context_arg_str) {
    /*
     * attempt to set up the encryption parameters for this, we load an ESYS_TR
     * from disk for transient objects and we load from tpm public for
     * persistent objects. Deserialized ESYS TR objects are checked.
     */
        tool_rc rc = tpm2_util_object_load(ectx,
                ctx.session.tpmkey.key_context_arg_str,
                &ctx.session.tpmkey.key_context_object, TPM2_HANDLE_ALL_W_NV);
        if (rc != tool_rc_success) {
            return rc;
        }

        /* if loaded object is non-permanant, it should ideally be persistent */
        if (ctx.session.tpmkey.key_context_object.handle) {

            bool is_transient = (ctx.session.tpmkey.key_context_object.handle
                    >> TPM2_HR_SHIFT) == TPM2_HT_TRANSIENT;
            if (!is_transient && !ctx.name_path) {
                LOG_WARN("check public portion of the tpmkey manually");
            }

            /*
             * ESAPI performs this check when an ESYS_TR or Context file is used, so we
             * could only run the check on the case where a raw TPM handle is provided,
             * however, it seems prudent that if the user specifies a name, we always
             * just check it.
             */
            if (ctx.name_path) {
                TPM2B_NAME *got_name = NULL;
                rc = tpm2_tr_get_name(ectx, ctx.session.tpmkey.key_context_object.tr_handle,
                        &got_name);
                if (rc != tool_rc_success) {
                    return rc;
                }

                bool is_expected = cmp_tpm2b(name, &ctx.name, got_name);
                Esys_Free(got_name);
                if (!is_expected) {
                    LOG_ERR("Expected name does not match");
                    return tool_rc_general_error;
                }
            }
        }
    }

    /*
     * We need to load the bind object and set its auth value in the bind
     * objects ESYS_TR.
     *
     * A loaded object creates another session and that is not what we want.
     */
    if (ctx.session.bind.bind_context_arg_str) {
        tool_rc rc = tpm2_util_object_load(ectx,
                ctx.session.bind.bind_context_arg_str,
                &ctx.session.bind.bind_context_object, TPM2_HANDLE_ALL_W_NV);
        if (rc != tool_rc_success) {
            return rc;
         }
    }

    if (ctx.session.bind.bind_context_auth_str) {
        TPM2B_AUTH authvalue = { 0 };
        bool result = handle_password(
            ctx.session.bind.bind_context_auth_str, &authvalue);
        if (!result) {
            return tool_rc_general_error;
        }

        tool_rc rc = tpm2_tr_set_auth(ectx,
        ctx.session.bind.bind_context_object.tr_handle, &authvalue);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed setting auth in the bind object ESYS_TR");
            return rc;
        }
    }

    return setup_session_data();
}

tool_rc tpm_startauthsession(ESYS_CONTEXT *ectx) {
    tool_rc rc;

    //Process inputs
    rc = process_input_data(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    //ESAPI call to start session
    tpm2_session *s = NULL;
    rc = tpm2_session_open(ectx, ctx.session_data, &s);
    if (rc != tool_rc_success) {
        fprintf(stderr, "ERROR: Could not start tpm session\n");
        return rc;
    }

    //Process outputs
    return tpm2_session_close(&s);
}