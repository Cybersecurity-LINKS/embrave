#include "tpm_ak.h"

tool_rc init_ak_public(TPMI_ALG_HASH name_alg, TPM2B_PUBLIC *public, struct createak_context *ctx) {

    const char *name_halg;
    char alg[256];

    name_halg = tpm2_alg_util_algtostr(name_alg, tpm2_alg_util_flags_hash);

    if (!strcmp(ctx->ak.in.alg.sign, "null")) {
        if (!strncmp(ctx->ak.in.alg.type, "rsa", 3)) {
            ctx->ak.in.alg.sign = "rsassa";
        } else if (!strncmp(ctx->ak.in.alg.type, "ecc", 3)) {
            ctx->ak.in.alg.sign = "ecdsa";
        }
    }
    if (!strcmp(ctx->ak.in.alg.type, "keyedhash"))
    {
        ctx->ak.in.alg.type = "hmac";
    }
    if (!strcmp(ctx->ak.in.alg.type, "hmac"))
    {
        snprintf(alg, sizeof(alg), "%s:%s", ctx->ak.in.alg.type,
            ctx->ak.in.alg.digest);

    } else {
        snprintf(alg, sizeof(alg), "%s:%s-%s:null", ctx->ak.in.alg.type,
        ctx->ak.in.alg.sign, ctx->ak.in.alg.digest);
    }
    return tpm2_alg_util_public_init(alg, name_halg, NULL, NULL, ATTRS, public);
}

tool_rc _create_ak(ESYS_CONTEXT *ectx){

    struct createak_context ctx = {
        .ak = {
            .in = {
                .alg = {
                    .type = "rsa2048",
                    .digest = "sha256",
                    .sign = "null"
                },
            },
            .out = {
                .pub_fmt = pubkey_format_tss
            },
        },
        .flags = { 0 },
    };

    tool_rc rc = tool_rc_general_error;

    TPML_PCR_SELECTION creation_pcr = { .count = 0 };
    TPM2B_DATA outside_info = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC *out_public;
    TPM2B_PRIVATE *out_private;
    TPM2B_PUBLIC in_public;
    TPML_DIGEST pHashList = { .count = 2 };

    /* get the nameAlg of the EK */
    TPM2_ALG_ID ek_name_alg = tpm2_alg_util_get_name_alg(ectx, ctx.ek.ek_ctx.tr_handle);
    if (ek_name_alg == TPM2_ALG_ERROR) {
        return tool_rc_general_error;
    }

    /* select the matching EK templates */
    switch (ek_name_alg) {
    case TPM2_ALG_SHA384:
        pHashList.digests[0] = policy_a_sha384;
        pHashList.digests[1] = policy_c_sha384;
        break;
    case TPM2_ALG_SHA512:
        pHashList.digests[0] = policy_a_sha512;
        pHashList.digests[1] = policy_c_sha512;
        break;
    case TPM2_ALG_SM3_256:
        pHashList.digests[0] = policy_a_sm3_256;
        pHashList.digests[1] = policy_c_sm3_256;
        break;
    case TPM2_ALG_SHA256:
    default:
        pHashList.count = 0;
        break;
    }

    tool_rc tmp_rc = init_ak_public(ek_name_alg, &in_public, &ctx);
    if (tmp_rc != tool_rc_success) {
        return tmp_rc;
    }

    tpm2_session_data *data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }
    tpm2_session_set_authhash(data, ek_name_alg);

    tpm2_session *session = NULL;
    tmp_rc = tpm2_session_open(ectx, data, &session);
    if (tmp_rc != tool_rc_success) {
        LOG_ERR("Could not start tpm session");
        return tmp_rc;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    ESYS_TR sess_handle = tpm2_session_get_handle(session);

    ESYS_TR shandle = ESYS_TR_NONE;
    tmp_rc = tpm2_auth_util_get_shandle(ectx, ESYS_TR_RH_ENDORSEMENT,
            ctx.ek.session, &shandle);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        goto out_session;
    }

    TPM2_RC rval = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, sess_handle,
            shandle, ESYS_TR_NONE, ESYS_TR_NONE,
            NULL, NULL, NULL, 0, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicySecret, rval);
        goto out_session;
    }

    LOG_INFO("Esys_PolicySecret success");

    if (pHashList.count > 1) {
        rval = Esys_PolicyOR(ectx, sess_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, &pHashList);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_PolicyOR, rval);
            goto out_session;
        }
    }

    TPM2B_CREATION_DATA *creation_data = NULL;
    rval = Esys_Create(ectx, ctx.ek.ek_ctx.tr_handle, sess_handle, ESYS_TR_NONE,
            ESYS_TR_NONE, &ctx.ak.in.in_sensitive, &in_public, &outside_info,
            &creation_pcr, &out_private, &out_public, &creation_data, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Create, rval);
        goto out;
    }
    LOG_INFO("Esys_Create success");

    rc = tpm2_session_close(&session);
    if (rc != tool_rc_success) {
        goto out;
    }

    data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        goto out;
    }
    tpm2_session_set_authhash(data, ek_name_alg);

    tmp_rc = tpm2_session_open(ectx, data, &session);
    if (tmp_rc != tool_rc_success) {
        LOG_ERR("Could not start tpm session");
        rc = tmp_rc;
        goto out;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    sess_handle = tpm2_session_get_handle(session);

    tmp_rc = tpm2_auth_util_get_shandle(ectx, sess_handle, ctx.ek.session,
            &shandle);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        goto out;
    }

    rval = Esys_PolicySecret(ectx, ESYS_TR_RH_ENDORSEMENT, sess_handle, shandle,
            ESYS_TR_NONE, ESYS_TR_NONE, NULL, NULL, NULL, 0, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_PolicySecret, rval);
        goto out;
    }
    LOG_INFO("Esys_PolicySecret success");

    if (pHashList.count > 1) {
        rval = Esys_PolicyOR(ectx, sess_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, &pHashList);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_PolicyOR, rval);
            goto out;
        }
    }

    ESYS_TR loaded_sha1_key_handle;
    rval = Esys_Load(ectx, ctx.ek.ek_ctx.tr_handle, sess_handle, ESYS_TR_NONE,
            ESYS_TR_NONE, out_private, out_public, &loaded_sha1_key_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Load, rval);
        rc = tool_rc_from_tpm(rval);
        goto out;
    }

    // Load the TPM2 handle so that we can print it
    TPM2B_NAME *key_name;
    rval = Esys_TR_GetName(ectx, loaded_sha1_key_handle, &key_name);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_GetName, rval);
        rc = tool_rc_from_tpm(rval);
        goto nameout;
    }

    rc = tpm2_session_close(&session);
    if (rc != tool_rc_success) {
        goto out;
    }

    /* generation qualified name */
    TPM2B_NAME *p_qname = &creation_data->creationData.parentQualifiedName;
    TPM2B_NAME qname = { 0 };
    rc = tpm2_calq_qname(p_qname,
            in_public.publicArea.nameAlg, key_name, &qname) ?
                    tool_rc_success : tool_rc_general_error;
    if (rc != tool_rc_success) {
        goto out;
    }

    /* Output in YAML format */
    tpm2_tool_output("loaded-key:\n  name: ");
    tpm2_util_print_tpm2b(key_name);
    tpm2_tool_output("\n");
    tpm2_tool_output("  qualified name: ");
    tpm2_util_print_tpm2b(&qname);
    tpm2_tool_output("\n");

    // write name to ak.name file
    if (ctx.ak.out.name_file) {
        if (!files_save_bytes_to_file(ctx.ak.out.name_file, key_name->name,
                key_name->size)) {
             LOG_ERR("Failed to save AK name into file \"%s\"",
                    ctx.ak.out.name_file);
            goto nameout;
        }
    }

    if (ctx.ak.out.qname_file) {
        if (!files_save_bytes_to_file(ctx.ak.out.qname_file, qname.name,
                qname.size)) {
            LOG_ERR("Failed to save AK qualified name into file \"%s\"",
                    ctx.ak.out.name_file);
            goto nameout;
        }
    }

    // If the AK isn't persisted we always save a context file of the
    // transient AK handle for future tool interactions.
    tmp_rc = files_save_tpm_context_to_path(ectx, loaded_sha1_key_handle,
            ctx.ak.out.ctx_file);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        LOG_ERR("Error saving tpm context for handle");
        goto nameout;
    }

    if (ctx.ak.out.pub_file) {
        if (!tpm2_convert_pubkey_save(out_public, ctx.ak.out.pub_fmt,
                ctx.ak.out.pub_file)) {
            goto nameout;
        }
    }

    if (ctx.ak.out.priv_file) {
        if (!files_save_private(out_private, ctx.ak.out.priv_file)) {
            goto nameout;
        }
    }

    rc = tool_rc_success;

nameout:
    free(key_name);
out:
    free(out_public);
    free(out_private);
    Esys_Free(creation_data);
out_session:
    tpm2_session_close(&session);

    return rc;

}