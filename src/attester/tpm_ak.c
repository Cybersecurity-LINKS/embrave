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
        .ek = {
            .ctx_arg = "0x81000003"
        },
        .ak = {
            .in = {
                .alg = {
                    .type = "ecc", // Elliptical Curve, defaults to ecc256 // "rsa2048",
                    .digest = "sha256", // possible addition of checking if sha3 is supported by the installed TPM
                    .sign = "null" 
                },
            },
            .out = {
                .pub_file = "ak.pub.pem",
                .name_file = "ak.name",
                .pub_fmt = pubkey_format_pem,
                .ctx_file = "ak.ctx"
            },
        },
        .flags = { 0 },
    };

    /* if (ctx.flags.f && !ctx.ak.out.pub_file) {
        LOG_ERR("Please specify an output file name when specifying a format");
        return tool_rc_option_error;
    } */

    /* if (!ctx.ak.out.ctx_file) {
        LOG_ERR("Expected option -c");
        return tool_rc_option_error;
    } */

    tool_rc rc = tpm2_util_object_load(ectx, ctx.ek.ctx_arg, &ctx.ek.ek_ctx,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (!ctx.ek.ek_ctx.tr_handle) {
        rc = tpm2_util_sys_handle_to_esys_handle(ectx, ctx.ek.ek_ctx.handle,
                &ctx.ek.ek_ctx.tr_handle);
        if (rc != tool_rc_success) {
            LOG_ERR("Converting ek_ctx TPM2_HANDLE to ESYS_TR");
            return rc;
        }
    }

    rc = tpm2_auth_util_from_optarg(NULL, ctx.ek.auth_str, &ctx.ek.session,
            true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid endorse authorization");
        return rc;
    }

    tpm2_session *tmp;
    rc = tpm2_auth_util_from_optarg(NULL, ctx.ak.auth_str, &tmp, true);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid AK authorization");
        return rc;
    }

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
    ctx.ak.in.in_sensitive.sensitive.userAuth = *auth;

    tpm2_session_close(&tmp);

    rc = tool_rc_general_error;

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

tool_rc _evictcontrol(ESYS_CONTEXT *ectx){

    struct tpm_evictcontrol_ctx ctx = {
        .to_persist_key.ctx_path = "ak.ctx",
        .auth_hierarchy.ctx_path="o",
        .out_tr = ESYS_TR_NONE,
        .parameter_hash_algorithm = TPM2_ALG_ERROR,
    };

     bool result = tpm2_util_string_to_uint32("0x81000004", &ctx.persist_handle);
    if (!result) {
        LOG_ERR("Could not convert persistent handle to a number, got: \"%s\"",
            "0x81000004");
        return false;
    }
    ctx.is_persistent_handle_specified = true;

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
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.auth_hierarchy.ctx_path,
            ctx.auth_hierarchy.auth_str, &ctx.auth_hierarchy.object, false,
            TPM2_HANDLE_FLAGS_O | TPM2_HANDLE_FLAGS_P);
    if (rc != tool_rc_success) {
        return rc;
    }

    /* Object #2 */
    rc = tpm2_util_object_load(ectx, ctx.to_persist_key.ctx_path,
        &ctx.to_persist_key.object, TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    if (ctx.to_persist_key.object.handle >> TPM2_HR_SHIFT
            == TPM2_HT_PERSISTENT) {
        ctx.persist_handle = ctx.to_persist_key.object.handle;
        ctx.is_persistent_handle_specified = true;
    }

    /* If we've been given a handle or context object to persist and not an
     * explicit persistent handle to use, find an available vacant handle in
     * the persistent namespace and use that.
     *
     * XXX: We need away to figure out of object is persistent and skip it.
     */
    if (ctx.to_persist_key.ctx_path && !ctx.is_persistent_handle_specified) {
        bool is_platform = ctx.auth_hierarchy.object.handle == TPM2_RH_PLATFORM;
        rc = tpm2_capability_find_vacant_persistent_handle(ectx,
                is_platform, &ctx.persist_handle);
        if (rc != tool_rc_success) {
            return rc;
        }
        /* we searched and found a persistent handle, so mark that peristent handle valid */
        ctx.is_persistent_handle_specified = true;
    }

    /* if (ctx.output_arg && !ctx.is_persistent_handle_specified) {
        LOG_ERR("Cannot specify -o without using a persistent handle");
        return tool_rc_option_error;
    } */

    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.auth_hierarchy.object.session,
        0,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */
    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    rc = tpm2_evictcontrol(ectx, &ctx.auth_hierarchy.object,
        &ctx.to_persist_key.object, ctx.persist_handle, &ctx.out_tr,
        &ctx.cp_hash, ctx.parameter_hash_algorithm);

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

    rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */

    /*
     * Only Close a TR object if it's still resident in the TPM.
     * When these handles match, evictcontrol flushed it from the TPM.
     * It's evicted when ESAPI sends back a none handle on evictcontrol.
     *
     * XXX: This output is wrong because we can't determine what handle was
     * evicted on ESYS_TR input.
     *
     * See bug: https://github.com/tpm2-software/tpm2-tools/issues/1816
     */
    tpm2_tool_output("persistent-handle: 0x%x\n", ctx.persist_handle);

    bool is_evicted = (ctx.out_tr == ESYS_TR_NONE);
    tpm2_tool_output("action: %s\n", is_evicted ? "evicted" : "persisted");

    tool_rc tmp_rc = tool_rc_success;
    if (ctx.output_arg) {
        tmp_rc = files_save_ESYS_TR(ectx, ctx.out_tr, ctx.output_arg);
    }

    if (!is_evicted) {
        rc = tpm2_close(ectx, &ctx.out_tr);
    }

    return (tmp_rc == tool_rc_success) ? rc : tmp_rc;
}