/* SPDX-License-Identifier: BSD-3-Clause */
//This code is based on tpm2-tools <github.com/tpm2-software/tpm2-tools>
#include "tpm2_utils.h"

#define UNFMT1(x) (x - TPM2_RC_FMT1)
#define UNVER1(x) (x - TPM2_RC_VER1)

static inline UINT16 tpm2_rc_fmt1_error_get(TPM2_RC rc) {
    return (rc & 0x3F);
}

static inline UINT16 tpm2_rc_fmt0_error_get(TPM2_RC rc) {
    return (rc & 0x7F);
}

static inline UINT8 tss2_rc_layer_format_get(TSS2_RC rc) {
    return ((rc & (1 << 7)) >> 7);
}

static tool_rc flatten_fmt1(TSS2_RC rc) {

    UINT8 errnum = tpm2_rc_fmt1_error_get(rc);
    switch (errnum) {
    case UNFMT1(TPM2_RC_AUTH_FAIL):
        return tool_rc_auth_error;
    default:
        return tool_rc_general_error;
    }
}

static tool_rc flatten_fmt0(TSS2_RC rc) {

    UINT8 errnum = tpm2_rc_fmt0_error_get(rc);
    switch (errnum) {
    case UNVER1(TPM2_RC_COMMAND_CODE):
        return tool_rc_unsupported;
    default:
        return tool_rc_general_error;
    }
}

tool_rc tool_rc_from_tpm(TSS2_RC rc) {

    bool is_fmt_1 = tss2_rc_layer_format_get(rc);
    if (is_fmt_1) {
        return flatten_fmt1(rc);
    }

    return flatten_fmt0(rc);
}

tool_rc tpm2_getsapicontext(ESYS_CONTEXT *esys_context,
    TSS2_SYS_CONTEXT **sys_context) {

    TSS2_RC rval = Esys_GetSysContext(esys_context, sys_context);
    if (rval != TPM2_RC_SUCCESS) {
        //LOG_PERR(Esys_GetSysContext, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

ESYS_TR tpm2_session_get_handle(tpm2_session *session) {
    return session->output.session_handle;
}

const TPM2B_AUTH *tpm2_session_get_auth_value(tpm2_session *session) {
    return &session->input->auth_data;
}

tool_rc tpm2_tr_set_auth(ESYS_CONTEXT *esys_context, ESYS_TR handle,
        TPM2B_AUTH const *auth_value) {

    TSS2_RC rval = Esys_TR_SetAuth(esys_context, handle, auth_value);
    if (rval != TSS2_RC_SUCCESS) {
        //LOG_PERR(Esys_SequenceComplete, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

tool_rc tpm2_auth_util_get_shandle(ESYS_CONTEXT *ectx, ESYS_TR object,
        tpm2_session *session, ESYS_TR *out) {

    *out = tpm2_session_get_handle(session);

    const TPM2B_AUTH *auth = tpm2_session_get_auth_value(session);

    return tpm2_tr_set_auth(ectx, object, auth);
}

tool_rc tpm2_quote(ESYS_CONTEXT *esys_context, tpm2_loaded_object *quote_obj,
    TPMT_SIG_SCHEME *in_scheme, TPM2B_DATA *qualifying_data,
    TPML_PCR_SELECTION *pcr_select, TPM2B_ATTEST **quoted,
    TPMT_SIGNATURE **signature, TPM2B_DIGEST *cp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm) {

    ESYS_TR quote_obj_session_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_auth_util_get_shandle(esys_context, quote_obj->tr_handle,
            quote_obj->session, &quote_obj_session_handle);
    if (rc != tool_rc_success) {
        printf("Failed to get shandle\n");
        return rc;
    }

    if (cp_hash && cp_hash->size) {
        /*
         * Need sys_context to be able to calculate CpHash
         */
        TSS2_SYS_CONTEXT *sys_context = 0;
        rc = tpm2_getsapicontext(esys_context, &sys_context);
        if(rc != tool_rc_success) {
            printf("Failed to acquire SAPI context.\n");
            return rc;
        }

        TSS2_RC rval = Tss2_Sys_Quote_Prepare(sys_context, quote_obj->handle,
        qualifying_data, in_scheme, pcr_select);
        if (rval != TPM2_RC_SUCCESS) {
            //LOG_PERR(Tss2_Sys_Quote_Prepare, rval);
            return tool_rc_general_error;
        }

        TPM2B_NAME *name1 = 0;
        rc = tpm2_tr_get_name(esys_context, quote_obj->tr_handle, &name1);
        if (rc != tool_rc_success) {
            goto tpm2_quote_free_name1;
        }

        rc = tpm2_sapi_getcphash(sys_context, name1, 0, 0,
            parameter_hash_algorithm, cp_hash);

        /*
         * Exit here without making the ESYS call since we just need the cpHash
         */
tpm2_quote_free_name1:
        Esys_Free(name1);
        goto tpm2_quote_skip_esapi_call;
    }

    TSS2_RC rval = Esys_Quote(esys_context, quote_obj->tr_handle,
            quote_obj_session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
            qualifying_data, in_scheme, pcr_select, quoted, signature);
    if (rval != TPM2_RC_SUCCESS) {
        //LOG_PERR(Esys_Quote, rval);
        return tool_rc_from_tpm(rval);
    }
tpm2_quote_skip_esapi_call:
    return rc;
}

/* tool_rc tpm2_util_object_load_auth(ESYS_CONTEXT *ctx, const char *objectstr,
        const char *auth, tpm2_loaded_object *outobject,
        bool is_restricted_pswd_session, tpm2_handle_flags flags) {

    return tpm2_util_object_load2(ctx, objectstr, auth, true, outobject,
            is_restricted_pswd_session, flags);
}

static tool_rc tpm2_util_object_load2(ESYS_CONTEXT *ctx, const char *objectstr,
        const char *auth, bool do_auth, tpm2_loaded_object *outobject,
        bool is_restricted_pswd_session, tpm2_handle_flags flags) {

    tool_rc rc = tool_rc_success;
    if (do_auth) {
        ESYS_CONTEXT *tmp_ctx = is_restricted_pswd_session ? NULL : ctx;
        tpm2_session *s = NULL;
        rc = tpm2_auth_util_from_optarg(tmp_ctx, auth, &s,
                is_restricted_pswd_session);
        if (rc != tool_rc_success) {
            return rc;
        }

        outobject->session = s;
    }

    if (!objectstr) {
        LOG_ERR("object string is empty");
        return tool_rc_general_error;
    }

    // 1. Attempt objectstr as a file path for context file.
    FILE *f = fopen(objectstr, "rb");
    if (f) {
        rc = tpm2_util_object_do_ctx_file(ctx, objectstr, f, outobject);
        fclose(f);
        if (rc == tool_rc_success) {
            return rc;
        }
    }

    // 2. Attempt converting objectstr to a hierarchy or raw handle
    TPMI_RH_PROVISION handle;
    bool result = tpm2_util_handle_from_optarg(objectstr, &handle, flags);
    if (result) {
        outobject->handle = handle;
        outobject->path = NULL;
        return tpm2_util_sys_handle_to_esys_handle(ctx, outobject->handle,
            &outobject->tr_handle);
    }

    // 3. Attempt objectstr as a file path for TSSPEM/ TSS-PRIVATE-KEY
    rc = tpm2_util_object_load_tsspem(ctx, objectstr, outobject);
    if (rc != tool_rc_success) {
        printf("Cannot make sense of object context \"%s\"\n", objectstr);
    }

    return rc;
} */

tool_rc pcr_get_banks(ESYS_CONTEXT *esys_context,
        TPMS_CAPABILITY_DATA *capability_data, tpm2_algorithm *algs) {

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capdata_ret;

    tool_rc rc = tpm2_get_capability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, TPM2_CAP_PCRS, no_argument, required_argument,
            &more_data, &capdata_ret);
    if (rc != tool_rc_success) {
        return rc;
    }

    *capability_data = *capdata_ret;

    unsigned i;

    // If the TPM support more bank algorithm that we currently
    // able to manage, throw an error
    if (capability_data->data.assignedPCR.count > ARRAY_LEN(algs->alg)) {
         printf("Current implementation does not support more than %zu banks, "
                "got %" PRIu32 " banks supported by TPM\n",
                sizeof(algs->alg), capability_data->data.assignedPCR.count); 
        free(capdata_ret);
        return tool_rc_general_error;
    }

    for (i = 0; i < capability_data->data.assignedPCR.count; i++) {
        algs->alg[i] = capability_data->data.assignedPCR.pcrSelections[i].hash;
    }
    algs->count = capability_data->data.assignedPCR.count;

    free(capdata_ret);
    return tool_rc_success;
}

tool_rc tpm2_get_capability(ESYS_CONTEXT *esys_context, ESYS_TR shandle1,
        ESYS_TR shandle2, ESYS_TR shandle3, TPM2_CAP capability,
        UINT32 property, UINT32 property_count, TPMI_YES_NO *more_data,
        TPMS_CAPABILITY_DATA **capability_data) {

    TSS2_RC rval = Esys_GetCapability(esys_context, shandle1, shandle2, shandle3,
            capability, property, property_count, more_data, capability_data);
    if (rval != TSS2_RC_SUCCESS) {
       // LOG_PERR(Esys_GetCapability, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

UINT8 *tpm2_convert_sig(UINT16 *size, TPMT_SIGNATURE *signature) {

    UINT8 *buffer = NULL;
    *size = 0;

    switch (signature->sigAlg) {
    case TPM2_ALG_RSASSA:
        *size = signature->signature.rsassa.sig.size;
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, signature->signature.rsassa.sig.buffer, *size);
        break;
    case TPM2_ALG_RSAPSS:
        *size = signature->signature.rsapss.sig.size;
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, signature->signature.rsapss.sig.buffer, *size);
        break;
    case TPM2_ALG_HMAC: {
        TPMU_HA *hmac_sig = &(signature->signature.hmac.digest);
        *size = tpm2_alg_util_get_hash_size(signature->signature.hmac.hashAlg);
        if (*size == 0) {
            printf("Hash algorithm %d has 0 size\n",
                    signature->signature.hmac.hashAlg);
            goto nomem;
        }
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, hmac_sig, *size);
        break;
    }
    case TPM2_ALG_ECDSA:
    case TPM2_ALG_SM2: {
        return extract_ecdsa(&signature->signature.ecdsa, size);
    }
    default:
        printf("%s: unknown signature scheme: 0x%x\n", __func__,
                signature->sigAlg);
        return NULL;
    }

    return buffer;
nomem:
    printf("%s: couldn't allocate memory", __func__);
    return NULL;
}

UINT16 tpm2_alg_util_get_hash_size(TPMI_ALG_HASH id) {

    switch (id) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
        /* no default */
    }

    return 0;
}

static UINT8 *extract_ecdsa(TPMS_SIGNATURE_ECDSA *ecdsa, UINT16 *size) {

    /* the DER encoded ECDSA signature */
    unsigned char *buf = NULL;

    TPM2B_ECC_PARAMETER *R = &ecdsa->signatureR;
    TPM2B_ECC_PARAMETER *S = &ecdsa->signatureS;

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (sig == NULL) {
        return NULL;
    }

    BIGNUM *bn_r = BN_bin2bn(R->buffer, R->size, NULL);
    if (!bn_r) {
        goto out;
    }

    BIGNUM *bn_s = BN_bin2bn(S->buffer, S->size, NULL);
    if (!bn_s) {
        BN_free(bn_r);
        goto out;
    }

    int rc = ECDSA_SIG_set0(sig, bn_r, bn_s);
    if (rc != 1) {
        BN_free(bn_r);
        BN_free(bn_s);
        goto out;
    }

    /*
     * r and s are now owned by the ecdsa signature no need
     * to free
     */

    int len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0) {
        goto out;
    }

    buf = malloc(len);
    if (!buf) {
        goto out;
    }

    unsigned char *pp = buf;
    len = i2d_ECDSA_SIG(sig, &pp);
    if (len <= 0) {
        free(buf);
        buf = NULL;
        goto out;
    }

    *size = len;
    /* success */

out:
    ECDSA_SIG_free(sig);

    return buf;
}

tool_rc tpm2_sapi_getcphash(TSS2_SYS_CONTEXT *sys_context,
    const TPM2B_NAME *name1, const TPM2B_NAME *name2, const TPM2B_NAME *name3,
    TPMI_ALG_HASH halg, TPM2B_DIGEST *cp_hash) {

    uint8_t command_code[4];
    TSS2_RC rval = Tss2_Sys_GetCommandCode(sys_context, &command_code[0]);
    if (rval != TPM2_RC_SUCCESS) {
        //LOG_PERR(Tss2_Sys_GetCommandCode, rval);
        return tool_rc_general_error;
    }

    const uint8_t *command_parameters;
    size_t command_parameters_size;
    rval = Tss2_Sys_GetCpBuffer(sys_context, &command_parameters_size,
        &command_parameters);
    if (rval != TPM2_RC_SUCCESS) {
        //LOG_PERR(Tss2_Sys_GetCpBuffer, rval);
        return tool_rc_general_error;
    }

    uint16_t to_hash_len = sizeof(command_code) + command_parameters_size;
    to_hash_len += name1 ? name1->size : 0;
    to_hash_len += name2 ? name2->size : 0;
    to_hash_len += name3 ? name3->size : 0;

    uint8_t *to_hash = malloc(to_hash_len);
    if (!to_hash) {
        printf("oom\n");
        return tool_rc_general_error;
    }

    //Command-Code
    memcpy(to_hash, command_code, sizeof(command_code));
    uint16_t offset = sizeof(command_code);

    //Names
    if (name1) {
        memcpy(to_hash + offset, name1->name, name1->size);
        offset += name1->size;
    }
    if (name2) {
        memcpy(to_hash + offset, name2->name, name2->size);
        offset += name2->size;
    }
    if (name3) {
        memcpy(to_hash + offset, name3->name, name3->size);
        offset += name3->size;
    }

    //CpBuffer
    memcpy(to_hash + offset, command_parameters, command_parameters_size);

    //cpHash
    tool_rc rc = tool_rc_success;
    bool result = tpm2_openssl_hash_compute_data(halg, to_hash, to_hash_len,
        cp_hash);
    free(to_hash);
    if (!result) {
        printf("Failed cpHash digest calculation.\n");
        rc = tool_rc_general_error;
    }

    return rc;
}

bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer,
        UINT16 length, TPM2B_DIGEST *digest) {

    bool result = false;

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(halg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        //LOG_ERR("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        ///LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    rc = EVP_DigestUpdate(mdctx, buffer, length);
    if (!rc) {
        //LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
    if (!rc) {
        //LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    digest->size = size;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

const EVP_MD *tpm2_openssl_md_from_tpmhalg(TPMI_ALG_HASH algorithm) {

    switch (algorithm) {
    case TPM2_ALG_SHA1:
        return EVP_sha1();
    case TPM2_ALG_SHA256:
        return EVP_sha256();
    case TPM2_ALG_SHA384:
        return EVP_sha384();
    case TPM2_ALG_SHA512:
        return EVP_sha512();
#if HAVE_EVP_SM3
	case TPM2_ALG_SM3_256:
		return EVP_sm3();
#endif
    default:
        return NULL;
    }
    /* no return, not possible */
}