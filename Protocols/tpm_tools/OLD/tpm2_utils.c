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

tool_rc tpm2_tr_get_name(ESYS_CONTEXT *esys_context, ESYS_TR handle,
        TPM2B_NAME **name) {

    TSS2_RC rval = Esys_TR_GetName(esys_context, handle, name);
    if (rval != TSS2_RC_SUCCESS) {
        //LOG_PERR(Esys_TR_GetName, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}
/* 
TPMI_ALG_HASH tpm2_util_calculate_phash_algorithm(ESYS_CONTEXT *ectx,
    const char **cphash_path, TPM2B_DIGEST *cp_hash, const char **rphash_path,
    TPM2B_DIGEST *rp_hash, tpm2_session **sessions) {

    // <halg> specified in pHash path 
    TPMI_ALG_HASH cphash_alg = cphash_path ? calc_phash_alg_from_phash_path(
        cphash_path) : TPM2_ALG_ERROR;

    TPMI_ALG_HASH rphash_alg = rphash_path ? calc_phash_alg_from_phash_path(
        rphash_path) : TPM2_ALG_ERROR;
    //
     // Default to cphash_alg if both are specified.
     // This removes the conflict if cphash_alg and rphash_alg don't match.
     // This also sets the cphash_alg if only rphash_alg is specified and vice
     // versa.
     //
    TPMI_ALG_HASH phash_alg = cphash_alg != TPM2_ALG_ERROR ? cphash_alg :
        (rphash_alg != TPM2_ALG_ERROR ? rphash_alg : TPM2_ALG_ERROR);

    if (phash_alg != TPM2_ALG_ERROR) {
        goto out;
    }

    // <halg> determined from the sessions 
    if (sessions) {
        phash_alg = tpm2_util_calc_phash_algorithm_from_session_types(ectx,
            sessions);
    }

out:
    // <halg> defaults to TPM2_ALG_SHA256 if cannot find from path or sessions 
    if (phash_alg == TPM2_ALG_ERROR) {
        phash_alg = TPM2_ALG_SHA256;
    }

    //
     // Side-effect: Set the size of the cp_hash and/or rp_hash
     //
    if (cphash_path && cp_hash) {
        cp_hash->size = tpm2_alg_util_get_hash_size(phash_alg);
    }

    if (rphash_path && rp_hash) {
        rp_hash->size = tpm2_alg_util_get_hash_size(phash_alg);
    }

    return phash_alg;
}
 */
void tpm2_util_hexdump(FILE *f, const BYTE *data, size_t len) {

    size_t i;
    for (i = 0; i < len; i++) {
        fprintf(f, "%02x", data[i]);
    }
}

/* static TPMI_ALG_HASH calc_phash_alg_from_phash_path(const char **phash_path) {

    if (!*phash_path) {
        return TPM2_ALG_ERROR;
    }
    
    
     // Expecting single token, so tokenize just once.
     
    char *str = malloc(strlen(*phash_path) + 1);
    strcpy(str, *phash_path);
    char *token = strtok(str, ":");

    TPMI_ALG_HASH hashalg = tpm2_alg_util_from_optarg(
        token, tpm2_alg_util_flags_hash);
    
     // Adjust the pHash path to skip the <halg>:
     
    if (hashalg != TPM2_ALG_ERROR) {
        *phash_path += strlen(token) + 1;
    }

    free(str);
    return hashalg;
}
 */
static TPMI_ALG_HASH tpm2_util_calc_phash_algorithm_from_session_types(
    ESYS_CONTEXT *ectx, tpm2_session **sessions) {

    TPMI_ALG_HASH rethash = TPM2_ALG_ERROR;

    size_t session_idx = 0;
    for (session_idx = 0; session_idx < MAX_SESSION_CNT; session_idx++) {
        if(!sessions[session_idx]) {
            continue;
        }

        /*
         * Ignore password sessions
         */
        ESYS_TR session_handle = tpm2_session_get_handle(sessions[session_idx]);
        if(session_handle == ESYS_TR_PASSWORD) {
            continue;
        }

        /*
         * Ignore trial sessions
         */
        TPM2_SE session_type = tpm2_session_get_type(sessions[session_idx]);
        if (session_type != TPM2_SE_HMAC && session_type != TPM2_SE_POLICY) {
            continue;
        }

        /*
         * If this is an audit session, use that session halg.
         * Note: Audit sessions are always HMAC type.
         */
        if (session_type == TPM2_SE_HMAC) {
            TPMA_SESSION attrs = 0;
            tool_rc tmp_rc = tpm2_sess_get_attributes(ectx, session_handle,
                &attrs);
            UNUSED(tmp_rc);

            if (attrs & TPMA_SESSION_AUDIT) {
                rethash = tpm2_session_get_authhash(sessions[session_idx]);
                break;
            }
        }

        /*
         * If no other sessions remain, simply use (policy)sessions halg.
         */
        rethash = tpm2_session_get_authhash(sessions[session_idx]);
    }

    return rethash;
}

tool_rc tpm2_sess_get_attributes(ESYS_CONTEXT *esys_context, ESYS_TR session,
        TPMA_SESSION *flags) {

    TSS2_RC rval = Esys_TRSess_GetAttributes(esys_context, session, flags);
    if (rval != TSS2_RC_SUCCESS) {
       // LOG_PERR(Esys_TRSess_GetAttributes, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

TPMI_ALG_HASH tpm2_session_data_get_authhash(tpm2_session_data *data) {
    return data->auth_hash;
}

TPMI_ALG_HASH tpm2_session_get_authhash(tpm2_session *session) {
    return session->input->auth_hash;
}

TPM2_SE tpm2_session_get_type(tpm2_session *session) {
    return session->input->session_type;
}

tool_rc tpm2_session_close(tpm2_session **s) {

    if (!*s) {
        return tool_rc_success;
    }

    /*
     * Do not back up:
     *   - password sessions are implicit
     *   - hmac sessions live the life of the tool
     */
    tool_rc rc = tool_rc_success;
    tpm2_session *session = *s;
    if (session->output.session_handle == ESYS_TR_PASSWORD) {
        goto out2;
    }

    const char *path = session->internal.path;
    FILE *session_file = path ? fopen(path, "w+b") : NULL;
    if (path && !session_file) {
        printf("Could not open path \"%s\", due to error: \"%s\"", path,
                strerror(errno));
        rc = tool_rc_general_error;
        goto out;
    }

    bool flush = path ? session->internal.is_final : true;
    if (flush) {
        rc = tpm2_flush_context(session->internal.ectx,
                session->output.session_handle, NULL, TPM2_ALG_NULL);
        /* done, use rc to indicate status */
        goto out;
    }
    /*
     //
    // Now write the session_type, handle and auth hash data to disk
     //
    bool result = files_write_header(session_file, SESSION_VERSION);
    if (!result) {
        printf("Could not write context file header\n");
        rc = tool_rc_general_error;
        goto out;
    }

    // UINT8 session type:
    TPM2_SE session_type = session->input->session_type;
    result = files_write_bytes(session_file, &session_type,
            sizeof(session_type));
    if (!result) {
        printf("Could not write session type\n");
        rc = tool_rc_general_error;
        goto out;
    }

    // UINT16 - auth hash digest
    TPMI_ALG_HASH hash = tpm2_session_get_authhash(session);
    result = files_write_16(session_file, hash);
    if (!result) {
        printf("Could not write auth hash\n");
        rc = tool_rc_general_error;
        goto out;
    }

    ///
     //* Save session context at end of tpm2_session. With tabrmd support it
    // * can be reloaded under certain circumstances.
     //
   
    ESYS_TR handle = tpm2_session_get_handle(session);
    printf("Saved session: ESYS_TR(0x%x)\n", handle);
    rc = files_save_tpm_context_to_file(session->internal.ectx, handle,
    session_file);
    if (rc != tool_rc_success) {
        printf("Could not write session context\n");
        // done, free session resources and use rc to indicate status
    } */

out:
    if (session_file) {
        fclose(session_file);
    }
out2:
    tpm2_session_free(s);

    return rc;
}
void tpm2_session_free(tpm2_session **session) {

    tpm2_session *s = *session;

    if (s) {
        free(s->input);
        if (s->internal.path) {
            free(s->internal.path);
        }
        free(s);
        *session = NULL;
    }
}

tool_rc pcr_read_pcr_values(ESYS_CONTEXT *esys_context,
        TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *cp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm) {

    TPML_PCR_SELECTION pcr_selection_tmp;
    TPML_PCR_SELECTION *pcr_selection_out;
    UINT32 pcr_update_counter;

    //1. prepare pcrSelectionIn with g_pcrSelections
    memcpy(&pcr_selection_tmp, pcr_select, sizeof(pcr_selection_tmp));

    //2. call pcr_read
    pcrs->count = 0;
    do {
        TPML_DIGEST *v;
        tool_rc rc = tpm2_pcr_read(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, &pcr_selection_tmp, &pcr_update_counter,
                &pcr_selection_out, &v, cp_hash, parameter_hash_algorithm);

        if (rc != tool_rc_success || (cp_hash && cp_hash->size)) {
            return rc;
        }

        pcrs->pcr_values[pcrs->count] = *v;

        free(v);

        //3. unmask pcrSelectionOut bits from pcrSelectionIn
        pcr_update_pcr_selections(&pcr_selection_tmp, pcr_selection_out);

        free(pcr_selection_out);

        //4. goto step 2 if pcrSelctionIn still has bits set
    } while (++pcrs->count < ARRAY_LEN(pcrs->pcr_values)
            && !pcr_unset_pcr_sections(&pcr_selection_tmp));

    if (pcrs->count >= ARRAY_LEN(pcrs->pcr_values)
            && !pcr_unset_pcr_sections(&pcr_selection_tmp)) {
        printf("too much pcrs to get! try to split into multiple calls...");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

tool_rc tpm2_pcr_read(ESYS_CONTEXT *esys_context, ESYS_TR shandle1,
        ESYS_TR shandle2, ESYS_TR shandle3,
        const TPML_PCR_SELECTION *pcr_selection_in, UINT32 *pcr_update_counter,
        TPML_PCR_SELECTION **pcr_selection_out, TPML_DIGEST **pcr_values,
        TPM2B_DIGEST *cp_hash, TPMI_ALG_HASH parameter_hash_algorithm) {

    TSS2_RC rval = TSS2_RC_SUCCESS;
    tool_rc rc = tool_rc_success;
    if (cp_hash && cp_hash->size) {
        /*
         * Need sys_context to be able to calculate CpHash
         */
        TSS2_SYS_CONTEXT *sys_context = 0;
        rc = tpm2_getsapicontext(esys_context, &sys_context);
        if(rc != tool_rc_success) {
            printf("Failed to acquire Tss2_Sys_PCR_Read_Prepare SAPI context.");
            return rc;
        }

        TSS2_RC rval = Tss2_Sys_PCR_Read_Prepare(
        sys_context, pcr_selection_in);
        if (rval != TPM2_RC_SUCCESS) {
            //LOG_PERR(Tss2_Sys_PCR_Read_Prepare, rval);
            return tool_rc_general_error;
        }

        rc = tpm2_sapi_getcphash(sys_context, NULL, NULL, NULL,
            parameter_hash_algorithm, cp_hash);

        goto tpm2_pcrread_skip_esapi_call;
    }
    
    rval = Esys_PCR_Read(esys_context, shandle1, shandle2, shandle3,
            pcr_selection_in, pcr_update_counter, pcr_selection_out, pcr_values);
    if (rval != TSS2_RC_SUCCESS) {
        //LOG_PERR(Esys_PCR_Read, rval);
        return tool_rc_from_tpm(rval);
    }

tpm2_pcrread_skip_esapi_call:
    return rc;
}

tool_rc files_tpm2b_attest_to_tpms_attest(TPM2B_ATTEST *quoted, TPMS_ATTEST *attest) {

    size_t offset = 0;
    TSS2_RC rval = Tss2_MU_TPMS_ATTEST_Unmarshal(quoted->attestationData,
            quoted->size, &offset, attest);
    if (rval != TSS2_RC_SUCCESS) {
        //LOG_PERR(Tss2_MU_TPM2B_ATTEST_Unmarshal, rval);
        return tool_rc_from_tpm(rval);
    }

    return tool_rc_success;
}

// show all PCR banks according to g_pcrSelection & g_pcrs->
bool tpm2_openssl_hash_pcr_banks(TPMI_ALG_HASH hash_alg,
        TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *digest) {

    UINT32 vi = 0, di = 0, i;
    bool result = false;

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(hash_alg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        printf("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
       // LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    // Loop through all PCR/hash banks
    for (i = 0; i < pcr_select->count; i++) {

        // Loop through all PCRs in this bank
        unsigned int pcr_id;
        for (pcr_id = 0; pcr_id < pcr_select->pcrSelections[i].sizeofSelect * 8u;
                pcr_id++) {
            if (!tpm2_util_is_pcr_select_bit_set(&pcr_select->pcrSelections[i],
                    pcr_id)) {
                // skip non-selected banks
                continue;
            }
            if (vi >= pcrs->count || di >= pcrs->pcr_values[vi].count) {
                printf("Something wrong, trying to print but nothing more");
                goto out;
            }

            // Update running digest (to compare with quote)
            TPM2B_DIGEST *b = &pcrs->pcr_values[vi].digests[di];
            rc = EVP_DigestUpdate(mdctx, b->buffer, b->size);
            if (!rc) {
                printf("%s", tpm2_openssl_get_err());
                goto out;
            }

            if (++di < pcrs->pcr_values[vi].count) {
                continue;
            }

            di = 0;
            if (++vi < pcrs->count) {
                continue;
            }
        }
    }

    // Finalize running digest
    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
    if (!rc) {
        //printf("%s", tpm2_openssl_get_err());
        goto out;
    }

    digest->size = size;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

bool tpm2_util_verify_digests(TPM2B_DIGEST *quoteDigest,
        TPM2B_DIGEST *pcr_digest) {

    // Sanity check -- they should at least be same size!
    if (quoteDigest->size != pcr_digest->size) {
        printf("FATAL ERROR: PCR values failed to match quote's digest!");
        return false;
    }

    // Compare running digest with quote's digest
    int k;
    for (k = 0; k < quoteDigest->size; k++) {
        if (quoteDigest->buffer[k] != pcr_digest->buffer[k]) {
            printf("FATAL ERROR: PCR values failed to match quote's digest!");
            return false;
        }
    }

    return true;
}

tool_rc tpm2_flush_context(ESYS_CONTEXT *esys_context, ESYS_TR flush_handle,
    TPM2B_DIGEST *cp_hash, TPMI_ALG_HASH parameter_hash_algorithm) {

   tool_rc rc = tool_rc_success;
   TSS2_RC rval = TSS2_RC_SUCCESS;
    if (cp_hash && cp_hash->size) {
        /*
         * Need sys_context to be able to calculate CpHash
         */
        TSS2_SYS_CONTEXT *sys_context = 0;
        rc = tpm2_getsapicontext(esys_context, &sys_context);
        if(rc != tool_rc_success) {
            printf("Failed to acquire Tss2_Sys_FlushContext_Prepare SAPI context.");
            return rc;
        }

        TPM2_HANDLE sapi_flush_handle = 0;
        rval = Esys_TR_GetTpmHandle(esys_context, flush_handle,
            &sapi_flush_handle);
        if (rval != TPM2_RC_SUCCESS) {
            printf("Failed to acquire SAPI handle");
            return tool_rc_general_error;
        }

        TSS2_RC rval = Tss2_Sys_FlushContext_Prepare(
        sys_context, sapi_flush_handle);
        if (rval != TPM2_RC_SUCCESS) {
            printf("Failed to run Tss2_Sys_FlushContext_Prepare");
            return tool_rc_general_error;
        }

        /*
         * There is a bug in SAPI where in the flush handle is placed in the
         * handle area instead of the parameter area.
         * Ref: https://github.com/tpm2-software/tpm2-tss/issues/2382
         *
         * We determine this scenario by reading the parameter size in the
         * cpBuffer which is returned as zero due to the bug. 
         *
         * When calculating the cpHash, the workaround for this scenario is to
         * provide the flush handle as a name.
         */
        const uint8_t *command_parameters;
        size_t command_parameters_size;
        rval = Tss2_Sys_GetCpBuffer(sys_context, &command_parameters_size,
            &command_parameters);
        if (rval != TPM2_RC_SUCCESS) {
            printf("Failed to run Tss2_Sys_GetCpBuffer\n");
            return tool_rc_general_error;
        }

        TPM2B_NAME name1 = { 0 };
        if (!command_parameters_size) {
            name1.size = sizeof(TPM2_HANDLE);
            rval = Tss2_MU_TPM2_HANDLE_Marshal(sapi_flush_handle, name1.name,
                name1.size, 0);
            if (rval != TPM2_RC_SUCCESS) {
                printf("Failed to populate SAPI handle\n");
                return tool_rc_general_error;
            }
        }

        rc = tpm2_sapi_getcphash(sys_context, name1.size ? &name1 : NULL, NULL,
            NULL, parameter_hash_algorithm, cp_hash);
        /*
         * Exit here without making the ESYS call since we just need the cpHash
         */
        goto tpm2_flushcontext_skip_esapi_call;
    }

    rval = Esys_FlushContext(esys_context, flush_handle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("Failed to run Esys_FlushContext\n");
        return tool_rc_from_tpm(rval);
    }

tpm2_flushcontext_skip_esapi_call:
    return rc;
}

static void pcr_update_pcr_selections(TPML_PCR_SELECTION *s1,
        TPML_PCR_SELECTION *s2) {
    UINT32 i1, i2, j;
    for (i2 = 0; i2 < s2->count; i2++) {
        for (i1 = 0; i1 < s1->count; i1++) {
            if (s2->pcrSelections[i2].hash != s1->pcrSelections[i1].hash)
                continue;

            for (j = 0; j < s1->pcrSelections[i1].sizeofSelect; j++)
                s1->pcrSelections[i1].pcrSelect[j] &=
                        ~s2->pcrSelections[i2].pcrSelect[j];
        }
    }
}

static bool pcr_unset_pcr_sections(TPML_PCR_SELECTION *s) {
    UINT32 i, j;
    for (i = 0; i < s->count; i++) {
        for (j = 0; j < s->pcrSelections[i].sizeofSelect; j++) {
            if (s->pcrSelections[i].pcrSelect[j]) {
                return false;
            }
        }
    }

    return true;
}