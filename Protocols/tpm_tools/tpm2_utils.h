/* SPDX-License-Identifier: BSD-3-Clause */
//This code is based on tpm2-tools <github.com/tpm2-software/tpm2-tools>
#include <tss2/tss2_esys.h>
//#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_sys.h>

#include <stdbool.h>
#include <getopt.h>
#include <stdio.h>

#include <string.h>
#include <strings.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/rsa.h>
#else
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#endif

#define UNUSED(x) (void)x

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define PSTR(x) x ? x : "(null)"

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }
#define TPM2B_INIT(xsize) { .size = xsize, }

#define TPM2B_EMPTY_INIT TPM2B_INIT(0)
#define TPM2B_SENSITIVE_CREATE_EMPTY_INIT { \
           .sensitive = { \
                .data = {   \
                    .size = 0 \
                }, \
                .userAuth = {   \
                    .size = 0 \
                } \
            } \
    }

typedef enum tpm2_convert_sig_fmt tpm2_convert_sig_fmt;
enum tpm2_convert_sig_fmt {
    signature_format_tss,
    signature_format_plain,
    signature_format_err
};


typedef enum tpm2_convert_pcrs_output_fmt tpm2_convert_pcrs_output_fmt;
enum tpm2_convert_pcrs_output_fmt {
    pcrs_output_format_values,
    pcrs_output_format_serialized,
    pcrs_output_format_err
};


/* do not port to TSS below here */
typedef enum tool_rc tool_rc;
enum tool_rc {
    /* do not reorder or change, part of returned codes to exit */
    /* maps to common/returns.md */
    tool_rc_success = 0,
    tool_rc_general_error,
    tool_rc_option_error,
    tool_rc_auth_error,
    tool_rc_tcti_error,
    tool_rc_unsupported
};

/* Definition of TPMT_SIG_SCHEME Structure */
typedef struct TPMT_SIG_SCHEME TPMT_SIG_SCHEME;

/* Definition of TPML_PCR_SELECTION Structure */
/* typedef struct TPML_PCR_SELECTION TPML_PCR_SELECTION;
struct TPML_PCR_SELECTION {
    UINT32 count; // number of selection structures. A value of zero is allowed. 
    TPMS_PCR_SELECTION pcrSelections[TPM2_NUM_PCR_BANKS]; // list of selections
}; */

typedef struct tpm2_pcrs tpm2_pcrs;
struct tpm2_pcrs {
    size_t count;
    TPML_DIGEST pcr_values[TPM2_MAX_PCRS];
};

typedef struct tpm2_session_data tpm2_session_data;
typedef struct tpm2_session tpm2_session;

struct tpm2_session_data {
    ESYS_TR key;
    ESYS_TR bind;
    TPM2_SE session_type;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH auth_hash;
    TPM2B_NONCE nonce_caller;
    TPMA_SESSION attrs;
    TPM2B_AUTH auth_data;
    const char *path;
};

struct tpm2_session {

    tpm2_session_data* input;

    struct {
        ESYS_TR session_handle;
    } output;

    struct {
        char *path;
        ESYS_CONTEXT *ectx;
        bool is_final;
    } internal;
};

typedef struct tpm2_loaded_object tpm2_loaded_object;
struct tpm2_loaded_object {
    TPM2_HANDLE handle;
    ESYS_TR tr_handle;
    const char *path;
    tpm2_session *session;
};


typedef enum tpm2_handle_flags tpm2_handle_flags;
enum tpm2_handle_flags {
    TPM2_HANDLE_FLAGS_NONE = 0,
    TPM2_HANDLE_FLAGS_O = 1 << 0,
    TPM2_HANDLE_FLAGS_P = 1 << 1,
    TPM2_HANDLE_FLAGS_E = 1 << 2,
    TPM2_HANDLE_FLAGS_N = 1 << 3,
    TPM2_HANDLE_FLAGS_L = 1 << 4,
    TPM2_HANDLE_FLAGS_ALL_HIERACHIES = 0x1F,
    TPM2_HANDLES_FLAGS_TRANSIENT = 1 << 5,
    TPM2_HANDLES_FLAGS_PERSISTENT = 1 << 6,
    /* bits 7 and 8 are mutually exclusive */
    TPM2_HANDLE_FLAGS_NV = 1 << 7,
    TPM2_HANDLE_ALL_W_NV = 0xFF,
    TPM2_HANDLE_FLAGS_PCR = 1 << 8,
    TPM2_HANDLE_ALL_W_PCR = 0x17F,
};

typedef struct tpm2_algorithm tpm2_algorithm;
struct tpm2_algorithm {
    int count;
    TPMI_ALG_HASH alg[TPM2_NUM_PCR_BANKS];
};

tool_rc tpm2_getsapicontext(ESYS_CONTEXT *esys_context, TSS2_SYS_CONTEXT **sys_context);
tool_rc tpm2_quote(ESYS_CONTEXT *esys_context, tpm2_loaded_object *quote_obj,
    TPMT_SIG_SCHEME *in_scheme, TPM2B_DATA *qualifying_data,
    TPML_PCR_SELECTION *pcr_select, TPM2B_ATTEST **quoted,
    TPMT_SIGNATURE **signature, TPM2B_DIGEST *cp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm);
tool_rc tpm2_auth_util_get_shandle(ESYS_CONTEXT *ectx, ESYS_TR object,
        tpm2_session *session, ESYS_TR *out);
ESYS_TR tpm2_session_get_handle(tpm2_session *session);
const TPM2B_AUTH *tpm2_session_get_auth_value(tpm2_session *session);
tool_rc tpm2_tr_set_auth(ESYS_CONTEXT *esys_context, ESYS_TR handle,
        TPM2B_AUTH const *auth_value);
/* tool_rc tpm2_util_object_load_auth(ESYS_CONTEXT *ctx, const char *objectstr,
        const char *auth, tpm2_loaded_object *outobject,
        bool is_restricted_pswd_session, tpm2_handle_flags flags); */
tool_rc tpm2_get_capability(ESYS_CONTEXT *esys_context, ESYS_TR shandle1,
        ESYS_TR shandle2, ESYS_TR shandle3, TPM2_CAP capability,
        UINT32 property, UINT32 property_count, TPMI_YES_NO *more_data,
        TPMS_CAPABILITY_DATA **capability_data);
tool_rc tool_rc_from_tpm(TSS2_RC rc);
UINT8 *tpm2_convert_sig(UINT16 *size, TPMT_SIGNATURE *signature);
static UINT8 *extract_ecdsa(TPMS_SIGNATURE_ECDSA *ecdsa, UINT16 *size);
UINT16 tpm2_alg_util_get_hash_size(TPMI_ALG_HASH id);
tool_rc tpm2_sapi_getcphash(TSS2_SYS_CONTEXT *sys_context,
    const TPM2B_NAME *name1, const TPM2B_NAME *name2, const TPM2B_NAME *name3,
    TPMI_ALG_HASH halg, TPM2B_DIGEST *cp_hash);
bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer,
        UINT16 length, TPM2B_DIGEST *digest);
const EVP_MD *tpm2_openssl_md_from_tpmhalg(TPMI_ALG_HASH algorithm);
/* static tool_rc tpm2_util_object_load2(ESYS_CONTEXT *ctx, const char *objectstr,
        const char *auth, bool do_auth, tpm2_loaded_object *outobject,
        bool is_restricted_pswd_session, tpm2_handle_flags flags); */
