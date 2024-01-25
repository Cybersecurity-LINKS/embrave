#include "tpm_flushcontext.h"

static struct tpm_flush_context_ctx ctx;

tool_rc tpm_flushcontext(ESYS_CONTEXT *ectx) {

    //UNUSED(flags);
    ctx.context_arg = "/var/lemon/attester/session.ctx";

    /* if (ctx.property) {
        TPMS_CAPABILITY_DATA *capability_data;
        tool_rc rc = tpm2_capability_get(ectx, TPM2_CAP_HANDLES, ctx.property,
                TPM2_MAX_CAP_HANDLES, &capability_data);
        if (rc != tool_rc_success) {
            return rc;
        }

        TPML_HANDLE *handles = &capability_data->data.handles;
        rc = flush_contexts_tpm2(ectx, handles->handle, handles->count);
        free(capability_data);
        return rc;
    } */

    if (!ctx.context_arg) {
        LOG_ERR("Specify options to evict handles or a session context.");
        return tool_rc_option_error;
    }

    TPM2_HANDLE handle;
    bool result = tpm2_util_string_to_uint32(ctx.context_arg, &handle);
    if (!result) {
        /* hmm not a handle, try a session */
        tpm2_session *s = NULL;
        tool_rc rc = tpm2_session_restore(ectx, ctx.context_arg, true, &s);
        if (rc != tool_rc_success) {
            return rc;
        }

        tpm2_session_close(&s);

        return tool_rc_success;
    }

    /* its a handle, call flush */
    /* ESYS_TR tr_handle = ESYS_TR_NONE;
    tool_rc rc = tpm2_util_sys_handle_to_esys_handle(ectx, handle, &tr_handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    return flush_contexts_tr(ectx, &tr_handle, 1); */
    return tool_rc_general_error;
}