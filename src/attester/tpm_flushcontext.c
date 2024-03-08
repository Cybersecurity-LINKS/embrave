// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "tpm_flushcontext.h"

static struct tpm_flush_context_ctx ctx;

tool_rc tpm_flushcontext(ESYS_CONTEXT *ectx) {

    ctx.context_arg = "/var/embrave/attester/session.ctx";

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

    return tool_rc_general_error;
}