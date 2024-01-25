#ifndef TPM_FLUSHCONTEXT
#define TPM_FLUSHCONTEXT

#include <stdlib.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_capability.h"
#include "tpm2_options.h"
#include "tpm2_session.h"

struct tpm_flush_context_ctx {
    TPM2_HANDLE property;
    char *context_arg;
    unsigned encountered_option;
};

tool_rc tpm_flushcontext(ESYS_CONTEXT *ectx);

#endif
