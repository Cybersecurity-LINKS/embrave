#ifndef TPM2_QUOTE_H_
#define TPM2_QUOTE_H_

#include "./lib/tpm2.h"

tool_rc tpm2_quote_start(ESYS_CONTEXT *ectx);
tool_rc tpm2_quote_free(ESYS_CONTEXT *ectx);
bool set_option(char key, char *value);
#endif