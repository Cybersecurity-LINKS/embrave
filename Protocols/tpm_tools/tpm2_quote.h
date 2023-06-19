#ifndef TPM2_QUOTE_H_
#define TPM2_QUOTE_H_

#include "./lib/tpm2.h"
#include "./lib/pcr.h"

int tpm2_quote_start(ESYS_CONTEXT *ectx);
tool_rc tpm2_quote_free(ESYS_CONTEXT *ectx);
bool set_option(char key, char *value);
TPM2B_ATTEST * get_quoted(void);
void print_tpm2b(TPM2B_ATTEST * quoted);
BYTE * get_signature(UINT16 *size);
//int get_pcrList(ESYS_CONTEXT *ectx, tpm2_pcrs *pcrs, TPML_PCR_SELECTION *pcr_selections);
int get_pcrList(ESYS_CONTEXT *ectx, tpm2_pcrs *pcrs);
void pcr_print_(TPML_PCR_SELECTION *pcrSelect, tpm2_pcrs *pcrs);
#endif