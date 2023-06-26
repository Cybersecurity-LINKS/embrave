#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#define HANDLE_EK 0x81000003
#define HANDLE_AK 0x81000004 
#define TCG_EVENT_NAME_LEN_MAX	255
#define MAX_TEXT_EVENT 1000
#define HANDLE_SIZE 11

#define RA_TYPE_EXPLICIT 0
#define RA_TYPE_DAA 1

bool check_keys(uint16_t *ek_handle, uint16_t  *ak_handle);
int getCap_handles_persistent(ESYS_CONTEXT *esys_context, uint16_t *ek_handle, uint16_t *ak_handle);

#endif