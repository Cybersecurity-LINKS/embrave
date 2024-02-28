// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

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
