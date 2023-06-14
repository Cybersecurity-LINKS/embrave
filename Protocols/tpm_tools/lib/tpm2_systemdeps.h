/* SPDX-License-Identifier: BSD-3-Clause */
//This code is based on tpm2-tools <github.com/tpm2-software/tpm2-tools>
#ifndef SYSTEM_H
#define SYSTEM_H

#if defined __FreeBSD__ || defined __DragonFly__
# include <sys/endian.h>
#else
# include <endian.h>
#endif

#endif
