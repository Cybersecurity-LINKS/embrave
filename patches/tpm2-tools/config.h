/* lib/config.h.  Generated from config.h.in by configure.  */
/* lib/config.h.in.  Generated from configure.ac by autoheader.  */

/* Some versions of libc cause a sigsegv on exit with dlclose(), this disables
   the dlclose() and works around that bug */
/* #undef DISABLE_DLCLOSE */

/* Esys2.3 */
/* #undef ESYS_2_3 */

/* Esys3.0 */
/* #undef ESYS_3_0 */

/* Esys4.0 */
#define ESYS_4_0 1

/* fapi3.0.0 */
#define FAPI_3_0 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <efivar/efivar.h> header file. */
/* #undef HAVE_EFIVAR_EFIVAR_H */

/* Support EVP_sm3 in openssl */
#define HAVE_EVP_SM3 1

/* Support EVP_sm4_cfb in openssl */
#define HAVE_EVP_SM4_CFB 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Define if debugging is disabled */
#define NDEBUG 1

/* Name of package */
#define PACKAGE "tpm2-tools"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "tpm2-tools"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "tpm2-tools "

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "tpm2-tools"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION ""