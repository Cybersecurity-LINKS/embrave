#define the C compiler to use
CC = gcc
CFLAGS = -g  -Wall -fPIC 


# define the C source files
SRCS = server.c ../Mongoose/mongoose.c ../../Agents/TPA/TPA.c ../../Protocols/Explicit/Explicit.c\
../../Protocols/common.c  \
#tpm2tools lib
SRCS +=  ../../tpm2-tools/tools/tpm2_tool.c $(wildcard ../../tpm2-tools/lib/*.c) 
# files.c ../../tpm_tools/lib/log.c
# ../../Protocols/tpm_tools/lib/object.c ../../Protocols/tpm_tools/lib/pcr.c\
#../../Protocols/tpm_tools/lib/tpm2.c ../../Protocols/tpm_tools/lib/tpm2_util.c ../../Protocols/tpm_tools/lib/ ../../Protocols/tpm_tools/lib/tool_rc.c\
../../Protocols/tpm_tools/lib/tpm2_alg_util.c ../../Protocols/tpm_tools/lib/tpm2_attr_util.c ../../Protocols/tpm_tools/lib/tpm2_auth_util.c\
../../Protocols/tpm_tools/lib/tpm2_capability.c ../../Protocols/tpm_tools/lib/tpm2_cc_util.c ../../Protocols/tpm_tools/lib/tpm2_convert.c ../../Protocols/tpm_tools/lib/tpm2_ctx_mgmt.c\
../../Protocols/tpm_tools/lib/tpm2_errata.c ../../Protocols/tpm_tools/lib/tpm2_eventlog_yaml.c ../../Protocols/tpm_tools/lib/tpm2_eventlog.c ../../Protocols/tpm_tools/lib/tpm2_hash.c\
../../Protocols/tpm_tools/lib/tpm2_hierarchy.c ../../Protocols/tpm_tools/lib/tpm2_identity_util.c ../../Protocols/tpm_tools/lib/tpm2_kdfa.c ../../Protocols/tpm_tools/lib/tpm2_kdfe.c\
../../Protocols/tpm_tools/lib/tpm2_openssl.c ../../Protocols/tpm_tools/lib/tpm2_options.c\
../../Protocols/tpm_tools/lib/tpm2_session.c ../../Protocols/tpm_tools/lib/tpm2_policy.c ../../Protocols/tpm_tools/lib/tpm2_tool_output.c\

# define any library to link into executable:
#  if I want to link libraries (libx.so or libx.a) I use the -llibname option
FLAGS =\
-ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-sys -ltss2-rc -lssl -lcrypto -lsqlite3

LDFLAGS+= -I../../tpm2-tools/tools/ -I../../tpm2-tools/lib/\

# define the executable file
MAIN = TPA

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SRCS) -o $(MAIN) $(LDFLAGS) $(FLAGS)

.PHONY: clean
clean:
	$(RM) $(MAIN)