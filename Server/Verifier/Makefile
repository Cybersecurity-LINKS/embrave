#define the C compiler to use
CC = gcc
CFLAGS = -g

# define the C source files
#SRCS = PoC_TPA.c ${WAM_DIR}/WAM/WAM.c tpm2_createek.c tpm2_createak.c tpm2_quote.c\
 createek_util.c createak_util.c PCR9Extend.c PEMconvertPub.c ../IMA/ima_read_writeOut_binary.c all_util.c

SRCS = client.c ../Mongoose/mongoose.c ../../Agents/Remote_Attestor/RA.c ../../Protocols/Explicit/Explicit.c\
../../Protocols/common.c ../../Protocols/tpm_tools/tpm2_quote.c\
../../Protocols/tpm_tools/lib/files.c ../../Protocols/tpm_tools/lib/log.c ../../Protocols/tpm_tools/lib/object.c ../../Protocols/tpm_tools/lib/pcr.c\
../../Protocols/tpm_tools/lib/tpm2.c ../../Protocols/tpm_tools/lib/tpm2_util.c ../../Protocols/tpm_tools/lib/tpm2_tool.c ../../Protocols/tpm_tools/lib/tool_rc.c\
../../Protocols/tpm_tools/lib/tpm2_alg_util.c ../../Protocols/tpm_tools/lib/tpm2_attr_util.c ../../Protocols/tpm_tools/lib/tpm2_auth_util.c\
../../Protocols/tpm_tools/lib/tpm2_capability.c ../../Protocols/tpm_tools/lib/tpm2_cc_util.c ../../Protocols/tpm_tools/lib/tpm2_convert.c ../../Protocols/tpm_tools/lib/tpm2_ctx_mgmt.c\
../../Protocols/tpm_tools/lib/tpm2_errata.c ../../Protocols/tpm_tools/lib/tpm2_eventlog_yaml.c ../../Protocols/tpm_tools/lib/tpm2_eventlog.c ../../Protocols/tpm_tools/lib/tpm2_hash.c\
../../Protocols/tpm_tools/lib/tpm2_hierarchy.c ../../Protocols/tpm_tools/lib/tpm2_identity_util.c ../../Protocols/tpm_tools/lib/tpm2_kdfa.c ../../Protocols/tpm_tools/lib/tpm2_kdfe.c\
../../Protocols/tpm_tools/lib/tpm2_openssl.c ../../Protocols/tpm_tools/lib/tpm2_options.c ../../Protocols/tpm_tools/lib/tpm2_session.c ../../Protocols/tpm_tools/lib/tpm2_policy.c ../../Protocols/tpm_tools/lib/tpm2_tool_output.c\
#../../Protocols/tpm_tools/tpm2_utils.c
# define any library to link into executable:
#  if I want to link libraries (libx.so or libx.a) I use the -llibname option
FLAGS = -lssl -lcrypto -D MG_IO_SIZE=102004\
-ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-sys -ltss2-rc -lssl #-lcrypto

#LDFLAGS+=\
-I${WAM_DIR} \
-I${WAM_DIR}/iota.c/build/include/ \
-I${WAM_DIR}/iota.c/build/include/cjson/ \
-I${WAM_DIR}/iota.c/build/include/client/ \
-I${WAM_DIR}/iota.c/build/include/crypto/ \
-I${WAM_DIR}/iota.c/build/include/core/ \

LDFLAGS+=
#LDFLAGS += \
-L${WAM_DIR}/iota.c/build/lib/ \
-liota_crypto -lcrypto -liota_core -liota_client -lcjson -lcurl -lsodium -lpthread

# define the executable file
MAIN = client

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SRCS) -o $(MAIN) $(LDFLAGS) $(FLAGS)

.PHONY: clean
clean:
	$(RM) $(MAIN)