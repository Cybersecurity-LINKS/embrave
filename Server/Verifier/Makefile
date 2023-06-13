#define the C compiler to use
CC = gcc
CFLAGS = -g

# define the C source files
#SRCS = PoC_TPA.c ${WAM_DIR}/WAM/WAM.c tpm2_createek.c tpm2_createak.c tpm2_quote.c\
 createek_util.c createak_util.c PCR9Extend.c PEMconvertPub.c ../IMA/ima_read_writeOut_binary.c all_util.c

SRCS = client.c ../Mongoose/mongoose.c ../../Agents/Remote_Attestor/RA.c ../../Protocols/Explicit/Explicit.c\
../../Protocols/common.c ../../Protocols/tpm_tools/tpm2_quote.c ../../Protocols/tpm_tools/tpm2_utils.c
# define any library to link into executable:
#  if I want to link libraries (libx.so or libx.a) I use the -llibname option
FLAGS = -lssl -lcrypto -D MG_IO_SIZE=102004\
-ltss2-esys -ltss2-tctildr -ltss2-mu -lssl #-lcrypto

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