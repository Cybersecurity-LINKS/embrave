#define the C compiler to use
CC = gcc
CFLAGS = -g

# define the C source files
SRCS = server_Mongoose.c ../Mongoose/mongoose.c ../../Agents/TPA/TPA.c ../../Protocols/Explicit/Explicit.c\
 #tpm2_createek.c tpm2_createak.c 
# define any library to link into executable:
#  if I want to link libraries (libx.so or libx.a) I use the -llibname option
FLAGS =\
-ltss2-esys -ltss2-tctildr -ltss2-mu -lssl -lcrypto

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
MAIN = TPA

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SRCS) -o $(MAIN) $(LDFLAGS) $(FLAGS)

.PHONY: clean
clean:
	$(RM) $(MAIN)