#define the C compiler to use
CC = gcc
CFLAGS = -g  -Wall -fPIC 

LEMONDIR=/home/ale/Scrivania/lemon
# define the C source files
SRCS = ${LEMONDIR}/src/attester/attester_server.c ${LEMONDIR}/lib/Mongoose/mongoose.c ${LEMONDIR}/src/attester/attester_agent.c ${LEMONDIR}/src/tpm.c\
${LEMONDIR}/src/common.c  \
#tpm2tools lib
SRCS +=   ${LEMONDIR}/lib/tpm2-tools/tools/tpm2_tool.c $(wildcard ${LEMONDIR}/lib/tpm2-tools/lib/*.c)

# define any library to link into executable:
#  if I want to link libraries (libx.so or libx.a) I use the -llibname option
FLAGS =\
-DMG_ENABLE_OPENSSL=1 -ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-sys -ltss2-rc -lssl -lcrypto -lsqlite3 -DDEBUG=1

LDFLAGS+= -I${LEMONDIR}/lib/tpm2-tools/tools/ -I${LEMONDIR}/lib/tpm2-tools/lib/ -I${LEMONDIR}/include/ -I${LEMONDIR}/lib/Mongoose/\

# define the executable file
MAIN = attester_server

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SRCS) -o $(MAIN) $(LDFLAGS) $(FLAGS)

.PHONY: clean
clean:
	$(RM) $(MAIN)