#define the C compiler to use
CC = gcc
CFLAGS = -g  -Wall -fPIC 


# define the C source files
SRCS = server.c ../Mongoose/mongoose.c ../../Agents/TPA/TPA.c ../../Protocols/Explicit/Explicit.c\
../../Protocols/common.c  \
#tpm2tools lib
SRCS +=  ../../tpm2-tools/tools/tpm2_tool.c $(wildcard ../../tpm2-tools/lib/*.c) \

# define any library to link into executable:
#  if I want to link libraries (libx.so or libx.a) I use the -llibname option
FLAGS =\
-DMG_ENABLE_OPENSSL=1 -ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-sys -ltss2-rc -lssl -lcrypto -lsqlite3 -DDEBUG=1

LDFLAGS+= -I../../tpm2-tools/tools/ -I../../tpm2-tools/lib/\

# define the executable file
MAIN = TPA

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SRCS) -o $(MAIN) $(LDFLAGS) $(FLAGS)

.PHONY: clean
clean:
	$(RM) $(MAIN)