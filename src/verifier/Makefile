#define the C compiler to use
CC = gcc
CFLAGS = -g  -Wall -fPIC 

# define the C source files
SRCS = client.c ../Mongoose/mongoose.c ../../Agents/Remote_Attestor/RA.c ../../Protocols/Explicit/Explicit.c\
../../Protocols/common.c \


#tpm2tools lib
SRCS +=  ../../tpm2-tools/tools/tpm2_tool.c $(wildcard ../../tpm2-tools/lib/*.c) 
# define any library to link into executable:
#  if I want to link libraries (libx.so or libx.a) I use the -llibname option
FLAGS = -lssl -lcrypto \
-DMG_ENABLE_OPENSSL=1 -ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-sys -ltss2-rc -lssl -lsqlite3 -DDEBUG=1 #-DTESTS=1#-DFRESH=900000 #-lcrypto -D MG_IO_SIZE=102004

LDFLAGS+= -I../../tpm2-tools/tools/ -I../../tpm2-tools/lib/\

# define the executable file
MAIN = client

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SRCS) -o $(MAIN) $(LDFLAGS) $(FLAGS)

.PHONY: clean
clean:
	$(RM) $(MAIN)