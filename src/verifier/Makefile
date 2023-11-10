#define the C compiler to use
CC ?= gcc
CFLAGS =\
	-g  -Wall \
	-fPIC 

LEMONDIR=$(lemondir)
# define the C source files
SRCS = ${LEMONDIR}/src/verifier/verifier.c ${LEMONDIR}/lib/Mongoose/mongoose.c  ${LEMONDIR}/src/verifier/RA.c  ${LEMONDIR}/src/tpm.c\
${LEMONDIR}/src/common.c \


#tpm2tools lib
SRCS +=   ${LEMONDIR}/lib/tpm2-tools/tools/tpm2_tool.c $(wildcard ${LEMONDIR}/lib/tpm2-tools/lib/*.c) ${LEMONDIR}/lib/sqlite3/sqlite3.c
# define any library to link into executable:
#  if I want to link libraries (libx.so or libx.a) I use the -llibname option
FLAGS = -lssl -lcrypto \
-DMG_ENABLE_OPENSSL=1 -ltss2-esys  \
-ltss2-tctildr -ltss2-mu -ltss2-sys \
-ltss2-rc -lssl -DDEBUG=1 #-DTESTS=1#-DFRESH=900000 #-lcrypto -D MG_IO_SIZE=102004 -lsqlite3

LDFLAGS+= -I${LEMONDIR}/lib/tpm2-tools/tools/ -I${LEMONDIR}/lib/tpm2-tools/lib/ \
	-I${LEMONDIR}/include/ -I${LEMONDIR}/lib/mongoose/ \
	-I${LEMONDIR}/lib/sqlite3/

# define the executable file
executable =\
	$(O)/verifier

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SRCS) -o $(executable) $(LDFLAGS) $(FLAGS)

.PHONY: clean
clean:
	$(RM) $(executable)