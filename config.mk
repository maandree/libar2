PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CC = cc

COMMON_SANITIZE = -fsanitize=alignment,shift,signed-integer-overflow,object-size,null,undefined,bounds,address
CLANG_SANITIZE  = -O1 $(COMMON_SANITIZE),cfi -flto -fvisibility=hidden -fno-sanitize-trap=cfi
GCC_SANITIZE    = -O1 $(COMMON_SANITIZE)
#SANITIZE        = $(CLANG_SANITIZE)
#SANITIZE        = $(GCC_SANITIZE)

CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CFLAGS   = $(SANITIZE) -std=c11 -Wall -O3
LDFLAGS  = $(SANITIZE) -lblake -s
