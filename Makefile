.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

OS = linux
# Linux:   linux
# Mac OS:  macos
# Windows: windows
include mk/$(OS).mk


LIB_MAJOR = 1
LIB_MINOR = 2
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)
LIB_NAME = ar2


OBJ =\
	libar2_decode_base64.o\
	libar2_decode_params.o\
	libar2_encode_base64.o\
	libar2_encode_params.o\
	libar2_erase.o\
	libar2_hash.o\
	libar2_hash_buf_size.o\
	libar2_latest_argon2_version.o\
	libar2_string_to_type.o\
	libar2_string_to_version.o\
	libar2_type_to_string.o\
	libar2_validate_params.o\
	libar2_version_to_string.o\
	libar2_version_to_string_proper.o

HDR =\
	libar2.h\
	common.h

LOBJ = $(OBJ:.o=.lo)
MAN3 = $(OBJ:.o=.3) libar2_init.3
MAN7 = libar2.7

SRC = $(OBJ:.o=.c) $(HDR) test.c


all: libar2.a libar2.$(LIBEXT) test
$(OBJ): $(HDR)
$(LOBJ): $(HDR)
test.o: test.c $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

test: test.o libar2.a
	$(CC) -o $@ test.o libar2.a $(LDFLAGS)

libar2.a: $(OBJ)
	@rm -f -- $@
	$(AR) rc $@ $(OBJ)

libar2.$(LIBEXT): $(LOBJ)
	$(CC) $(LIBFLAGS) -o $@ $(LOBJ) $(LDFLAGS)

check: test
	./test

install: libar2.a libar2.$(LIBEXT)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man3"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man7"
	cp -- libar2.a "$(DESTDIR)$(PREFIX)/lib/"
	cp -- libar2.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/libar2.$(LIBMINOREXT)"
	$(FIX_INSTALL_NAME) "$(DESTDIR)$(PREFIX)/lib/libar2.$(LIBMINOREXT)"
	ln -sf -- libar2.$(LIBMINOREXT) "$(DESTDIR)$(PREFIX)/lib/libar2.$(LIBMAJOREXT)"
	ln -sf -- libar2.$(LIBMAJOREXT) "$(DESTDIR)$(PREFIX)/lib/libar2.$(LIBEXT)"
	cp -- libar2.h "$(DESTDIR)$(PREFIX)/include/"
	cp -- $(MAN3) "$(DESTDIR)$(MANPREFIX)/man3/"
	cp -- $(MAN7) "$(DESTDIR)$(MANPREFIX)/man7/"
	ln -sf -- libar2_encode_base64.3 "$(DESTDIR)$(MANPREFIX)/man3/libar2_encode_base64_overlap_support.3"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libar2.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libar2.$(LIBMAJOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libar2.$(LIBMINOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libar2.$(LIBEXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/include/libar2.h"
	-cd -- "$(DESTDIR)$(MANPREFIX)/man3/" && rm -f -- $(MAN3)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man7/" && rm -f -- $(MAN7)
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man3/libar2_encode_base64_overlap_support.3"

clean:
	-rm -f -- *.o *.a *.lo *.su *.so *.so.* *.dll *.dylib
	-rm -f -- *.gch *.gcov *.gcno *.gcda *.$(LIBEXT) test

.SUFFIXES:
.SUFFIXES: .lo .o .c

.PHONY: all check install uninstall clean
