CONFIGFILE_PROPER = config.mk
include $(CONFIGFILE_PROPER)

CC   = $(CC_PREFIX)gcc
GCOV = gcov

CFLAGS_COVERAGE  = -g -O0 -pedantic -fprofile-arcs -ftest-coverage
LDFLAGS_COVERAGE = -lgcov -fprofile-arcs

CFLAGS  = -std=c11 $(CFLAGS_COVERAGE)
LDFLAGS = -lblake $(LDFLAGS_COVERAGE)

coverage: check
	$(GCOV) -pr $(SRC) 2>&1
