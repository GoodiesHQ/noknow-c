PROJECT:=noknow
STDVER:=c99
SRCDIR:=src
SRCEXT:=.c
INCDIR:=inc mbedtls/include
INCEXT:=.h
OBJDIR:=${SRCDIR}/obj
LIBDIR:=lib mbedtls/library
BINDIR:=bin
CC=gcc
LIBS=mbedtls mbedcrypto mbedx509
CFLAGS := -Wall -Wextra -Werror -pedantic --std=$(STDVER) $(foreach DIR, $(INCDIR), -I${DIR}) ${CFLAGS}
LFLAGS := -static $(foreach DIR, $(LIBDIR), -L${DIR}) $(foreach LIB, $(LIBS), -l$(LIB))
OBJECTS=$(patsubst $(SRCDIR)/%$(SRCEXT),$(OBJDIR)/%.o,$(wildcard $(SRCDIR)/*$(SRCEXT)))

.PHONY: build
build: dirs bins

.PHONY: debug
debug: CFLAGS := -g -DDEBUG ${CFLAGS}
debug: LFLAGS := -g ${LFLAGS}
debug: build

.PHONY: release
release: CFLAGS := -O3 ${CFLAGS}
release: build

$(OBJDIR)/%.o: $(SRCDIR)/%$(SRCEXT)
	$(CC) -c $< $(CFLAGS) -o $@

$(BINDIR)/$(PROJECT): $(OBJECTS)
	$(CC) $^ $(LFLAGS) -o $@

bins: $(BINDIR)/$(PROJECT)

dirs:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)

.PHONY: clean
clean:
	@rm -f $(OBJECTS)
