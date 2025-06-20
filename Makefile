# ---------- Makefile ----------
CC   ?= gcc
LIB  ?= libprocesshider.so

all: $(LIB)

$(LIB): processhider.c
	$(CC) -Wall -fPIC -shared -Wl,-soname,$(LIB) -o $@ $< -ldl

.PHONY: clean
clean:
	rm -f $(LIB)
