# --- Makefile ------------------------
LIB ?= libprocesshider.so       # 默认名，可用命令行覆盖

all: $(LIB)

$(LIB): processhider.c
	$(CC) -Wall -fPIC -shared \
	      -Wl,-soname,$(LIB) \   # <- 同步修改 SONAME
	      -o $@ $< -ldl

.PHONY: clean
clean:
	rm -f $(LIB)
