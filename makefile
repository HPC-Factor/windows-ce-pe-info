CC?=gcc
CFLAGS=-I.
DEPS=src/WinCePEHeader.h src/WinCEArchitecture.h src/cjson/cJSON.h
OUT_DIR=dist

# PREFIX is environment variable, but if it is not set, then set default value
ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

wcepeinfo: src/wcepeinfo.o src/cjson/cJSON.o
	$(shell mkdir -p $(OUT_DIR))
	$(CC) -o $(OUT_DIR)/wcepeinfo src/wcepeinfo.o src/cjson/cJSON.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

install: clean wcepeinfo
	install -m 655 dist/wcepeinfo $(PREFIX)/bin/

clean:
	rm -f src/*.o src/cjson/*.o dist/wcepeinfo dist/wcepeinfo.exe