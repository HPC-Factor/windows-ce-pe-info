CC=gcc
CFLAGS=-I. -fshort-wchar
DEPS=src/WinCePEHeader.h

build: src/wcepeinfo.o
	$(CC) -o dist/wcepeinfo src/wcepeinfo.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f src/*.o dist/wcepeinfo

install: clean build
	install -m 655 dist/wcepeinfo $(DESTDIR)/bin/