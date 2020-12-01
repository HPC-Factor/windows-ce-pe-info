CC=gcc
CFLAGS=-I. -fshort-wchar
DEPS=src/WinCePEHeader.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

build: src/wcepeinfo.o
	$(CC) -o dist/wcepeinfo src/wcepeinfo.o

clean:
	rm -f src/*.o