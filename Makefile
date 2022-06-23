all: chksan

chksan:
	$(CC) -o $@ chksan.c -O0

clean:
	rm -f chksan
