# If you set D=1 on the command line then $(D:1=-g)
# returns -g, else it returns the default (-O2).
D = -O2
CFLAGS += -Wall $(D:1=-g)
CFLAGS += -DSAMLIB

all: rtf learnem rtfsort rtfdbdump

rtf: rtf.c
	$(CC) $(CFLAGS) -o $@ $+ -lsamlib -ldb

rtfdbdump: rtfdbdump.c
	$(CC) $(CFLAGS) -o $@ $+ -lsamlib -ldb

clean:
	rm -f rtf learnem rtfsort rtfdbdump
