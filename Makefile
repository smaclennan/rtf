# If you set D=1 on the command line then $(D:1=-g)
# returns -g, else it returns the default (-O2).
D = -O2
CFLAGS += -Wall $(D:1=-g)

# SAMLIB is only needed for logging blacklist usage.
# If SAMLIB not defined you do not need -lsamlib or -ldb
CFLAGS += -DSAMLIB
SAMLIB ?= -lsamlib
DB ?= -ldb

all: rtf learnem rtfsort rtfdbdump

rtf: rtf.c
	$(CC) $(CFLAGS) -o $@ $< $(SAMLIB) $(DB)

rtfdbdump: rtfdbdump.c
	$(CC) $(CFLAGS) -o $@ $< $(SAMLIB) $(DB)

clean:
	rm -f rtf learnem rtfsort rtfdbdump
