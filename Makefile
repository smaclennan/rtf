# If you set D=1 on the command line then $(D:1=-g)
# returns -g, else it returns the default (-O2).
D = -O2
CFLAGS += -Wall $(D:1=-g)

all: rtf learnem rtfsort

rtf: rtf.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f rtf learnem rtfsort TAGS
