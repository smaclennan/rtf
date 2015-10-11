CFLAGS += -Wall -O2

all: rtf

rtf: rtf.c

mailhdrsize: mailhdrsize.c

clean:
	rm -f rtf mailhdrsize
