CFLAGS += -Wall -O2

all: rtf learnem

mailhdrsize: mailhdrsize.c

clean:
	rm -f rtf learnem mailhdrsize
