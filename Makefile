# If you set D=1 on the command line then $(D:1=-g)
# returns -g, else it returns the default (-O2).
D = -O2
CFLAGS += -Wall $(D:1=-g)

WANT_FORWARDING=0
WANT_BEARSSL=1

ifeq ($(WANT_FORWARDING),1)
CFLAGS += -DWANT_FORWARDING
LIBS += -L/usr/local/lib -lcurl
endif

ifeq ($(WANT_BEARSSL),1)
BEARDIR ?= ./BearSSL
BEARLIB = $(BEARDIR)/build/libbearssl.a
CFLAGS += -I $(BEARDIR)/inc
LIBS += $(BEARLIB)
endif

VERSION=1.1

all: $(BEARLIB) rtf imap-rtf learnem rtfsort regex-check clean-imap fetch

rtf: rtf.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

imap-rtf: imap-rtf.c bear.c bear-tools.c eyemap.c config.c diary.c
	$(CC) $(CFLAGS) -DIMAP -o $@ $+ $(LIBS)
	@etags $+

fetch: fetch.c eyemap.c config.c bear.c bear-tools.c
	$(CC) $(CFLAGS) -DIMAP -o $@ $+ $(LIBS)

clean-imap: clean-imap.c eyemap.c bear.c bear-tools.c config.c
	$(CC) $(CFLAGS) -DIMAP -o $@ $+ $(LIBS)
	@etags $+

$(BEARLIB):
	make -C BearSSL -j8

tarball:
	rm -rf rtf-$(VERSION)
	mkdir rtf-$(VERSION)
	cp rtf.c learnem.c rtfsort.c regex-check.c rtf.h Makefile README logrotate.rtf rtf-$(VERSION)
	tar zcf rtf-$(VERSION).tar.gz rtf-$(VERSION)
	rm -rf rtf-$(VERSION)

install:
	mkdir -p $(DESTDIR)/usr/bin
	install rtf     $(DESTDIR)/usr/bin
	install learnem $(DESTDIR)/usr/bin
	install rtfsort $(DESTDIR)/usr/bin
	mkdir -p $(DESTDIR)/etc/logrotate.d
	install -m 644 logrotate.rtf $(DESTDIR)/etc/logrotate.d/rtf

install-strip: install
	strip $(DESTDIR)/usr/bin/*

clean:
	rm -f rtf imap-rtf learnem rtfsort regex-check TAGS rtf-*.tar.gz

real-clean: clean
	make -C BearSSL clean
