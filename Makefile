# If you set D=1 on the command line then $(D:1=-g)
# returns -g, else it returns the default (-O2).
D = -O2
CFLAGS += -Wall $(D:1=-g)

VERSION=1.0

all: rtf learnem rtfsort

tarball:
	rm -rf rtf-$(VERSION)
	mkdir rtf-$(VERSION)
	cp rtf.c learnem.c rtfsort.c rtf.h Makefile README logrotate.rtf rtf-$(VERSION)
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
	rm -f rtf learnem rtfsort TAGS rtf-*.tar.gz

