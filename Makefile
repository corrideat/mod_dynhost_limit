APXS=apxs2
VERSION=`cat VERSION`
DISTFILES=`cat FILES`

all: mod_dynhost_limit.o

install:
	$(APXS) -i mod_dynhost_limit.la

clean:
	for ext in lo la slo; do find . -type f -name \*.$ext -print0 | xargs -0 rm -f; done
	rm -rf .libs
	rm -rf mod_dynhost_limit-$(VERSION)
	rm -rf mod_dynhost_limit-$(VERSION).tar.gz

mod_dynhost_limit.o: mod_dynhost_limit.c
	$(APXS) -Wc,-Wall -Wc,-Werror -Wc,-g, Wl,--as-needed -Wc,-DNO_DEBUG -DLOG -DTRANSFER -DSUPHP -c -lldap_r mod_dynhost_limit.c

format:
	indent *.c
