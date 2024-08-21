# slock - simple screen locker
# See LICENSE file for copyright and license details.

include config.mk

SRC = slock.c drw/drw.c drw/util.c
OBJ = slock.o drw.o util.o

all: options ebin-slock

options:
	@echo slock build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ}: config.mk

ebin-slock:
	@echo ${CC} -o $@ ${SRC} ${LDFLAGS} ${CFLAGS}
	@${CC} -o $@ ${SRC} ${LDFLAGS} ${CFLAGS}

clean:
	@echo cleaning
	@rm -f ebin-slock ${OBJ} ebin-slock-${VERSION}.tar.gz

dist: clean
	@echo creating dist tarball
	@mkdir -p ebin-slock-${VERSION}
	@cp -R LICENSE Makefile README config.mk ${SRC} ebin-slock-${VERSION}
	@tar -cf ebin-slock-${VERSION}.tar ebin-slock-${VERSION}
	@gzip ebin-slock-${VERSION}.tar
	@rm -rf ebin-slock-${VERSION}

install: all
	@echo installing executable file to ${DESTDIR}${PREFIX}/bin
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	@cp -f ebin-slock ${DESTDIR}${PREFIX}/bin
	@chmod 755 ${DESTDIR}${PREFIX}/bin/ebin-slock
	@chmod u+s ${DESTDIR}${PREFIX}/bin/ebin-slock

uninstall:
	@echo removing executable file from ${DESTDIR}${PREFIX}/bin
	@rm -f ${DESTDIR}${PREFIX}/bin/ebin-slock

.PHONY: all options clean dist install uninstall
