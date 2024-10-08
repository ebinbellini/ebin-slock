# slock version
VERSION = 2.0

# Customize below to fit your system

# paths
PREFIX = /usr/local

X11INC = /usr/X11R6/include
X11LIB = /usr/X11R6/lib

# includes and libs
INCS = -I. -I/usr/include -I${X11INC} -I/usr/include/freetype2 \
	-I/usr/include/libpng16 -I/usr/include/harfbuzz -I/usr/include/glib-2.0 \
	-I/usr/lib/glib-2.0/include -I/usr/include/sysprof-6 -pthread

LIBS = -L/usr/lib -lc -lcrypt -L${X11LIB} -lX11 -lXext \
	-lXft -lfontconfig -lfreetype -lm -lImlib2

# flags
CPPFLAGS = -DVERSION=\"${VERSION}\" -DHAVE_SHADOW_H
CFLAGS = -std=c99 -pedantic -Wall -Os ${INCS} ${CPPFLAGS}
LDFLAGS = -s ${LIBS}

# On *BSD remove -DHAVE_SHADOW_H from CPPFLAGS and add -DHAVE_BSD_AUTH
# On OpenBSD and Darwin remove -lcrypt from LIBS

# compiler and linker
CC = cc

# Install mode. On BSD systems MODE=2755 and GROUP=auth
# On others MODE=4755 and GROUP=root
#MODE=2755
#GROUP=auth
