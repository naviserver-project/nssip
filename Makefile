NAVISERVER=/usr/local/ns

#
# Module name
#
MOD      =  nssip.so

#
# Objects to build.
#
OBJS     = nssip.o

#
# Objects to clean
#
CLEAN   += clean-bak

CFLAGS = -I. -g -O2 -pthread

MODLIBS = -losipparser2 -losip2 -lpthread

include  $(NAVISERVER)/include/Makefile.module

clean-bak:
	rm -rf *~
