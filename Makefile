ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nssip.so

#
# Objects to build.
#
OBJS     = nssip.o

CFLAGS = -I. -g -O2 -pthread

MODLIBS = -losipparser2 -losip2 -lpthread

include  $(NAVISERVER)/include/Makefile.module
