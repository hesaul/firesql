AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	connection.h \
			proxy.h \
			decoder.h \
			mysql_decoder.h \
			visitor_decoder.h

firesql_SOURCES = 	mysql_decoder.cc \
			connection.cc \
			proxy.cc \
			main.cc

firesql_CPPFLAGS = $(BOOST_CPPFLAGS)
firesql_LDFLAGS = -lpthread -lstdc++ -lboost_system -lboost_thread
firesql_LDADD = $(BOOST_LIBS)

bin_PROGRAMS = firesql

CLEANFILES = *.o *.lo

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

