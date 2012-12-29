AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	connection.h \
			proxy.h

firesql_SOURCES = 	connection.cc \
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

