AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	connection.h \
			proxy.h \
			mysql_decoder.h \
			rule.h \
			rule_manager.h 

firesql_SOURCES = 	rule.cc \
			mysql_decoder.cc \
			rule_manager.cc \
			connection.cc \
			proxy.cc \
			main.cc

firesql_CPPFLAGS = $(BOOST_CPPFLAGS)
firesql_LDFLAGS = -lpthread -lstdc++ -lboost_system -lboost_thread -lboost_program_options -lboost_regex
firesql_LDADD = $(BOOST_LIBS)

bin_PROGRAMS = firesql

CLEANFILES = *.o *.lo

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

