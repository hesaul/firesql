AUTOMAKE_OPTIONS = gnu

EXTRA_DIST = wrapper.cc setup.py

noinst_HEADERS =	connection.h \
			proxy.h \
			mysql_decoder.h \
			rule.h \
			rule_manager.h \
			action_manager.h \
			action_close.h \
			action_drop.h \
			action_print.h \
			action_reject.h \
			action_modify_limit.h \
			action.h \
			mysqldefs.h 

firesql_SOURCES = 	action_drop.cc \
			action_close.cc \
			action_print.cc \
			action_reject.cc \
			action_modify_limit.cc \
			action_manager.cc \
			rule.cc \
			mysql_decoder.cc \
			rule_manager.cc \
			connection.cc \
			proxy.cc \
			main.cc

firesql_CPPFLAGS = $(BOOST_CPPFLAGS)
firesql_LDFLAGS = -lpthread -lstdc++ -lboost_system -lboost_thread -lboost_program_options -lboost_regex
firesql_LDADD = $(BOOST_LIBS)

bin_PROGRAMS = firesql

BUILT_SOURCES = $(srcdir)/pyfiresql.so

$(srcdir)/pyfiresql.so: wrapper.cc
	g++ -fPIC rule.cc rule_manager.cc action_print.cc action_manager.cc wrapper.cc `pkg-config --cflags python-2.7` \
		-I/usr/include/boost/python -std=c++11 -lpthread -lstdc++ -lboost_system \
		-lboost_thread -lboost_regex -lboost_python -lpython2.7 -o pyfiresql.so -shared 

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

