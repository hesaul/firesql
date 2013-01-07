FireSql a mysql firewall 
=========

The main goal of FireSql is to provide firewall services for
mysql databases by using regular expressions and other rules.

FireSql system is based on c++11 and boost just for fun. 

Using FireSql 
---------------

To use FireSql just execute the binary firesql:


	luis@max-xps:~/c/firesql/src$ ./firesql 
	Error: missing required option localip
	FireSql 0.0.1 usage:
  		--help                  show help
  		-l [ --localip ] arg    set the local address of the proxy.
  		-p [ --localport ] arg  set the local port of the proxy.
  		-r [ --remoteip ] arg   set the remote address of the database.
  		-q [ --remoteport ] arg set the remote port of the database.
  		-R [ --regex ] arg      user a regex for the user queries.

Contributing to FireSql 
-------------------------

FireSql is under the terms of GPLv2 and is under develop.

Check out the FireSql source with 

    $ git clone git://github.com/camp0/firesql
