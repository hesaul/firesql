/*
 * FireSql a detection and protection sql injection engine.
 *
 * Copyright (C) 2012  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2012
 *
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <csignal>
#include "action_close.h"
#include "proxy.h"
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

Proxy *proxy;

bool process_command_line(int argc, char **argv,
	std::string &local_address,
	unsigned short &local_port,
	std::string &remote_address,
	unsigned short &remote_port,
	std::string &regex_exp)
{
	namespace po = boost::program_options;

	po::options_description mandatory_ops("Mandatory arguments");
	mandatory_ops.add_options()
		("localip,l",   po::value<std::string>(&local_address)->required(),
			"set the local address of the proxy.")
		("localport,p",   po::value<unsigned short>(&local_port)->required(),
			"set the local port of the proxy.")
		("remoteip,r", po::value<std::string>(&remote_address)->required(), 
			"set the remote address of the database.")
		("remoteport,q", po::value<unsigned short>(&remote_port)->required(), 
			"set the remote port of the database.")
        	;

	po::options_description optional_ops("Optional arguments");
	optional_ops.add_options()
		("help",     	"show help")
		("version,v",   "show version string")
          	("regex,R", po::value<std::string>(&regex_exp), 
			"use a regex for the user queries(default action print).")
		;

	mandatory_ops.add(optional_ops);

	try
	{
		po::variables_map vm;
        	po::store(po::parse_command_line(argc, argv, mandatory_ops), vm);

        	if (vm.count("help"))
        	{
            		std::cout << "FireSql " VERSION << std::endl;
            		std::cout << mandatory_ops << std::endl;
            		return false;
        	}
        	if (vm.count("version"))
        	{
            		std::cout << "FireSql " VERSION << std::endl;
            		return false;
        	}


        	po::notify(vm);
    	}
	catch(boost::program_options::required_option& e)
    	{
            	std::cout << "FireSql " VERSION << std::endl;
        	std::cerr << "Error: " << e.what() << std::endl;
		std::cout << mandatory_ops << std::endl;
        	return false;
    	}
    	catch(...)
    	{	
            	std::cout << "FireSql " VERSION << std::endl;
        	std::cerr << "Unknown error!" << std::endl;
        	return false;
    	}


	return true;
}

void signalHandler( int signum )
{
	proxy->Stop();
	proxy->Statistics();
	MysqlDecoder::DestroyInstance();
	RuleManager::DestroyInstance();
	exit(signum);  
}

int main(int argc, char* argv[])
{
	std::string local_host;
	std::string remote_host;
	std::string regex_exp;
	unsigned short local_port;
	unsigned short remote_port;

	if(!process_command_line(argc,argv,local_host,local_port,remote_host,remote_port,regex_exp))
	{
		return 1;
	}

   	boost::asio::io_service ios;

    	signal(SIGINT, signalHandler);  

	if(regex_exp.size() >0)
	{
		ActionPtr action = ActionPtr(new ActionPrint());

		RuleManager::GetInstance()->AddRule(regex_exp,action);
	}
   	try
   	{
		proxy = new Proxy(ios,local_host,local_port,remote_host,remote_port);
		
		proxy->Start();
		proxy->Run();
		ios.run();
   	}
   	catch(std::exception& e)
   	{
      		std::cerr << "Error: " << e.what() << std::endl;
      		return 1;
   	}
	return 0;
}

