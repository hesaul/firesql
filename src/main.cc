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
#include "action_manager.h"
#include "proxy.h"
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <fstream>

Proxy *proxy;
ActionManager *action_mng;

bool process_command_line(int argc, char **argv,
	std::string &local_address,
	unsigned short &local_port,
	std::string &remote_address,
	unsigned short &remote_port,
	std::string &regex_exp,
	std::string &regex_file,
	std::string &action_str)
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
          	("regexfile,F", po::value<std::string>(&regex_file), 
			"use a regex file for the user queries(default action print).")
          	("action,a", po::value<std::string>(&action_str), 
			"sets the action when matchs the regex (print,close,reject,drop).")
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
        	std::cerr << "Unsupported option." << std::endl;
		std::cout << mandatory_ops << std::endl;
        	return false;
    	}


	return true;
}

void signalHandler( int signum )
{
	proxy->stop();
	proxy->statistics();
	ActionManager::getInstance()->statistics();
	MysqlDecoder::destroyInstance();
	RuleManager::destroyInstance();
	ActionManager::destroyInstance();
	exit(signum);  
}

int main(int argc, char* argv[])
{
	std::string local_host;
	std::string remote_host;
	std::string regex_exp;
	std::string regex_file;
	std::string action_str;
	unsigned short local_port;
	unsigned short remote_port;
	ActionPtr action;

	if(!process_command_line(argc,argv,local_host,local_port,remote_host,remote_port,
		regex_exp,regex_file,action_str))
	{
		return 1;
	}

   	//boost::asio::io_service ios;

    	signal(SIGINT, signalHandler);  

	ActionManager::getInstance()->addAction("print",ActionPtr(new ActionPrint()));
	ActionManager::getInstance()->addAction("drop",ActionPtr(new ActionDrop()));
	ActionManager::getInstance()->addAction("close",ActionPtr(new ActionClose()));
	ActionManager::getInstance()->addAction("reject",ActionPtr(new ActionReject()));

	if(action_str.size() >0)
	{
		action = ActionManager::getInstance()->getAction(action_str);
		if(!action)
		{
			std::cout << "Unknown action "<< action_str << " using print as default action" <<std::endl;
			action = ActionManager::getInstance()->getAction("print");
		}
	}

	if(regex_exp.size() >0)
	{
		RuleManager::getInstance()->addRule(regex_exp,action);
	}

	if(regex_file.size() > 0) 
	{
		std::ifstream rfile(regex_file);
		
		if(rfile.is_open())
		{
			while(rfile.good())
			{
				getline(rfile,regex_exp);
				if(regex_exp.size() >0) 
				{
					RuleManager::getInstance()->addRule(regex_exp,action);
				}
			}
			rfile.close();
		}
	}

   	try
   	{
		proxy = new Proxy(local_host,local_port,remote_host,remote_port);
		//proxy = new Proxy(ios,local_host,local_port,remote_host,remote_port);
		
		proxy->start();
		proxy->run();
	//	ios.run();
   	}
   	catch(std::exception& e)
   	{
      		std::cerr << "Error: " << e.what() << std::endl;
      		return 1;
   	}
	return 0;
}

