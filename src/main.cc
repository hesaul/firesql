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

#include "proxy.h"
#include <boost/asio.hpp>

int main(int argc, char* argv[])
{
	if (argc != 5)
   	{
      		std::cerr << "usage:"<< argv[0] <<" <local ip> <local port> <server ip> <server port>" << std::endl;
      		return 1;
   	}

	const unsigned short local_port   = static_cast<unsigned short>(::atoi(argv[2]));
   	const unsigned short forward_port = static_cast<unsigned short>(::atoi(argv[4]));
   	const std::string local_host      = argv[1];
   	const std::string forward_host    = argv[3];

   	boost::asio::io_service ios;

/*
	boost::asio::signal_set signals(ios);
	signals.add(SIGINT);
  	signals.add(SIGTERM);
#if defined(SIGQUIT)
	signals.add(SIGQUIT);
#endif 
  	signals.async_wait(boost::bind(
      		&boost::asio::io_service::stop, &ios));
*/
   	try
   	{
		Proxy proxy(ios,local_host,local_port,forward_host,forward_port);

		proxy.Run();
		ios.run();
   	}
   	catch(std::exception& e)
   	{
      		std::cerr << "Error: " << e.what() << std::endl;
      		return 1;
   	}
	return 0;
}

