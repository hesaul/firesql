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

#include "connection.h"
#include "proxy.h"

void Proxy::Stop()
{
	io_service_.stop();
}

void Proxy::Statistics()
{
	std::cout << "Statistics" <<std::endl;
	std::cout << "\tconnections:" << total_connections <<std::endl;
	return;
}

void Proxy::HandleAccept(const boost::system::error_code& error)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        if (!error)
        {
        	session_->Start(server_host_,server_port_);
               	if(!Run())
               	{
                	std::cerr << "Failure during call to accept." << std::endl;
               	}

	}else{
        	std::cerr << "Error: " << error.message() << std::endl;
        }
	return;
}

bool Proxy::Run()
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        try
        {
        	session_ = boost::shared_ptr<Connection>(new Connection(io_service_));
		total_connections++;
               	acceptor_.async_accept(session_->GetServerSocket(),
                	boost::bind(&Proxy::HandleAccept,
                        	this,
                         	boost::asio::placeholders::error));

        }catch(std::exception& e){
               std::cerr << "acceptor exception: " << e.what() << std::endl;
               return false;
        }
        return true;
}

