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

#ifndef FIRESQL_PROXY_H
#define FIRESQL_PROXY_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <cstddef>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "connection.h"
#include "mysql_decoder.h"
#include "rule_manager.h"
#include "action_print.h"
#include "action_drop.h"
#include "action_close.h"
#include "action_reject.h"

class Proxy
{
public:
	explicit Proxy(
        	const std::string& local_host, unsigned short local_port,
                const std::string& server_host, unsigned short server_port)
        	: 
           	localhost_address(boost::asio::ip::address_v4::from_string(local_host)),
           	acceptor_(io_service_,boost::asio::ip::tcp::endpoint(localhost_address,local_port)),
           	server_port_(server_port),
           	server_host_(server_host),
		total_connections(0)
	{
		return;
	}	
/*
        explicit Proxy(
                const std::string& local_host)
                : 
                localhost_address(boost::asio::ip::address_v4::from_string(local_host)),
                acceptor_(io_service_,boost::asio::ip::tcp::endpoint(localhost_address,3000)),
                server_port_(3306),
                server_host_("10.10.10.1"),
                total_connections(0)
        {
                return;
        }
*/
/*        Proxy()
                :
                localhost_address(boost::asio::ip::address_v4::from_string("127.0.0.1")),
                acceptor_(io_service_,boost::asio::ip::tcp::endpoint(localhost_address,3000)),
                server_port_(3306),
                server_host_("10.10.10.1"),
                total_connections(0)
        {
                return;
        }
*/
//	Proxy() {}

	void start();
	bool run();
	void statistics();
	void stop();
private:
	void handleAccept(const boost::system::error_code& error);

	boost::posix_time::ptime start_time_;
	boost::posix_time::ptime end_time_;
        boost::asio::io_service io_service_;
        boost::asio::ip::address_v4 localhost_address;
        boost::asio::ip::tcp::acceptor acceptor_;
        unsigned short server_port_;
        std::string server_host_;
	ConnectionPtr session_;
	int total_connections;
	std::vector<ConnectionPtr> connection_list_;
};

#endif // FIRESQL_PROXY_H

