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

void Proxy::start() 
{
	start_time_ = boost::posix_time::microsec_clock::local_time();
	std::cout << "FireSql proxy start" <<std::endl;
}

void Proxy::stop()
{
	std::cout << "FireSql proxy stop" <<std::endl;
	end_time_ = boost::posix_time::microsec_clock::local_time();
	io_service_.stop();
}

void Proxy::statistics()
{
	MysqlDecoder *decoder = MysqlDecoder::getInstance();
	RuleManager *rules = RuleManager::getInstance();
	int t = 0;
	int32_t bytes_server = 0;
	int32_t bytes_client = 0;
	boost::posix_time::time_duration duration(end_time_ - start_time_);

	std::cout << "FireSql proxy statistics" <<std::endl;

	// A cool lambda function 
	std::for_each(connection_list_.begin(), 
		connection_list_.end(), [&](boost::shared_ptr<Connection>& it)
	{ 
		it->statistics();
		bytes_server += it->getTotalServerBytes();
		bytes_client += it->getTotalClientBytes();
	});

	std::cout << "Statistics" <<std::endl;
	std::cout << "\telapsed time:" << duration <<std::endl;	
	std::cout << "\tconnections:" << total_connections <<std::endl;
	std::cout << "\tserver bytes:" << bytes_server <<std::endl;
	std::cout << "\tclient bytes:" << bytes_client <<std::endl;
	std::cout << "\ttotal queries:" << decoder->getTotalDecodeQueries() <<std::endl;
	std::cout << "\ttotal bogus queries:" << decoder->getTotalBogusQueries() <<std::endl;
	std::cout << "\ttotal rules:" << rules->getTotalRules() << std::endl;
	std::cout << "\ttotal matching rules:" << rules->getTotalMatchingRules() << std::endl;
	return;
}

void Proxy::handleAccept(const boost::system::error_code& error)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        if (!error)
        {
        	session_->start(server_host_,server_port_);
		connection_list_.push_back(session_);
		total_connections++;
               	if(!run())
               	{
                	std::cerr << "Failure during call to accept." << std::endl;
               	}
	}else{
        	std::cerr << "Error: " << error.message() << std::endl;
        }
	return;
}

bool Proxy::run()
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        try
        {
        	session_ = ConnectionPtr(new Connection(io_service_));
               	acceptor_.async_accept(session_->getServerSocket(),
                	boost::bind(&Proxy::handleAccept,
                        	this,
                         	boost::asio::placeholders::error));

        }catch(std::exception& e){
               std::cerr << "acceptor exception: " << e.what() << std::endl;
               return false;
        }
	io_service_.run();
        return true;
}

