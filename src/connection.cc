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

boost::asio::ip::tcp::socket& Connection::GetServerSocket()
{
	return server_socket_;
}

boost::asio::ip::tcp::socket& Connection::GetClientSocket()
{
	return client_socket_;
}

void Connection::Start(const std::string& client_host, unsigned short client_port)
{
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<":"<< client_host <<":"<< client_port <<std::endl;
#endif
        client_socket_.async_connect(
        	boost::asio::ip::tcp::endpoint(
                	boost::asio::ip::address::from_string(client_host),
                   	client_port),
               	boost::bind(&Connection::HandleServerConnect,
                	shared_from_this(),
                    	boost::asio::placeholders::error));
	return;
}

void Connection::HandleServerConnect(const boost::system::error_code& error)
{
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        if (!error) {
        	server_socket_.async_read_some(
                	boost::asio::buffer(server_data_,max_data_length),
                 	boost::bind(&Connection::HandleServerRead,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));

            	client_socket_.async_read_some(
                	boost::asio::buffer(client_data_,max_data_length),
                 	boost::bind(&Connection::HandleClientRead,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));
        }else{
         	Close();
	}
	return;
}

void Connection::HandleClientWrite(const boost::system::error_code& error)
{
	if (!error)
        {
        	server_socket_.async_read_some(
                	boost::asio::buffer(server_data_,max_data_length),
                 	boost::bind(&Connection::HandleServerRead,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));
        
	}else{ 
        	Close();
	}
	return;
}


// TODO: Hooks for the server response, this function have the response of the server
void Connection::HandleClientRead(const boost::system::error_code& error,const size_t& bytes)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<":bytes:"<<bytes <<std::endl;
#endif
        if (!error)
        {
        	async_write(server_socket_,
                	boost::asio::buffer(client_data_,bytes),
                  	boost::bind(&Connection::HandleServerWrite,
                        	shared_from_this(),
                        	boost::asio::placeholders::error));
	}else{
		Close();
	}
	return;
}

void Connection::HandleServerWrite(const boost::system::error_code& error)
{
        if (!error)
        {
        	client_socket_.async_read_some(
                 	boost::asio::buffer(client_data_,max_data_length),
                 	boost::bind(&Connection::HandleClientRead,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));
	}else{
		Close();
	}
	return;
}

// TODO: hooks for the clients queryes
void Connection::HandleServerRead(const boost::system::error_code& error,const size_t& bytes)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<":bytes:"<<bytes <<std::endl;
#endif
	if (!error)
        {
        	async_write(client_socket_,
                	boost::asio::buffer(server_data_,bytes),
                	boost::bind(&Connection::HandleClientWrite,
                      		shared_from_this(),
                      		boost::asio::placeholders::error));
		// TODO:This should be on a specific class
		if(bytes >4) { // There is a mysql header
			int type_query = server_data_[4];
			int query_length = server_data_[5];
			if(type_query == 3 ) {
        			std::ostringstream os;
				for(int i = 5;i < bytes;++i) 
					os << server_data_[i];
		
				std::cout << "QUERY(" << os.str() << ")" <<std::endl;
			}
		}	
	}else{
		Close();
	}
	return;
}

void Connection::Close()
{
#ifdef DEBUG
	std::cout << __FUNCTION__ <<std::endl;
#endif
	boost::mutex::scoped_lock lock(mutex_);
        if (server_socket_.is_open())
        	server_socket_.close();
        if (client_socket_.is_open())
        	client_socket_.close();
	return;
}

