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

#ifndef FIRESQL_CONNECTION_H
#define FIRESQL_CONNECTION_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <string>
//#include <array>
//#include <vector>
#include <sstream>
//#include <iomanip>
//#include <algorithm>

//#include <array>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/bind.hpp>

class Connection : public boost::enable_shared_from_this<Connection>
{
public:
	explicit Connection(boost::asio::io_service& ios):
		server_socket_(ios),
		client_socket_(ios)
	{}

	boost::asio::ip::tcp::socket& GetServerSocket();
	boost::asio::ip::tcp::socket& GetClientSocket();

	void Start(const std::string& server_host, unsigned short server_port);
	void HandleServerConnect(const boost::system::error_code& error);
private:

	void HandleServerWrite(const boost::system::error_code& error);
	void HandleServerRead(const boost::system::error_code& error,const size_t& bytes);
	void HandleClientWrite(const boost::system::error_code& error);
	void HandleClientRead(const boost::system::error_code& error,const size_t& bytes);

	void Close();

	boost::asio::ip::tcp::socket server_socket_;
	boost::asio::ip::tcp::socket client_socket_;

      	enum { max_data_length = 8192 }; //8KB check mysql documentation
//      	unsigned char server_data_[max_data_length];
 //     	unsigned char client_data_[max_data_length];
	boost::array<unsigned char,max_data_length> server_data_;
	boost::array<unsigned char,max_data_length> client_data_;
      	boost::mutex mutex_;
};

#endif // FIRESQL_CONNECTION_H
