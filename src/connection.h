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
#include <sstream>
#include <boost/lexical_cast.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/bind.hpp>

#include "action.h"
#include "rule_manager.h"
#include "mysql_decoder.h"

class Connection : public boost::enable_shared_from_this<Connection>
{
public:
	explicit Connection(boost::asio::io_service& ios):
		server_socket_(ios),
		client_socket_(ios),
		total_server_data_bytes_(0),
		total_client_data_bytes_(0),
		database_user_("none")
	{
	}

	virtual ~Connection()=default;

	boost::asio::ip::tcp::socket& getServerSocket();
	boost::asio::ip::tcp::socket& getClientSocket();

	void start(const std::string& server_host, unsigned short server_port);
	void handleServerConnect(const boost::system::error_code& error);
	void statistics();
	
	int32_t getTotalServerBytes() { return total_server_data_bytes_; };
	int32_t getTotalClientBytes() { return total_client_data_bytes_; };
	const std::string &getClientIpAddress() { return client_ip_;};
	const std::string &getDatabaseUser() { return database_user_;};
	void setDatabaseUser(std::string user) { database_user_ = user; };

private:

	void writeToClient(const boost::system::error_code& error);
	void readFromClient(const boost::system::error_code& error,const size_t& bytes);
	void writeToServer(const boost::system::error_code& error);
	void readFromServer(const boost::system::error_code& error,const size_t& bytes);

	void writeToClientResponse(const boost::system::error_code& error);

	void close();

	boost::asio::ip::tcp::socket server_socket_;
	boost::asio::ip::tcp::socket client_socket_;

      	enum { max_data_length = 8192 }; //8KB check mysql documentation
	boost::array<unsigned char,max_data_length> server_data_;
	boost::array<unsigned char,max_data_length> client_data_;
      	boost::mutex mutex_;

	ActionPtr default_action_;

	std::string user_query_;
	std::string database_user_;
	std::string client_ip_;
	int32_t total_server_data_bytes_;
	int32_t total_client_data_bytes_;
};

typedef boost::shared_ptr<Connection> ConnectionPtr;

#endif // FIRESQL_CONNECTION_H
