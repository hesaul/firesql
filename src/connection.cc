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


void Connection::statistics() 
{
	std::cout << "Connection:" << this <<" ip:" << getClientIpAddress();
	std::cout << " user:" << getDatabaseUser(); 
	std::cout << " server bytes:" << total_server_data_bytes_; 
	std::cout << " client bytes:" << total_client_data_bytes_ <<std::endl; 
}

boost::asio::ip::tcp::socket& Connection::getServerSocket()
{
	return client_socket_;
}

boost::asio::ip::tcp::socket& Connection::getClientSocket()
{
	return server_socket_;
}

void Connection::start(const std::string& server_host, unsigned short server_port)
{
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<":"<< server_host <<":"<< server_port <<std::endl;
#endif
        server_socket_.async_connect(
        	boost::asio::ip::tcp::endpoint(
                	boost::asio::ip::address::from_string(server_host),
                   	server_port),
               	boost::bind(&Connection::handleServerConnect,
                	shared_from_this(),
                    	boost::asio::placeholders::error));

	client_ip_ = boost::lexical_cast<std::string>(client_socket_.remote_endpoint());
	return;
}

void Connection::handleServerConnect(const boost::system::error_code& error)
{
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        if (!error) {
        	client_socket_.async_read_some(
                	boost::asio::buffer(server_data_,max_data_length),
                 	boost::bind(&Connection::readFromClient,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));

            	server_socket_.async_read_some(
                	boost::asio::buffer(client_data_,max_data_length),
                 	boost::bind(&Connection::readFromServer,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));
        }else{
         	close();
	}
	return;
}

void Connection::writeToServer(const boost::system::error_code& error)
{
	if (!error)
        {
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        	client_socket_.async_read_some(
                	boost::asio::buffer(server_data_,max_data_length),
                 	boost::bind(&Connection::readFromClient,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));
        
	}else{ 
        	close();
	}
	return;
}


// TODO: Hooks for the server response, this function have the response of the server
void Connection::readFromServer(const boost::system::error_code& error,const size_t& bytes)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<":bytes:"<<bytes <<std::endl;
#endif
        if (!error)
        {
		// the proxy writes on the client socket
		async_write(client_socket_,
			boost::asio::buffer(client_data_,bytes),
			boost::bind(&Connection::writeToClient,
				shared_from_this(),
				boost::asio::placeholders::error));
		
		total_server_data_bytes_ += bytes;
	}else{
		close();
	}
	return;
}


// The proxy writes the response on the client
void Connection::writeToClient(const boost::system::error_code& error)
{
        if (!error)
        {
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        	server_socket_.async_read_some(
                 	boost::asio::buffer(client_data_,max_data_length),
                 	boost::bind(&Connection::readFromServer,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));
	}else{
		close();
	}
	return;
}

// The proxy writes the response on the client but need to wait for new queries
void Connection::writeToClientResponse(const boost::system::error_code& error)
{
        if (!error)
        {
#ifdef DEBUG
        	std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
                client_socket_.async_read_some(
                       	boost::asio::buffer(server_data_,max_data_length),
                        boost::bind(&Connection::readFromClient,
                                shared_from_this(),
                                boost::asio::placeholders::error,
                                boost::asio::placeholders::bytes_transferred));
        }else{
                close();
        }
        return;
}




// TODO: hooks for the clients queryes
void Connection::readFromClient(const boost::system::error_code& error,const size_t& bytes)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<":bytes:"<<bytes <<std::endl;
#endif
	if (!error)
        {
		MysqlDecoder *decoder = MysqlDecoder::getInstance();
		ActionCodes action = ActionCodes::CONTINUE;

		// Decode the server_data_ buffer write from the client
		// to verify it.
		decoder->decode(*this,boost::asio::buffer(server_data_,bytes));
		if(decoder->isQuery()) 
		{
			RuleManager *rulemng = RuleManager::getInstance();
			bool result = false;
			
			rulemng->evaluate(decoder->getQuery(),&result);
			if(result) 
			{
				RulePtr rule = rulemng->getCurrentRule();
				
				user_query_ = decoder->getQuery();
				default_action_ = rule->getDefaultAction();
				default_action_->preAction(user_query_,&action);

				if(action == ActionCodes::CLOSE) 
				{
					close();
				}else if(action == ActionCodes::REJECT) {
					int response_size = 0;

					decoder->reject(*this,
						boost::asio::buffer(client_data_,bytes),
						user_query_,&response_size);
		
					/* Write on the client_socket_ a mysql error packet */	
					async_write(client_socket_,
						boost::asio::buffer(client_data_,response_size),
						boost::bind(&Connection::writeToClientResponse,
							shared_from_this(),
							boost::asio::placeholders::error));
				}
			}else{
				default_action_ = rulemng->getDefaultAction();
			}
		}

		if(action == ActionCodes::CONTINUE) 
		{
			// write to the server
			async_write(server_socket_,
				boost::asio::buffer(server_data_,bytes),
				boost::bind(&Connection::writeToServer,
					shared_from_this(),
					boost::asio::placeholders::error));
			
			total_client_data_bytes_ += bytes;
		}
	}else{
		close();
	}
	return;
}

void Connection::close()
{
#ifdef DEBUG
	std::cout << __FUNCTION__ <<std::endl;
#endif
	boost::mutex::scoped_lock lock(mutex_);
        if (client_socket_.is_open())
        	client_socket_.close();
        if (server_socket_.is_open())
        	server_socket_.close();
	return;
}

