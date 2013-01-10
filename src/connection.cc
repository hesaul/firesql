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


void Connection::Statistics() 
{
	std::cout << "Connection:" << this <<" ip:" << GetClientIpAddress();
	std::cout << " user:" << GetDatabaseUser(); 
	std::cout << " server bytes:" << total_server_data_bytes_; 
	std::cout << " client bytes:" << total_client_data_bytes_ <<std::endl; 
}

boost::asio::ip::tcp::socket& Connection::GetServerSocket()
{
	return client_socket_;
}

boost::asio::ip::tcp::socket& Connection::GetClientSocket()
{
	return server_socket_;
}

void Connection::Start(const std::string& server_host, unsigned short server_port)
{
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<":"<< server_host <<":"<< server_port <<std::endl;
#endif
        server_socket_.async_connect(
        	boost::asio::ip::tcp::endpoint(
                	boost::asio::ip::address::from_string(server_host),
                   	server_port),
               	boost::bind(&Connection::HandleServerConnect,
                	shared_from_this(),
                    	boost::asio::placeholders::error));

	client_ip_ = boost::lexical_cast<std::string>(client_socket_.remote_endpoint());
	return;
}

void Connection::HandleServerConnect(const boost::system::error_code& error)
{
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        if (!error) {
        	client_socket_.async_read_some(
                	boost::asio::buffer(server_data_,max_data_length),
                 	boost::bind(&Connection::ReadFromClient,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));

            	server_socket_.async_read_some(
                	boost::asio::buffer(client_data_,max_data_length),
                 	boost::bind(&Connection::ReadFromServer,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));
        }else{
         	Close();
	}
	return;
}

void Connection::WriteToServer(const boost::system::error_code& error)
{
	if (!error)
        {
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        	client_socket_.async_read_some(
                	boost::asio::buffer(server_data_,max_data_length),
                 	boost::bind(&Connection::ReadFromClient,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));
        
	}else{ 
        	Close();
	}
	return;
}


// TODO: Hooks for the server response, this function have the response of the server
void Connection::ReadFromServer(const boost::system::error_code& error,const size_t& bytes)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<":bytes:"<<bytes <<std::endl;
#endif
        if (!error)
        {
		// the proxy writes on the client socket
		async_write(client_socket_,
			boost::asio::buffer(client_data_,bytes),
			boost::bind(&Connection::WriteToClient,
				shared_from_this(),
				boost::asio::placeholders::error));
		
		total_server_data_bytes_ += bytes;
	}else{
		Close();
	}
	return;
}


// The proxy writes the response on the client
void Connection::WriteToClient(const boost::system::error_code& error)
{
        if (!error)
        {
#ifdef DEBUG
	std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
        	server_socket_.async_read_some(
                 	boost::asio::buffer(client_data_,max_data_length),
                 	boost::bind(&Connection::ReadFromServer,
                      		shared_from_this(),
                      		boost::asio::placeholders::error,
                      		boost::asio::placeholders::bytes_transferred));
	}else{
		Close();
	}
	return;
}

// The proxy writes the response on the client but need to wait for new queries
void Connection::WriteToClientResponse(const boost::system::error_code& error)
{
        if (!error)
        {
#ifdef DEBUG
        	std::cout << __FILE__ << ":"<< __FUNCTION__ <<std::endl;
#endif
                client_socket_.async_read_some(
                       	boost::asio::buffer(server_data_,max_data_length),
                        boost::bind(&Connection::ReadFromClient,
                                shared_from_this(),
                                boost::asio::placeholders::error,
                                boost::asio::placeholders::bytes_transferred));
        }else{
                Close();
        }
        return;
}




// TODO: hooks for the clients queryes
void Connection::ReadFromClient(const boost::system::error_code& error,const size_t& bytes)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<":bytes:"<<bytes <<std::endl;
#endif
	if (!error)
        {
		MysqlDecoder *decoder = MysqlDecoder::GetInstance();
		int action = ACTION_CONTINUE;

		// Decode the server_data_ buffer write from the client
		// to verify it.
		decoder->Decode(*this,boost::asio::buffer(server_data_,bytes));
		if(decoder->IsQuery()) 
		{
			RuleManager *rulemng = RuleManager::GetInstance();
			bool result = false;
			
			rulemng->Evaluate(decoder->GetQuery(),&result);
			if(result) 
			{
				RulePtr rule = rulemng->GetCurrentRule();
				
				user_query_ = decoder->GetQuery();
				default_action_ = rule->GetDefaultAction();
				default_action_->PreAction(user_query_,&action);

				if(action == ACTION_CLOSE) 
				{
					Close();
				}else if(action == ACTION_REJECT) {
					int response_size = 0;

					decoder->Reject(*this,boost::asio::buffer(client_data_,bytes),&response_size);
		
					/* Write on the client_socket_ a mysql error packet */	
					async_write(client_socket_,
						boost::asio::buffer(client_data_,response_size),
						boost::bind(&Connection::WriteToClientResponse,
							shared_from_this(),
							boost::asio::placeholders::error));
				}
			}else{
				default_action_ = rulemng->GetDefaultAction();
			}
		}

		if(action == ACTION_CONTINUE) 
		{
			// write to the server
			async_write(server_socket_,
				boost::asio::buffer(server_data_,bytes),
				boost::bind(&Connection::WriteToServer,
					shared_from_this(),
					boost::asio::placeholders::error));
			
			total_client_data_bytes_ += bytes;
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
        if (client_socket_.is_open())
        	client_socket_.close();
        if (server_socket_.is_open())
        	server_socket_.close();
	return;
}

