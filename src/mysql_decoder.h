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

#ifndef FIRESQL_MYSQL_DECODER_H
#define FIRESQL_MYSQL_DECODER_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/asio/buffer.hpp>
#include "connection.h"
#include "mysqldefs.h"

class Connection;

template <class T>
class SingletonDecoder
{
public:
        template <typename... Args>

        static T* GetInstance()
        {
                if(!decoderInstance_)
                {
                        decoderInstance_ = new T();
                }
                return decoderInstance_;
        }

        static void DestroyInstance()
        {
                delete decoderInstance_;
                decoderInstance_ = nullptr;
        }

private:
        static T* decoderInstance_;
};

template <class T> T*  SingletonDecoder<T>::decoderInstance_ = nullptr;
class MysqlDecoder: public SingletonDecoder<MysqlDecoder>
{
public:
	void Decode(Connection &conn,boost::asio::mutable_buffers_1 buffer);
	void Reject(Connection &conn,boost::asio::mutable_buffers_1 buffer,const std::string &query,int *bytes);

	int32_t GetTotalDecodeQueries() { return total_decode_queries_;}
	int32_t GetTotalBogusQueries() { return total_bogus_queries_;}

	const std::string &GetQuery() { return query_;}
	friend class SingletonDecoder<MysqlDecoder>;
	bool IsQuery() { return is_query_;}
private:
	int GetIntFromNetworkPacket(unsigned char *packet,int packet_len,int *offset); 
	std::string GetUser(unsigned char *buffer,int buffer_len);
	int32_t total_decode_queries_;
	int32_t total_bogus_queries_;
	std::string query_;
	bool is_query_;
};

#endif // FIRESQL_MYSQL_DECODER_H

