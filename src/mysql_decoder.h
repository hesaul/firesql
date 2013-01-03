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
#include "singleton.h"

template <class T> T*  Singleton<T>::instance_ = nullptr;
class MysqlDecoder: public Singleton<MysqlDecoder>
{
public:
	void decode(boost::asio::mutable_buffers_1 buffer);

	int32_t GetTotalDecodeQueries() { return total_decode_queries_;}
	int32_t GetTotalBogusQueries() { return total_bogus_queries_;}

	friend class Singleton<MysqlDecoder>;

private:
	int GetIntFromNetworkPacket(unsigned char *packet,int packet_len,int *offset); 
	int32_t total_decode_queries_;
	int32_t total_bogus_queries_;
};

#endif // FIRESQL_MYSQL_DECODER_H

