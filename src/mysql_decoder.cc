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

#include <iostream>
#include <sstream>
#include "mysql_decoder.h"

int MysqlDecoder::GetIntFromNetworkPacket(unsigned char *packet,int packet_len,int *offset)
{
	int off = *offset;
	int ret = 0;
	unsigned char *bytestream = packet;

	if(off >= packet_len) 
		return 0;
	if(bytestream[off] <= 251) { 
		ret = bytestream[off];
		off += 1; // 
	}else if (bytestream[off] == 252) { // 2 bytes length 
		if(off+2 >= packet_len) 
			return 0;
		ret = (bytestream[off +1 ] << 0 ) | 
			( bytestream[off +2] <<8);
		off += 2;
	}else if (bytestream[off] == 253) { // 3 bytes length
		if(off+3 >= packet_len) 
			return 0;

		ret = (bytestream[off + 1] << 0) |
			(bytestream[off + 2] << 8) |
			(bytestream[off + 3] << 16);
		off += 3;
	}else if(bytestream[off] == 254) { // 8 bytes length
		if(off + 8 >= packet_len)
			return 0;
		ret = (bytestream[off + 5] << 0) |
			(bytestream[off + 6] << 8) |
			(bytestream[off + 7] << 16) |
			(bytestream[off + 8] << 24);
		ret <<= 32;

		ret |= (bytestream[off + 1] <<  0) | 
			(bytestream[off + 2] <<  8) |
			(bytestream[off + 3] << 16) |
			(bytestream[off + 4] << 24);
		off += 8;
	}else {
		ret = -1;
	}		

	off += 1;

	*offset = off;
	return ret;
}

void MysqlDecoder::Decode(Connection &conn,boost::asio::mutable_buffers_1 buffer) 
{
	std::size_t bytes = boost::asio::buffer_size(buffer);
	unsigned char* packet = boost::asio::buffer_cast<unsigned char*>(buffer);

	if(bytes < MYSQL_PACKET_HEADER_SIZE ) // At least 4 bytes of mysql header 
		return;

	int offset = 0;
	int mysql_packet_size = GetIntFromNetworkPacket(packet,bytes,&offset);
	offset = 3; 
	int packet_number = packet[offset];

	if(bytes < MYSQL_PACKET_HEADER_SIZE + mysql_packet_size)
		return;

	offset ++;
	int type_query = packet[offset];
	is_query_ = false;
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ << ":bytes:"<< bytes;
        std::cout << " mysqllen:"<< mysql_packet_size;
        std::cout << " querytype:"<< type_query;
        std::cout << " offset:"<< offset+1 << std::endl;
#endif

	// type_query == 5 is for authenticated, the username can be retrieve	
        if((type_query >=3 )&&(type_query <=4)) 
	{
               	std::ostringstream os;
		offset++;
                for(int i = offset;i < bytes;++i)
                      	os << packet[i];
		++total_decode_queries_;
		is_query_ = true;
		query_ = os.str();	
	}
	else if((type_query == 5)||(type_query == 133)) 
	{
		std::string user_ = GetUser(&packet[offset],mysql_packet_size);		
		conn.SetDatabaseUser(user_);
	}else{
		++total_bogus_queries_;
	}
	return;
}

// Type query equals 5 is for autenticate the user
// Login request 
//   Client Capabilities 2 bytes
//   Extended Client Capabilities 2 bytes
//   Max packet 4 bytes
//   Charset 1 byte
//   Username 30 bytes aprox 
//   Password hashed 
std::string MysqlDecoder::GetUser(unsigned char *buffer,int buffer_len)
{
	std::string user("none");
	unsigned char *pointer = buffer;

	if(buffer_len <= 30) 
		return user;	

	std::ostringstream os;

	pointer = &buffer[9];
	for (int i = 0; i < 30;++i) 
	{
		os << pointer[i];
	}

	return os.str();
}

void MysqlDecoder::Reject(Connection &conn,boost::asio::mutable_buffers_1 buffer,const std::string &query,int *bytes)
{
        unsigned char* packet = boost::asio::buffer_cast<unsigned char*>(buffer);
	int mysql_packet_len = 0;
	std::string message;
	std::ostringstream msg;

	msg << "Syntax error on:"<< query; 
	message = msg.str();

	mysql_packet_len = 8;
	memcpy(packet+ MYSQL_PACKET_HEADER_SIZE + 1,"\x76\x04\x23\x34\x32\x30\x30\x30",mysql_packet_len);

	memcpy(packet + MYSQL_PACKET_HEADER_SIZE + 1 + mysql_packet_len, message.c_str(),message.length());
	mysql_packet_len += message.length() + 1;

	// Copy the header
	memcpy(packet,"\x00\x00\x00\x01\xff",5);	
	memcpy(packet , &mysql_packet_len, 1);
	(*bytes) = mysql_packet_len + MYSQL_PACKET_HEADER_SIZE ;
}
