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

void MysqlDecoder::decode(VisitorDecoder &v,boost::asio::mutable_buffers_1 buffer) {
	std::size_t bytes = boost::asio::buffer_size(buffer);
	unsigned char* ptr = boost::asio::buffer_cast<unsigned char*>(buffer);

#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ << ":bytes:"<< bytes <<std::endl;
#endif
	if(bytes >4) { // There is a mysql header
        	int type_query = ptr[4];
                int query_length = ptr[5];
                if(type_query == 3 ) {
                	std::ostringstream os;
                        for(int i = 5;i < bytes;++i)
                        	os << ptr[i];

                        std::cout << "QUERY(" << os.str() << ")" <<std::endl;
                }
	}

        v.decode(*this,buffer);
}

