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

#ifndef FIRESQL_MYSQLDEFS_H
#define FIRESQL_MYSQLDEFS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

enum MYSQL_COMMANDS
{
  MC_SLEEP = 0,
  MC_QUIT = 1,
  MC_INIT_DB = 2,
  MC_QUERY = 3,
  MC_LIST = 4,
};


enum MYSQL_FIELDTYPE
{
  MFTYPE_DECIMAL = 0x00,
  MFTYPE_TINY = 0x01,
  MFTYPE_SHORT = 0x02,
  MFTYPE_LONG = 0x03,
  MFTYPE_FLOAT = 0x04,
  MFTYPE_DOUBLE = 0x05,
  MFTYPE_NULL = 0x06,
  MFTYPE_TIMESTAMP = 0x07,
  MFTYPE_LONGLONG = 0x08,
  MFTYPE_INT24 = 0x09,
  MFTYPE_DATE = 0x0a,
  MFTYPE_TIME = 0x0b,
  MFTYPE_DATETIME = 0x0c,
  MFTYPE_YEAR = 0x0d,
  MFTYPE_NEWDATE = 0x0e,
  MFTYPE_VARCHAR = 0x0f,
  MFTYPE_BIT = 0x10,
  MFTYPE_NEWDECIMAL = 0xf6,
  MFTYPE_ENUM = 0xf7,
  MFTYPE_SET = 0xf8,
  MFTYPE_TINY_BLOB = 0xf9,
  MFTYPE_MEDIUM_BLOB = 0xfa,
  MFTYPE_LONG_BLOB = 0xfb,
  MFTYPE_BLOB = 0xfc,
  MFTYPE_VAR_STRING = 0xfd,
  MFTYPE_STRING = 0xfe,
  MFTYPE_GEOMETRY = 0xff,
};

enum MYSQL_FIELDFLAG
{
  MFFLAG_NOT_NULL_FLAG = 0x0001,
  MFFLAG_PRI_KEY_FLAG = 0x0002,
  MFFLAG_UNIQUE_KEY_FLAG = 0x0004,
  MFFLAG_MULTIPLE_KEY_FLAG = 0x0008,
  MFFLAG_BLOB_FLAG = 0x0010,
  MFFLAG_UNSIGNED_FLAG = 0x0020,
  MFFLAG_ZEROFILL_FLAG = 0x0040,
  MFFLAG_BINARY_FLAG = 0x0080,
  MFFLAG_ENUM_FLAG = 0x0100,
  MFFLAG_AUTO_INCREMENT_FLAG = 0x0200,
  MFFLAG_TIMESTAMP_FLAG = 0x0400,
  MFFLAG_SET_FLAG = 0x0800,
};

#define MYSQL_PACKET_HEADER_SIZE 4
#define MYSQL_PROTOCOL_VERSION 0x0a
#define MYSQL_PACKET_SIZE (1024 * 1024 * 16)

#endif 

