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

#ifndef FIRESQL_SINGLETON_H
#define FIRESQL_SINGLETON_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>

template <class T>
class Singleton
{
public:
	template <typename... Args>
  	
	static T* GetInstance() 
	{
		if(!instance_)
		{
			instance_ = new T();
		}
		return instance_;
	}

	static void DestroyInstance() 
	{
		delete instance_;
		instance_ = nullptr;
	}

private:
	static T* instance_;
};

#endif // FIRESQL_SINGLETON_H
