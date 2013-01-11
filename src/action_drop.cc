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

#include "action_drop.h"

void ActionDrop::PreAction(const std::string& query,int *code)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<":matchs("<< query << ")" <<std::endl;
#endif
	++matchs_;
	(*code) = ACTION_DROP;
}


void ActionDrop::PostAction(int *code)
{
#ifdef DEBUG
        std::cout << __FILE__ << ":"<< __FUNCTION__ <<":droping response" <<std::endl;
#endif
	(*code) = ACTION_DROP;
}

