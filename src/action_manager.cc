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
#include "action_manager.h"

void ActionManager::addAction(const std::string &name, ActionPtr action)
{
	actions_.insert(make_pair(name,action));
}

ActionPtr ActionManager::getAction(const std::string &name)
{
	return actions_[name];
}

void ActionManager::statistics()
{
	std::cout << "acllme" <<std::endl;
        std::for_each(actions_.begin(),actions_.end(),
                [](std::pair<std::string,ActionPtr> const &p)
        {
                std::cout << "\taction " << p.first <<" matchs:" << p.second->getMatches()<< std::endl;
        });
	return;
}
