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

#ifndef FIRESQL_ACTION_MANAGER_H
#define FIRESQL_ACTION_MANAGER_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unordered_map>
#include "action.h"

template <class T>
class SingletonActionManager
{
public:
        template <typename... Args>

        static T* getInstance()
        {
                if(!actionManagerInstance_)
                {
                        actionManagerInstance_ = new T();
                }
                return actionManagerInstance_;
        }

        static void destroyInstance()
        {
                delete actionManagerInstance_;
                actionManagerInstance_ = nullptr;
        }

private:
        static T* actionManagerInstance_;
};

template <class T> T*  SingletonActionManager<T>::actionManagerInstance_ = nullptr;
class ActionManager: public SingletonActionManager<ActionManager>
{
public:
	void addAction(const std::string &name, ActionPtr action);

	void statistics();
	ActionPtr getAction(const std::string &name);
	
	friend class SingletonActionManager<ActionManager>;
private:
	std::unordered_map<std::string , ActionPtr> actions_;
};

#endif // FIRESQL_MYSQL_DECODER_H

