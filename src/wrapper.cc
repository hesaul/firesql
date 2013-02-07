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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "action_manager.h"
#include "proxy.h"
#include <iostream>
#include <boost/python.hpp>

using namespace boost::python;

BOOST_PYTHON_MODULE(pyfiresql)
{
	using namespace std;

	// Wrapper for the singleton class ActionManager
        boost::python::class_<ActionManager>("ActionManager",no_init)
       		.def("getInstance",&ActionManager::getInstance,return_value_policy<reference_existing_object>()).staticmethod("getInstance") 
		.def("statistics",&ActionManager::statistics)
	;

	// for method overload
	void (RuleManager::*addRule1)(const std::string) = &RuleManager::addRule;

	// Wrapper
        boost::python::class_<RuleManager>("RuleManager",no_init)
       		.def("getInstance",&RuleManager::getInstance,return_value_policy<reference_existing_object>()).staticmethod("getInstance") 
		//.def("statistics",&RuleManager::statistics)
		.def("getTotalRules",&RuleManager::getTotalRules)
		.def("addRule",addRule1)
	;

	// TODO
	//        boost::python::class_<Proxy>("Proxy")
        //boost::python::class_<Proxy>("Proxy",init<const std::string&,unsigned short,const std::string&, unsigned short>())
		//.def("statistics",&RuleManager::statistics)
	//	.def("start",&Proxy::start)
	//;
}


