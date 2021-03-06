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
#include "rule_manager.h"
#include "action_print.h"

void RuleManager::addRule(RulePtr rule)
{
	rules_.push_back(rule);
	total_rules_ += 1;
}


void RuleManager::addRule(const std::string expression,ActionPtr action)
{
        RulePtr rule = RulePtr(new Rule(expression));

        rule->setDefaultAction(action);
        addRule(rule);
}


void RuleManager::addRule(const std::string expression)
{
	ActionPtr action = ActionPtr(new ActionPrint()); // the default action

	addRule(expression,action);
}


void RuleManager::evaluate(const std::string &query, bool *result)
{
        std::for_each(rules_.begin(),
                rules_.end(),  [&](boost::shared_ptr<Rule>& r)
        {
		current_rule_ = r;
		if(r->evaluate(query.c_str()))
		{
			++total_matched_rules_;
			(*result) = true;
			return;	
		}
        });

	return;
}

ActionPtr RuleManager::getDefaultAction() 
{ 
	if(!default_action_)
	{
		default_action_ = ActionPtr(new ActionPrint());
	}
	return default_action_;
}
