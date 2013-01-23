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

#ifndef FIRESQL_RULE_MANAGER_H
#define FIRESQL_RULE_MANAGER_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <vector>
#include "rule.h"

template <class T>
class SingletonRuleManager
{
public:
        template <typename... Args>

        static T* GetInstance()
        {
                if(!ruleMngInstance_)
                {
                        ruleMngInstance_ = new T();
                }
                return ruleMngInstance_;
        }

        static void DestroyInstance()
        {
                delete ruleMngInstance_;
                ruleMngInstance_ = nullptr;
        }

private:
        static T* ruleMngInstance_;
};

template <class T> T*  SingletonRuleManager<T>::ruleMngInstance_ = nullptr;
class RuleManager: public SingletonRuleManager<RuleManager>
{
public:

	int32_t GetTotalRules() { return total_rules_;}
	int32_t GetTotalMatchingRules() { return total_matched_rules_;}

	void Evaluate(const std::string &query,bool *result); 

	void AddRule(const std::string expression, const ActionPtr action);
	void AddRule(const std::string expression);

	void Statistics();
	RulePtr GetCurrentRule() { return current_rule_;};
	ActionPtr GetDefaultAction(); 
	friend class SingletonRuleManager<RuleManager>;
private:
	void AddRule(const RulePtr rule);

	int32_t total_rules_;
	int32_t total_matched_rules_;
	std::vector<RulePtr> rules_;
	RulePtr current_rule_;
	ActionPtr default_action_;
};

#endif // FIRESQL_RULE_MANAGER_H

