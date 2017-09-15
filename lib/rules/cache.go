package rules

import (
	"time"

	"fmt"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/common"
	"github.com/r3boot/go-snitch/lib/logger"
)

func NewRuleCache(l *logger.Logger, dbpath string) (*RuleCache, error) {
	log = l

	db, err := NewRuleDB(nil, dbpath)
	if err != nil {
		return nil, fmt.Errorf("NewRuleCache: %v", err)
	}

	cache := &RuleCache{
		backend: db,
		ruleset: make(Ruleset, MAX_CACHE_SIZE),
	}

	return cache, nil
}

func (cache *RuleCache) GetVerdict(r common.ConnRequest) (netfilter.Verdict, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	isAppRule := true
	foundRules := Ruleset{}
	matchingRule := RuleItem{}

	// Get all rules matching command
	for _, rule := range cache.ruleset {
		if rule.Cmd != r.Command {
			continue
		}

		if rule.Dstip != "" {
			isAppRule = false
		}
		foundRules = append(foundRules, rule)
	}

	// Return if no rules are found
	if len(foundRules) == 0 {
		return netfilter.NF_UNDEF, nil
	}

	// Check if we have a rule which matches on ip+port+proto
	if !isAppRule {
		for _, rule := range foundRules {
			if r.Destination == rule.Dstip && r.Port == rule.Port && r.Proto == rule.Proto {
				matchingRule = rule
				break
			}
		}
		if matchingRule.Cmd == "" {
			return netfilter.NF_UNDEF, nil
		}
	} else {
		matchingRule = foundRules[0]
	}

	// Check if the rule is expired
	if matchingRule.Duration != 0 {
		if time.Since(matchingRule.Timestamp) > matchingRule.Duration {
			cache.DeleteRule(matchingRule.Id)
			return netfilter.NF_UNDEF, nil
		}
	}

	// Check if the rule matches the requested user
	if matchingRule.User == USER_ANY || matchingRule.User == r.User {
		return netfilter.Verdict(matchingRule.Verdict), nil
	}

	return netfilter.NF_UNDEF, nil
}

func (cache *RuleCache) AddRule(r common.ConnRequest, action int) error {
	err := cache.backend.AddRule(r, action)
	if err != nil {
		return err
	}

	cache.Prime()

	return nil
}

func (cache *RuleCache) DeleteRule(id int) error {
	err := cache.backend.DeleteRule(id)
	if err != nil {
		return err
	}

	cache.Prime()

	return nil
}

func (cache *RuleCache) UpdateRule(newRule RuleDetail) error {
	err := cache.backend.UpdateRule(newRule)
	if err != nil {
		return err
	}

	cache.Prime()

	return nil
}

func (cache *RuleCache) Prime() error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	ruleset, err := cache.backend.GetAllRules()
	if err != nil {
		return err
	}

	cache.ruleset = ruleset

	return nil
}

func (cache *RuleCache) GetRules() []RuleItem {
	return cache.ruleset
}
