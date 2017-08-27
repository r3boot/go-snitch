package rules

import (
	"time"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/snitch"
)

func NewRuleCache(dbpath string) *RuleCache {
	db := NewRuleDB(dbpath)

	cache := &RuleCache{
		backend: db,
		ruleset: make([]RuleItem, MAX_CACHE_SIZE),
	}

	return cache
}

func (cache *RuleCache) GetVerdict(r snitch.ConnRequest) (netfilter.Verdict, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	isAppRule := true
	foundRules := []RuleItem{}
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
			if r.Dstip == rule.Dstip && r.Port == rule.Port && r.Proto == rule.Proto {
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
		return matchingRule.Verdict, nil
	}

	return netfilter.NF_UNDEF, nil
}

func (cache *RuleCache) AddRule(r snitch.ConnRequest, action int) error {
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
