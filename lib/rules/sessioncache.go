package rules

import (
	"fmt"
	"time"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/datastructures"
	"github.com/r3boot/go-snitch/lib/logger"
)

func NewSessionCache(l *logger.Logger) *SessionCache {
	log = l

	cache := &SessionCache{
		ruleset: datastructures.Ruleset{},
	}

	return cache
}

func (cache *SessionCache) GetVerdict(r datastructures.ConnRequest) (netfilter.Verdict, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	isAppRule := true
	foundRules := datastructures.Ruleset{}
	matchingRule := datastructures.RuleItem{}

	// Get all rules matching command
	for _, rule := range cache.ruleset {
		if rule.Command != r.Command {
			continue
		}

		if rule.Destination != "" {
			isAppRule = false
		}
		foundRules = append(foundRules, rule)
	}

	// Return if no rules found
	if len(foundRules) == 0 {
		return netfilter.NF_UNDEF, fmt.Errorf("SessionCache.GetVerdict: No rules defined")
	}

	// Check if we have a rule which matches on ip+port+proto
	if !isAppRule {
		for _, rule := range foundRules {
			if r.Destination == rule.Destination && r.Port == rule.Port && r.Proto == rule.Proto {
				matchingRule = rule
				break
			}
		}
		if matchingRule.Command == "" {
			return netfilter.NF_UNDEF, fmt.Errorf("SessionCache.GetVerdict: Command is empty")
		}
	} else {
		matchingRule = foundRules[0]
	}

	// Check if the rule is expired
	if matchingRule.Duration != 0 {
		if time.Since(matchingRule.Timestamp) > matchingRule.Duration {
			cache.DeleteRuleByRule(matchingRule)
			return netfilter.NF_UNDEF, fmt.Errorf("SessionCache.GetVerdict: Rule is expired")
		}
	}

	// Check if the rule matches the requested user
	if matchingRule.User == USER_ANY {
		return netfilter.NF_ACCEPT, nil
	} else if matchingRule.User == r.User {
		return netfilter.NF_ACCEPT, nil
	}

	return netfilter.NF_UNDEF, fmt.Errorf("SessionCache.GetVerdict: No matching rule found")
}

func (cache *SessionCache) DeleteConnRulesFor(cmd string) {
	ruleset := datastructures.Ruleset{}

	for _, rule := range cache.ruleset {
		if rule.Command != cmd {
			continue
		}
		if rule.Destination != "" {
			continue
		}

		ruleset = append(ruleset, rule)
	}

	cache.ruleset = ruleset
}

func (cache *SessionCache) DeleteRuleByRule(delRule datastructures.RuleItem) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	ruleset := datastructures.Ruleset{}

	for _, rule := range cache.ruleset {
		if rule == delRule {
			continue
		}
		ruleset = append(ruleset, rule)
	}

	cache.ruleset = ruleset
}

func (cache *SessionCache) DeleteRule(id int) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	ruleset := datastructures.Ruleset{}

	for _, rule := range cache.ruleset {
		if rule.Id == id {
			continue
		}
		ruleset = append(ruleset, rule)
	}

	cache.ruleset = ruleset
}

func (cache *SessionCache) DeleteAppUserRules(r datastructures.ConnRequest) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	ruleset := datastructures.Ruleset{}

	for _, rule := range cache.ruleset {
		if rule.Command != r.Command {
			continue
		}

		if rule.User == USER_ANY {
			continue
		}

		ruleset = append(ruleset, rule)
	}

	cache.ruleset = ruleset
}

func (cache *SessionCache) DeleteConnUserRules(r datastructures.ConnRequest) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	ruleset := datastructures.Ruleset{}

	for _, rule := range cache.ruleset {
		if rule.Command == r.Command && rule.Destination == r.Destination && rule.Port == r.Port && rule.Proto == r.Proto {
			continue
		}
		ruleset = append(ruleset, rule)
	}

	cache.ruleset = ruleset
}

func (cache *SessionCache) NextFreeId() int {
	if len(cache.ruleset) == 0 {
		return 0
	}

	lastId := 0
	for _, rule := range cache.ruleset {
		if rule.Id > lastId {
			lastId = rule.Id
		}
	}

	return lastId + 1
}

func (cache *SessionCache) AddRule(r datastructures.ConnRequest, response datastructures.Response) error {
	user := r.User

	// Delete existing rules if rule is built as a system-wide rule
	if response.User == datastructures.USER_SYSTEM {
		switch response.Action {
		case datastructures.ACTION_WHITELIST, datastructures.ACTION_BLOCK:
			cache.DeleteAppUserRules(r)
		case datastructures.ACTION_ALLOW, datastructures.ACTION_DENY:
			cache.DeleteConnUserRules(r)
		}
		user = datastructures.SYSTEM_USER
	}

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Add new rule
	switch response.Action {
	case datastructures.ACTION_WHITELIST, datastructures.ACTION_BLOCK:
		{
			cache.DeleteConnRulesFor(r.Command)
			cache.ruleset = append(cache.ruleset, datastructures.RuleItem{
				Id:        cache.NextFreeId(),
				Command:   r.Command,
				Verdict:   response.Verdict,
				User:      user,
				Timestamp: time.Now(),
				Duration:  response.Duration,
			})
		}
	case datastructures.ACTION_ALLOW, datastructures.ACTION_DENY:
		{
			cache.ruleset = append(cache.ruleset, datastructures.RuleItem{
				Id:          cache.NextFreeId(),
				Command:     r.Command,
				Verdict:     response.Verdict,
				Destination: r.Destination,
				Port:        r.Port,
				Proto:       r.Proto,
				User:        user,
				Timestamp:   time.Now(),
				Duration:    response.Duration,
			})
		}
	}

	return nil
}

func (cache *SessionCache) GetAllRules() (datastructures.Ruleset, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	return cache.ruleset, nil
}

func (cache *SessionCache) UpdateRule(newRule datastructures.RuleDetail) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	newRuleset := datastructures.Ruleset{}

	for _, rule := range cache.ruleset {
		if rule.Id == newRule.Id {
			newRuleset = append(newRuleset, datastructures.RuleItem{
				Id:          newRule.Id,
				Command:     newRule.Command,
				Destination: newRule.Destination,
				Port:        newRule.Port,
				Proto:       newRule.Proto,
				User:        newRule.User,
				Verdict:     newRule.Verdict,
				Duration:    newRule.Duration,
			})
		} else {
			newRuleset = append(newRuleset, rule)
		}
	}

	cache.ruleset = newRuleset
}
