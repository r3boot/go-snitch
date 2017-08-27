package rules

import (
	"fmt"
	"time"

	"github.com/r3boot/go-snitch/lib/snitch"
)

func NewSessionCache() *SessionCache {

	cache := &SessionCache{
		ruleset: []SessionRuleItem{},
	}

	return cache
}

func (cache *SessionCache) GetVerdict(r snitch.ConnRequest) (int, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	isAppRule := true
	foundRules := []SessionRuleItem{}
	matchingRule := SessionRuleItem{}

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

	// Return if no rules found
	if len(foundRules) == 0 {
		return snitch.UNKNOWN, nil
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
			return snitch.UNKNOWN, nil
		}
	} else {
		matchingRule = foundRules[0]
	}

	// Check if the rule is expired
	if matchingRule.Duration != 0 {
		if time.Since(matchingRule.Timestamp) > matchingRule.Duration {
			cache.DeleteRuleByRule(matchingRule)
			return snitch.UNKNOWN, nil
		}
	}

	// Check if the rule matches the requested user
	if matchingRule.User == USER_ANY || matchingRule.User == r.User {
		return matchingRule.Verdict, nil
	}

	return snitch.UNKNOWN, nil
}

func (cache *SessionCache) DeleteConnRulesFor(cmd string) {
	ruleset := []SessionRuleItem{}

	for _, rule := range cache.ruleset {
		if rule.Cmd != cmd {
			continue
		}
		if rule.Dstip != "" {
			continue
		}

		ruleset = append(ruleset, rule)
	}

	cache.ruleset = ruleset
}

func (cache *SessionCache) DeleteRuleByRule(delRule SessionRuleItem) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	ruleset := []SessionRuleItem{}

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

	ruleset := []SessionRuleItem{}

	for _, rule := range cache.ruleset {
		if rule.Id == id {
			continue
		}
		ruleset = append(ruleset, rule)
	}

	cache.ruleset = ruleset
}

func (cache *SessionCache) DeleteAppUserRules(r snitch.ConnRequest) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	ruleset := []SessionRuleItem{}

	for _, rule := range cache.ruleset {
		if rule.Cmd != r.Command {
			continue
		}

		if rule.User == USER_ANY {
			continue
		}

		ruleset = append(ruleset, rule)
	}

	cache.ruleset = ruleset
}

func (cache *SessionCache) DeleteConnUserRules(r snitch.ConnRequest) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	ruleset := []SessionRuleItem{}

	for _, rule := range cache.ruleset {
		if rule.Cmd == r.Command && rule.Dstip == r.Dstip && rule.Port == r.Port && rule.Proto == r.Proto {
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

func (cache *SessionCache) AddRule(r snitch.ConnRequest, verdict int) error {
	user := r.User

	// Delete existing rules if rule is built as a system-wide rule
	switch verdict {
	case snitch.DROP_APP_ONCE_SYSTEM, snitch.ACCEPT_APP_ONCE_SYSTEM:
		{
			cache.DeleteAppUserRules(r)
			user = USER_ANY
		}
	case snitch.DROP_CONN_ONCE_SYSTEM, snitch.ACCEPT_CONN_ONCE_SYSTEM:
		{
			cache.DeleteConnUserRules(r)
			user = USER_ANY
		}
	}

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Add new rule
	switch verdict {
	case snitch.ACCEPT_APP_ONCE_SYSTEM,
		snitch.ACCEPT_APP_ONCE_USER,
		snitch.DROP_APP_ONCE_SYSTEM,
		snitch.DROP_APP_ONCE_USER:
		{
			cache.DeleteConnRulesFor(r.Command)
			cache.ruleset = append(cache.ruleset, SessionRuleItem{
				Id:        cache.NextFreeId(),
				Cmd:       r.Command,
				Verdict:   verdict,
				User:      user,
				Timestamp: time.Now(),
				Duration:  r.Duration,
			})
		}
	case snitch.ACCEPT_CONN_ONCE_SYSTEM,
		snitch.ACCEPT_CONN_ONCE_USER,
		snitch.DROP_CONN_ONCE_SYSTEM,
		snitch.DROP_CONN_ONCE_USER:
		{
			cache.ruleset = append(cache.ruleset, SessionRuleItem{
				Id:        cache.NextFreeId(),
				Cmd:       r.Command,
				Verdict:   verdict,
				Dstip:     r.Dstip,
				Port:      r.Port,
				Proto:     r.Proto,
				User:      user,
				Timestamp: time.Now(),
				Duration:  r.Duration,
			})
		}
	}

	fmt.Printf("cache: %v\n", cache.ruleset)

	return nil
}

func (cache *SessionCache) GetAllRules() ([]SessionRuleItem, error) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()

	fmt.Printf("cache: %v\n", cache.ruleset)

	return cache.ruleset, nil
}

func (cache *SessionCache) UpdateRule(newRule RuleDetail) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	newRuleset := []SessionRuleItem{}

	fmt.Printf("newRule: %v\n", newRule)

	for _, rule := range cache.ruleset {
		if rule.Id == newRule.Id {
			newRuleset = append(newRuleset, SessionRuleItem{
				Id:       newRule.Id,
				Cmd:      newRule.Command,
				Dstip:    newRule.Dstip,
				Port:     newRule.Port,
				Proto:    newRule.Proto,
				User:     newRule.User,
				Verdict:  newRule.Verdict,
				Duration: newRule.Duration,
			})
		} else {
			newRuleset = append(newRuleset, rule)
		}
	}

	cache.ruleset = newRuleset
	fmt.Printf("cache: %v\n", cache.ruleset)
}
