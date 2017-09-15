package rules

import (
	"fmt"
	"time"

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

func (cache *SessionCache) GetVerdict(r datastructures.ConnRequest) (datastructures.ResponseType, error) {
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
		return datastructures.RESPONSE_UNKNOWN, fmt.Errorf("SessionCache.GetVerdict: No rules defined")
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
			return datastructures.RESPONSE_UNKNOWN, fmt.Errorf("SessionCache.GetVerdict: Command is empty")
		}
	} else {
		matchingRule = foundRules[0]
	}

	// Check if the rule is expired
	if matchingRule.Duration != 0 {
		if time.Since(matchingRule.Timestamp) > matchingRule.Duration {
			cache.DeleteRuleByRule(matchingRule)
			return datastructures.RESPONSE_UNKNOWN, fmt.Errorf("SessionCache.GetVerdict: Rule is expired")
		}
	}

	// Check if the rule matches the requested user
	if matchingRule.User == USER_ANY {
		switch matchingRule.Verdict {
		case datastructures.VERDICT_ACCEPT:
			return datastructures.ACCEPT_APP_ONCE_SYSTEM, nil
		case datastructures.VERDICT_REJECT:
			return datastructures.DROP_APP_ONCE_SYSTEM, nil
		}
	} else if matchingRule.User == r.User {
		switch matchingRule.Verdict {
		case datastructures.VERDICT_ACCEPT:
			return datastructures.ACCEPT_APP_ONCE_USER, nil
		case datastructures.VERDICT_REJECT:
			return datastructures.DROP_APP_ONCE_USER, nil
		}
	}

	return datastructures.RESPONSE_UNKNOWN, fmt.Errorf("SessionCache.GetVerdict: No matching rule found")
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

func (cache *SessionCache) AddRule(r datastructures.ConnRequest, response datastructures.ResponseType) error {
	user := r.User

	// Delete existing rules if rule is built as a system-wide rule
	switch response {
	case datastructures.DROP_APP_ONCE_SYSTEM, datastructures.ACCEPT_APP_ONCE_SYSTEM:
		{
			cache.DeleteAppUserRules(r)
			user = USER_ANY
		}
	case datastructures.DROP_CONN_ONCE_SYSTEM, datastructures.ACCEPT_CONN_ONCE_SYSTEM:
		{
			cache.DeleteConnUserRules(r)
			user = USER_ANY
		}
	}

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Add new rule
	verdict := datastructures.VERDICT_UNKNOWN
	switch response {
	case datastructures.ACCEPT_APP_ONCE_SYSTEM,
		datastructures.ACCEPT_APP_ONCE_USER,
		datastructures.DROP_APP_ONCE_SYSTEM,
		datastructures.DROP_APP_ONCE_USER:
		{
			if response == datastructures.ACCEPT_APP_ONCE_SYSTEM || response == datastructures.ACCEPT_APP_ONCE_USER {
				verdict = datastructures.VERDICT_ACCEPT
			} else {
				verdict = datastructures.VERDICT_REJECT
			}
			cache.DeleteConnRulesFor(r.Command)
			cache.ruleset = append(cache.ruleset, datastructures.RuleItem{
				Id:        cache.NextFreeId(),
				Command:   r.Command,
				Cmdline:   r.Cmdline,
				Verdict:   verdict,
				User:      user,
				Timestamp: time.Now(),
				Duration:  r.Duration,
			})
		}
	case datastructures.ACCEPT_CONN_ONCE_SYSTEM,
		datastructures.ACCEPT_CONN_ONCE_USER,
		datastructures.DROP_CONN_ONCE_SYSTEM,
		datastructures.DROP_CONN_ONCE_USER:
		{
			if response == datastructures.ACCEPT_CONN_ONCE_SYSTEM || response == datastructures.ACCEPT_CONN_ONCE_USER {
				verdict = datastructures.VERDICT_ACCEPT
			} else {
				verdict = datastructures.VERDICT_REJECT
			}
			cache.ruleset = append(cache.ruleset, datastructures.RuleItem{
				Id:          cache.NextFreeId(),
				Command:     r.Command,
				Cmdline:     r.Cmdline,
				Verdict:     verdict,
				Destination: r.Destination,
				Port:        r.Port,
				Proto:       r.Proto,
				User:        user,
				Timestamp:   time.Now(),
				Duration:    r.Duration,
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
				Cmdline:     newRule.Cmdline,
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
