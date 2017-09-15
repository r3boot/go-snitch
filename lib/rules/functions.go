package rules

import (
	"fmt"
)

func (rs Ruleset) String() string {
	response := fmt.Sprintf("== Ruleset:\n")
	for _, rule := range rs {
		response += rule.String()
	}
	return response
}

func (r RuleItem) String() string {
	response := fmt.Sprintf("== RuleItem:\n")
	response += fmt.Sprintf("Id: %d\n", r.Id)
	response += fmt.Sprintf("Cmd: %s\n", r.Cmd)
	response += fmt.Sprintf("Verdict: %d\n", r.Verdict)
	response += fmt.Sprintf("Dstip: %s\n", r.Dstip)
	response += fmt.Sprintf("Port: %s\n", r.Port)
	response += fmt.Sprintf("Proto: %d\n", r.Proto)
	response += fmt.Sprintf("User: %s\n", r.User)
	response += fmt.Sprintf("Timestamp: %v\n", r.Timestamp)
	response += fmt.Sprintf("Duration: %v\n", r.Duration)
	return response
}
