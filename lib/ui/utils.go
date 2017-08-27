package ui

import (
	"fmt"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/snitch"
)

func VerdictToAction(verdict netfilter.Verdict) string {
	switch verdict {
	case netfilter.NF_ACCEPT:
		{
			return "accept"
		}
	case netfilter.NF_DROP:
		{
			return "reject"
		}
	default:
		{
			return "UNKNOWN"
		}
	}
}

func ActionToAction(action int) string {
	switch action {
	case snitch.DROP_CONN_ONCE_USER,
		snitch.DROP_CONN_ONCE_SYSTEM,
		snitch.DROP_APP_ONCE_USER,
		snitch.DROP_APP_ONCE_SYSTEM:
		{
			return "reject"
		}
	case snitch.ACCEPT_CONN_ONCE_USER,
		snitch.ACCEPT_CONN_ONCE_SYSTEM,
		snitch.ACCEPT_APP_ONCE_USER,
		snitch.ACCEPT_APP_ONCE_SYSTEM:
		{
			return "accept"
		}
	default:
		return "UNKNOWN"
	}
}

func getRuleId(cmd string, rules map[int]*Rule) int {
	for key, value := range rules {
		if value.Command == cmd {
			return key
		}
	}

	return -1
}

func protoToString(proto int) string {
	switch proto {
	case snitch.PROTO_TCP:
		{
			return "tcp"
		}
	case snitch.PROTO_UDP:
		{
			return "udp"
		}
	}

	return "UNKNOWN"
}

func dumpRuleset(ruleset map[int]*Rule) {
	for id, rule := range ruleset {
		fmt.Printf("Id: %d\n", id)
		fmt.Printf("Command: %s\n", rule.Command)
		if len(rule.ConnRules) > 0 {
			for connId, connRule := range ruleset[id].ConnRules {
				fmt.Printf("\tconnId: %d\n", connId)
				fmt.Printf("\tDstip: %s\n", connRule.Dstip)
			}
		}
	}
}
