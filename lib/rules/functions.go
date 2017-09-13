package rules

import (
	"fmt"
)

func (r RuleItem) Dump() {
	fmt.Printf("== RuleItem:\n")
	fmt.Printf("Id: %d\n", r.Id)
	fmt.Printf("Cmd: %s\n", r.Cmd)
	fmt.Printf("Verdict: %d\n", r.Verdict)
	fmt.Printf("Dstip: %s\n", r.Dstip)
	fmt.Printf("Port: %s\n", r.Port)
	fmt.Printf("Proto: %d\n", r.Proto)
	fmt.Printf("User: %s\n", r.User)
	fmt.Printf("Timestamp: %v\n", r.Timestamp)
	fmt.Printf("Duration: %v\n", r.Duration)
}

func (r RuleItem) Dump() {
	fmt.Printf("== RuleItem:\n")
	fmt.Printf("Id: %d\n", r.Id)
	fmt.Printf("Cmd: %s\n", r.Cmd)
	fmt.Printf("Verdict: %d\n", r.Verdict)
	fmt.Printf("Dstip: %s\n", r.Dstip)
	fmt.Printf("Port: %s\n", r.Port)
	fmt.Printf("Proto: %d\n", r.Proto)
	fmt.Printf("User: %s\n", r.User)
	fmt.Printf("Timestamp: %v\n", r.Timestamp)
	fmt.Printf("Duration: %v\n", r.Duration)
}
