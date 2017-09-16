package datastructures

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func init() {
	DurationToValueMap[DURATION_5M], _ = time.ParseDuration("5m")
	DurationToValueMap[DURATION_1H], _ = time.ParseDuration("1h")
	DurationToValueMap[DURATION_8H], _ = time.ParseDuration("8h")
	DurationToValueMap[DURATION_1D], _ = time.ParseDuration("24h")
	DurationToValueMap[DURATION_FOREVER], _ = time.ParseDuration("0s")
}

func (r ConnRequest) String() string {
	response := fmt.Sprintf("== ConnRequest:\n")
	response += fmt.Sprintf("Destination: %s\n", r.Destination)
	response += fmt.Sprintf("Port: %s\n", r.Port)
	response += fmt.Sprintf("Proto: %s\n", ProtoToStringMap[r.Proto])
	response += fmt.Sprintf("Command: %s\n", r.Command)
	response += fmt.Sprintf("Cmdline: %s\n", r.Cmdline)
	response += fmt.Sprintf("Pid: %s\n", r.Pid)
	response += fmt.Sprintf("User: %s\n", r.User)
	response += fmt.Sprintf("Timestamp: %s", r.Timestamp.Format(time.RFC3339))
	return response
}

func (s Scope) String() string {
	switch s {
	case SCOPE_ONCE:
		return "Once"
	case SCOPE_SESSION:
		return "For this session"
	case SCOPE_FOREVER:
		return "Forever"
	}
	return "UNKNOWN"
}

func (a Action) String() string {
	switch a {
	case ACTION_WHITELIST:
		return "Whitelist app"
	case ACTION_BLOCK:
		return "Block app"
	case ACTION_ALLOW:
		return "Allow connection"
	case ACTION_DENY:
		return "Deny connection"
	}
	return "UNKNOWN"
}

func (d Duration) String() string {
	switch d {
	case DURATION_5M:
		return "5 minutes"
	case DURATION_1H:
		return "1 hour"
	case DURATION_8H:
		return "8 hours"
	case DURATION_1D:
		return "1 day"
	case DURATION_FOREVER:
		return "Forever"
	}
	return "UNKNOWN"
}

func (u User) String() string {
	switch u {
	case USER_NAME:
		return "Specific user"
	case USER_SYSTEM:
		return "System-wide"
	}
	return "UNKNOWN"
}

func (p Proto) String() string {
	switch p {
	case PROTO_TCP:
		return "tcp"
	case PROTO_UDP:
		return "udp"
	}
	return "UNKNOWN"
}

func (r Response) String() string {
	response := "== Response:\n"
	response += fmt.Sprintf("Scope: %s\n", r.Scope.String())
	response += fmt.Sprintf("User: %s\n", r.User.String())
	response += fmt.Sprintf("Duration: %s\n", r.Duration.String())
	response += fmt.Sprintf("Action: %s", r.Action.String())

	return response
}

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
	response += fmt.Sprintf("Command: %s\n", r.Command)
	response += fmt.Sprintf("Destination: %s\n", r.Destination)
	response += fmt.Sprintf("Port: %s\n", r.Port)
	response += fmt.Sprintf("Proto: %s\n", r.Proto.String())
	response += fmt.Sprintf("User: %s\n", r.User)
	response += fmt.Sprintf("Timestamp: %s\n", r.Timestamp.Format(time.RFC3339))
	response += fmt.Sprintf("Duration: %s\n", r.Duration.String())
	response += fmt.Sprintf("Verdict: %s", r.Verdict.String())
	return response
}

func (r Response) ToJSON() string {
	data, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Response.ToJSON: failed to marshal to json: %v", err)
		return ""
	}
	return string(data)
}