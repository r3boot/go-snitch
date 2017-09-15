package common

import "time"

type Proto int
type Scope int
type User int
type Action int
type Duration int
type RuleType int
type Verdict int

const (
	PROTO_UNKNOWN int = 255

	PROTO_ICMP  int = 1
	PROTO_TCP   int = 6
	PROTO_UDP   int = 17
	PROTO_ICMP6 int = 58

	PROTO_IPV4 int = 4
	PROTO_IPV6 int = 41

	USER_NAME   User = 0
	USER_SYSTEM User = 1

	SCOPE_ONCE    Scope = 0
	SCOPE_SESSION Scope = 1
	SCOPE_FOREVER Scope = 2

	DURATION_5M      Duration = 0
	DURATION_1H      Duration = 1
	DURATION_8H      Duration = 2
	DURATION_1D      Duration = 3
	DURATION_FOREVER Duration = 4

	TYPE_DB      RuleType = 0
	TYPE_SESSION RuleType = 1

	ACTION_WHITELIST Action = 0
	ACTION_BLOCK     Action = 1
	ACTION_ALLOW     Action = 2
	ACTION_DENY      Action = 3

	VERDICT_ACCEPT Verdict = 0
	VERDICT_REJECT Verdict = 1
)

type ConnRequest struct {
	Destination string
	Port        string
	Proto       int
	Pid         string
	Command     string
	Cmdline     string
	User        string
	Timestamp   time.Time
	Duration    time.Duration
}

var ProtoToStringMap = map[int]string{
	PROTO_ICMP:    "icmp",
	PROTO_TCP:     "tcp",
	PROTO_UDP:     "udp",
	PROTO_ICMP6:   "icmp6",
	PROTO_IPV4:    "ipv4",
	PROTO_IPV6:    "ipv6",
	PROTO_UNKNOWN: "unknown",
}
