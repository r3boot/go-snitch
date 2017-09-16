package datastructures

import (
	"time"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
)

type Proto int
type Scope int
type User int
type Action int
type Duration int
type RuleSource int
type RuleType int

const (
	PROTO_UNKNOWN Proto = 255

	PROTO_ICMP  Proto = 1
	PROTO_TCP   Proto = 6
	PROTO_UDP   Proto = 17
	PROTO_ICMP6 Proto = 58

	PROTO_IPV4 Proto = 4
	PROTO_IPV6 Proto = 41

	USER_NAME   User = 0
	USER_SYSTEM User = 1

	SYSTEM_USER string = "*"

	SCOPE_ONCE    Scope = 0
	SCOPE_SESSION Scope = 1
	SCOPE_FOREVER Scope = 2

	DURATION_5M      Duration = 0
	DURATION_1H      Duration = 1
	DURATION_8H      Duration = 2
	DURATION_1D      Duration = 3
	DURATION_FOREVER Duration = 4

	SOURCE_DB      RuleSource = 0
	SOURCE_SESSION RuleSource = 1

	TYPE_APP  RuleType = 0
	TYPE_CONN RuleType = 1

	ACTION_WHITELIST Action = 0
	ACTION_BLOCK     Action = 1
	ACTION_ALLOW     Action = 2
	ACTION_DENY      Action = 3
)

// Created for each new connection. Passed on to requestwindow via DBUS
type ConnRequest struct {
	Destination string
	Port        string
	Proto       Proto
	Pid         string
	Command     string
	Cmdline     string
	User        string
	Timestamp   time.Time
}

// Defines a single item in a ruleset
type RuleItem struct {
	Id          int
	Command     string
	Destination string
	Port        string
	Proto       Proto
	User        string
	Timestamp   time.Time
	Duration    time.Duration
	Verdict     netfilter.Verdict
}

// Created for each response by the request window. Passed back via DBUS
type Response struct {
	Scope    Scope
	User     User
	Duration time.Duration
	Action   Action
	Verdict  netfilter.Verdict
}

type Ruleset []RuleItem

// Used inside the GUI to display a specific rule
type RuleDetail struct {
	RuleItem
	RuleSource RuleSource
}

type UiRulesItem struct {
	RuleType RuleType
	Rules    []RuleDetail
}

type UiRuleset map[string]UiRulesItem

var ProtoToStringMap = map[Proto]string{
	PROTO_ICMP:    "icmp",
	PROTO_TCP:     "tcp",
	PROTO_UDP:     "udp",
	PROTO_ICMP6:   "icmp6",
	PROTO_IPV4:    "ipv4",
	PROTO_IPV6:    "ipv6",
	PROTO_UNKNOWN: "unknown",
}

var DurationToValueMap = map[Duration]time.Duration{}
