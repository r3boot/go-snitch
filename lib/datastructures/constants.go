package datastructures

import "time"

type Proto int
type Scope int
type User int
type Action int
type Duration int
type RuleType int
type Verdict int
type ResponseType int

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

	VERDICT_ACCEPT  Verdict = 0
	VERDICT_REJECT  Verdict = 1
	VERDICT_UNKNOWN Verdict = 255

	DROP_CONN_ONCE_USER      ResponseType = 0
	DROP_CONN_SESSION_USER   ResponseType = 1
	DROP_CONN_ALWAYS_USER    ResponseType = 2
	ACCEPT_CONN_ONCE_USER    ResponseType = 3
	ACCEPT_CONN_SESSION_USER ResponseType = 4
	ACCEPT_CONN_ALWAYS_USER  ResponseType = 5
	DROP_APP_ONCE_USER       ResponseType = 6
	DROP_APP_SESSION_USER    ResponseType = 7
	DROP_APP_ALWAYS_USER     ResponseType = 8
	ACCEPT_APP_ONCE_USER     ResponseType = 9
	ACCEPT_APP_SESSION_USER  ResponseType = 10
	ACCEPT_APP_ALWAYS_USER   ResponseType = 11

	DROP_CONN_ONCE_SYSTEM      ResponseType = 20
	DROP_CONN_SESSION_SYSTEM   ResponseType = 21
	DROP_CONN_ALWAYS_SYSTEM    ResponseType = 22
	ACCEPT_CONN_ONCE_SYSTEM    ResponseType = 23
	ACCEPT_CONN_SESSION_SYSTEM ResponseType = 24
	ACCEPT_CONN_ALWAYS_SYSTEM  ResponseType = 25
	DROP_APP_ONCE_SYSTEM       ResponseType = 26
	DROP_APP_SESSION_SYSTEM    ResponseType = 27
	DROP_APP_ALWAYS_SYSTEM     ResponseType = 28
	ACCEPT_APP_ONCE_SYSTEM     ResponseType = 29
	ACCEPT_APP_SESSION_SYSTEM  ResponseType = 30
	ACCEPT_APP_ALWAYS_SYSTEM   ResponseType = 31

	RESPONSE_UNKNOWN ResponseType = 255
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
	Duration    time.Duration
}

// Created for each response by the request window. Passed back via DBUS
type Response struct {
	Scope    Scope
	User     User
	Duration Duration
	Action   Action
}

// Defines a single item in a ruleset
type RuleItem struct {
	Id          int
	Command     string
	Cmdline     string
	Destination string
	Port        string
	Proto       Proto
	User        string
	Timestamp   time.Time
	Duration    time.Duration
	Verdict     Verdict
}

// Used inside the GUI to display a specific rule
type RuleDetail struct {
	RuleItem
	RuleType RuleType
}

type Ruleset []RuleItem

var ProtoToStringMap = map[Proto]string{
	PROTO_ICMP:    "icmp",
	PROTO_TCP:     "tcp",
	PROTO_UDP:     "udp",
	PROTO_ICMP6:   "icmp6",
	PROTO_IPV4:    "ipv4",
	PROTO_IPV6:    "ipv6",
	PROTO_UNKNOWN: "unknown",
}
