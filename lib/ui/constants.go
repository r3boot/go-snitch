package ui

import (
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/snitch"
)

type RuleType int

const (
	RULE_DB      RuleType = 0
	RULE_SESSION RuleType = 1
)

var ProtoNameMap = map[int]string{
	snitch.PROTO_TCP: "tcp",
	snitch.PROTO_UDP: "udp",
}

var VerdictNameMap = map[netfilter.Verdict]string{
	netfilter.NF_ACCEPT: "accept",
	netfilter.NF_DROP:   "reject",
}

var ActionNameMap = map[int]string{
	snitch.DROP_CONN_ONCE_USER:     "reject",
	snitch.DROP_CONN_ONCE_SYSTEM:   "reject",
	snitch.DROP_APP_ONCE_USER:      "reject",
	snitch.DROP_APP_ONCE_SYSTEM:    "reject",
	snitch.ACCEPT_CONN_ONCE_USER:   "accept",
	snitch.ACCEPT_CONN_ONCE_SYSTEM: "accept",
	snitch.ACCEPT_APP_ONCE_USER:    "accept",
	snitch.ACCEPT_APP_ONCE_SYSTEM:  "accept",
}

type ConnRule struct {
	Id        int
	Dstip     string
	Port      string
	Proto     int
	User      string
	Action    string
	Verdict   int
	Timestamp time.Time
	Duration  time.Duration
}

type Rule struct {
	Id          int
	Command     string
	User        string
	Action      string
	Verdict     int
	Timestamp   time.Time
	RuleType    int
	Duration    time.Duration
	RowExpanded bool
	ConnRules   map[int]*ConnRule
}
