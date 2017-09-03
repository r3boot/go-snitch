package ui

import (
	"time"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/snitch"
)

type RuleType int

const (
	RULE_DB      RuleType = 0
	RULE_SESSION RuleType = 1
)

type Scope string
type Action string
type Duration string

const (
	SCOPE_USER   Scope = "for this user"
	SCOPE_SYSTEM Scope = "system wide"

	ACTION_ONCE    Action = "only once"
	ACTION_SESSION Action = "for this session"
	ACTION_FOREVER Action = "forever"

	DURATION_5M      Duration = "5m"
	DURATION_1H      Duration = "1h"
	DURATION_8H      Duration = "8h"
	DURATION_24H     Duration = "24h"
	DURATION_FOREVER Duration = "forever"
)

var ActionToIntMap map[Action]int = map[Action]int{
	ACTION_ONCE:    0,
	ACTION_SESSION: 1,
	ACTION_FOREVER: 2,
}

var IntToActionMap map[int]Action = map[int]Action{
	0: ACTION_ONCE,
	1: ACTION_SESSION,
	2: ACTION_FOREVER,
}

var ScopeToIntMap map[Scope]int = map[Scope]int{
	SCOPE_USER:   0,
	SCOPE_SYSTEM: 1,
}

var IntToScopeMap map[int]Scope = map[int]Scope{
	0: SCOPE_USER,
	1: SCOPE_SYSTEM,
}

var DurationToIntMap map[Duration]int = map[Duration]int{
	DURATION_5M:      0,
	DURATION_1H:      1,
	DURATION_8H:      2,
	DURATION_24H:     3,
	DURATION_FOREVER: 4,
}

var IntToDurationMap map[int]Duration = map[int]Duration{
	0: DURATION_5M,
	1: DURATION_1H,
	2: DURATION_8H,
	3: DURATION_24H,
	4: DURATION_FOREVER,
}

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
	RuleType    RuleType
	Duration    time.Duration
	RowExpanded bool
	ConnRules   map[int]*ConnRule
}
