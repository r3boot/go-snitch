package ui

import (
	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/snitch"
)

type Proto int
type Scope string
type User string
type Action int
type Duration string
type RuleType int
type Verdict int

const (
	USER_NAME   User = "for this user"
	USER_SYSTEM User = "system wide"

	SCOPE_ONCE    Scope = "only once"
	SCOPE_SESSION Scope = "for this session"
	SCOPE_FOREVER Scope = "forever"

	DURATION_5M      Duration = "5m"
	DURATION_1H      Duration = "1h"
	DURATION_8H      Duration = "8h"
	DURATION_1D      Duration = "24h"
	DURATION_FOREVER Duration = "forever"

	TYPE_DB      RuleType = 0
	TYPE_SESSION RuleType = 1

	PROTO_TCP Proto = 0
	PROTO_UDP Proto = 1

	ACTION_WHITELIST Action = 0
	ACTION_BLOCK     Action = 1
	ACTION_ALLOW     Action = 2
	ACTION_DENY      Action = 3

	VERDICT_ACCEPT Verdict = 0
	VERDICT_REJECT Verdict = 1
)

var ScopeToIntMap map[Scope]int = map[Scope]int{
	SCOPE_ONCE:    0,
	SCOPE_SESSION: 1,
	SCOPE_FOREVER: 2,
}

var UserToIntMap map[User]int = map[User]int{
	USER_NAME:   0,
	USER_SYSTEM: 1,
}

var DurationToIntMap map[Duration]int = map[Duration]int{
	DURATION_5M:      0,
	DURATION_1H:      1,
	DURATION_8H:      2,
	DURATION_1D:      3,
	DURATION_FOREVER: 4,
}

var IntToDurationMap map[int]Duration = map[int]Duration{
	0: DURATION_5M,
	1: DURATION_1H,
	2: DURATION_8H,
	3: DURATION_1D,
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
