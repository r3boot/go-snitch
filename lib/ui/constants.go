package ui

import (
	"github.com/r3boot/go-snitch/lib/snitch"
)

type Proto int
type Scope int
type User int
type Action int
type Duration int
type RuleType int
type Verdict int

const (
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

	PROTO_TCP Proto = 0
	PROTO_UDP Proto = 1

	ACTION_WHITELIST Action = 0
	ACTION_BLOCK     Action = 1
	ACTION_ALLOW     Action = 2
	ACTION_DENY      Action = 3

	VERDICT_ACCEPT Verdict = 0
	VERDICT_REJECT Verdict = 1
)

var ProtoNameMap = map[int]string{
	snitch.PROTO_TCP: "tcp",
	snitch.PROTO_UDP: "udp",
}

var ProtoIntMap = map[int]Proto{
	snitch.PROTO_TCP: PROTO_TCP,
	snitch.PROTO_UDP: PROTO_UDP,
}
