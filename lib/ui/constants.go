package ui

import "github.com/r3boot/go-snitch/lib/common"

const (
	PROTO_TCP Proto = 0
	PROTO_UDP Proto = 1
)

var ProtoIntMap = map[int]Proto{
	common.PROTO_TCP: PROTO_TCP,
	common.PROTO_UDP: PROTO_UDP,
}
