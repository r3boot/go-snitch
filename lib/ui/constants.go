package ui

import "github.com/r3boot/go-snitch/lib/datastructures"

type UiProto int

const (
	UI_PROTO_TCP UiProto = 0
	UI_PROTO_UDP UiProto = 1
)

var ProtoIntMap = map[datastructures.Proto]UiProto{
	datastructures.PROTO_TCP: UI_PROTO_TCP,
	datastructures.PROTO_UDP: UI_PROTO_UDP,
}
