package ui

import (
	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
)

func (s Scope) String() string {
	switch s {
	case SCOPE_ONCE:
		return "SCOPE_ONCE"
	case SCOPE_SESSION:
		return "SCOPE_SESSION"
	case SCOPE_FOREVER:
		return "SCOPE_FOREVER"
	}
	return "UNKNOWN"
}

func (a Action) String() string {
	switch a {
	case ACTION_WHITELIST:
		return "ACTION_WHITELIST"
	case ACTION_BLOCK:
		return "ACTION_BLOCK"
	case ACTION_ALLOW:
		return "ACTION_ALLOW"
	case ACTION_DENY:
		return "ACTION_DENY"
	}
	return "UNKNOWN"
}

func (d Duration) String() string {
	switch d {
	case DURATION_5M:
		return "DURATION_5M"
	case DURATION_1H:
		return "DURATION_1H"
	case DURATION_8H:
		return "DURATION_8H"
	case DURATION_1D:
		return "DURATION_1D"
	case DURATION_FOREVER:
		return "DURATION_FOREVER"
	}
	return "UNKNOWN"
}

func (u User) String() string {
	switch u {
	case USER_NAME:
		return "USER_NAME"
	case USER_SYSTEM:
		return "USER_SYSTEM"
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

func NFVerdictToVerdict(v netfilter.Verdict) Verdict {
	switch v {
	case netfilter.NF_ACCEPT:
		return VERDICT_ACCEPT
	case netfilter.NF_DROP:
		return VERDICT_REJECT
	default:
		return VERDICT_REJECT
	}
}

func (v Verdict) String() string {
	switch v {
	case VERDICT_ACCEPT:
		return "accept"
	case VERDICT_REJECT:
		return "reject"
	default:
		return "UNKNOWN"
	}
}
