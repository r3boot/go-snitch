package ui

import "github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"

func (s Scope) String() string {
	return string(s)
}

func (a Action) String() string {
	return string(a)
}

func (d Duration) String() string {
	return string(d)
}

func (p Proto) String() string {
	switch p {
	case PROTO_TCP:
		return "tcp"
	case PROTO_UDP:
		return "udp"
	default:
		return "UNKNOWN"
	}
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
