package iptables

import "github.com/r3boot/go-snitch/lib/logger"

const (
	MAX_RESOLVERS int = 16
)

type Iptables struct {
	iptables     string
	ip6tables    string
	ip4Resolvers []string
	ip6Resolvers []string
}

var (
	log *logger.Logger
)
