package iptables

import (
	"fmt"

	"github.com/r3boot/go-snitch/lib/logger"
	"github.com/r3boot/go-snitch/lib/utils"
)

func NewNetfilter(l *logger.Logger) (*Iptables, error) {
	var err error

	log = l

	iptables, err := utils.Which("iptables")
	if err != nil {
		return nil, fmt.Errorf("NewNetfilter: %v", err)
	}

	ip6tables, err := utils.Which("ip6tables")
	if err != nil {
		return nil, fmt.Errorf("NewNetfilter: %v", err)
	}

	return &Iptables{
		iptables:     iptables,
		ip6tables:    ip6tables,
		ip4Resolvers: make([]string, MAX_RESOLVERS),
		ip6Resolvers: make([]string, MAX_RESOLVERS),
	}, nil
}
