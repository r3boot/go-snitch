package kernel

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Netfilter struct {
	iptables  string
	ip6tables string
}

func NewNetfilter(iptables string, ip6tables string) *Netfilter {
	nf := &Netfilter{
		iptables:  iptables,
		ip6tables: ip6tables,
	}
	return nf
}

func (nf *Netfilter) ip4rule(rule string) {
	cmd := exec.Command(nf.iptables, strings.Split(rule, " ")...)
	err := cmd.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run iptables: %v\n", err)
		os.Exit(1)
	}
}

func (nf *Netfilter) ip6rule(rule string) {
	cmd := exec.Command(nf.ip6tables, strings.Split(rule, " ")...)
	err := cmd.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run ip6tables: %v\n", err)
		os.Exit(1)
	}
}

func (nf *Netfilter) SetupRules() {
	// For now, only filter TCP and UDP
	nf.ip4rule("-I OUTPUT -m tcp -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip4rule("-I OUTPUT -m udp -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip4rule("-I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	nf.ip4rule("-I OUTPUT -o lo -j ACCEPT")

	nf.ip6rule("-I OUTPUT -m tcp -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip6rule("-I OUTPUT -m udp -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip6rule("-I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	nf.ip6rule("-I OUTPUT -o lo -j ACCEPT")
}

func (nf *Netfilter) CleanupRules() {
	nf.ip4rule("-D OUTPUT -m tcp -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip4rule("-D OUTPUT -m udp -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip4rule("-D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	nf.ip4rule("-D OUTPUT -o lo -j ACCEPT")

	nf.ip6rule("-D OUTPUT -m tcp -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip6rule("-D OUTPUT -m udp -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip6rule("-D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	nf.ip6rule("-D OUTPUT -o lo -j ACCEPT")
}
