package kernel

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type Netfilter struct {
	iptables     string
	ip6tables    string
	ip4Resolvers []string
	ip6Resolvers []string
}

func NewNetfilter(iptables string, ip6tables string) *Netfilter {
	nf := &Netfilter{
		iptables:     iptables,
		ip6tables:    ip6tables,
		ip4Resolvers: make([]string, MAX_RESOLVERS),
		ip6Resolvers: make([]string, MAX_RESOLVERS),
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

	nf.AllowResolvers()
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

	nf.RemoveResolvers()
}

func (nf *Netfilter) RemoveResolvers() {
	// Remove existing resolvers
	for _, ip := range nf.ip4Resolvers {
		nf.ip4rule("-D OUTPUT -d " + ip + " -m tcp -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT")
		nf.ip4rule("-D OUTPUT -d " + ip + " -m udp -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT")
	}

	for _, ip := range nf.ip6Resolvers {
		nf.ip6rule("-D OUTPUT -d " + ip + " -m tcp -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT")
		nf.ip6rule("-D OUTPUT -d " + ip + " -m udp -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT")
	}
}

func (nf *Netfilter) AllowResolvers() error {
	// Add new resolvers
	fd, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("Failed to read resolv.conf: %v", err)
	}
	defer fd.Close()

	reResolvers := regexp.MustCompile("^nameserver\\ ([0-9a-f\\:\\.]+)")

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		match := reResolvers.FindStringSubmatch(scanner.Text())
		if len(match) > 0 {
			ip := match[1]
			if strings.Contains(ip, ":") {
				nf.ip6Resolvers = append(nf.ip6Resolvers, ip)
				nf.ip6rule("-I OUTPUT -d " + ip + " -m tcp -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT")
				nf.ip6rule("-I OUTPUT -d " + ip + " -m udp -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT")
			} else {
				nf.ip4Resolvers = append(nf.ip4Resolvers, ip)
				nf.ip4rule("-I OUTPUT -d " + ip + " -m tcp -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT")
				nf.ip4rule("-I OUTPUT -d " + ip + " -m udp -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT")
			}
		}
	}

	return nil
}
