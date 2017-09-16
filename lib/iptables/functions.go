package iptables

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func (nf *Iptables) ip4rule(rule string) {
	log.Debugf("Running: %s %s", nf.iptables, rule)
	cmd := exec.Command(nf.iptables, strings.Split(rule, " ")...)
	err := cmd.Start()
	if err != nil {
		log.Fatalf("Netfilter.ip4rule: Failed to run iptables: %v", err)
	}
	cmd.Wait()
}

func (nf *Iptables) ip6rule(rule string) {
	log.Debugf("Running: %s %s", nf.ip6tables, rule)
	cmd := exec.Command(nf.ip6tables, strings.Split(rule, " ")...)
	err := cmd.Start()
	if err != nil {
		log.Fatalf("Netfilter.ip6rule: Failed to run ip6tables: %v", err)
	}
	cmd.Wait()
}

func (nf *Iptables) SetupRules() error {
	// For now, only filter TCP and UDP
	nf.ip4rule("-I OUTPUT -m tcp -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip4rule("-I OUTPUT -m udp -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip4rule("-I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	nf.ip4rule("-I OUTPUT -o lo -j ACCEPT")

	nf.ip6rule("-I OUTPUT -m tcp -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip6rule("-I OUTPUT -m udp -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip6rule("-I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	nf.ip6rule("-I OUTPUT -o lo -j ACCEPT")

	return nf.AllowResolvers()

}

func (nf *Iptables) CleanupRules() {
	nf.ip4rule("-D OUTPUT -o lo -j ACCEPT")
	nf.ip4rule("-D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	nf.ip4rule("-D OUTPUT -m tcp -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip4rule("-D OUTPUT -m udp -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")

	nf.ip6rule("-D OUTPUT -o lo -j ACCEPT")
	nf.ip6rule("-D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	nf.ip6rule("-D OUTPUT -m tcp -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
	nf.ip6rule("-D OUTPUT -m udp -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0")
}

func (nf *Iptables) RemoveResolvers() {
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

func (nf *Iptables) AllowResolvers() error {
	// Add new resolvers
	fd, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("Netfilter.AllowResolvers: Failed to read resolv.conf: %v", err)
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
