#!/bin/sh

iptables -I OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
iptables -I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

ip6tables -I OUTPUT -j NFQUEUE --queue-num 0
ip6tables -I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
