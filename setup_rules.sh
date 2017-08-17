#!/bin/sh

iptables -I OUTPUT -m tcp -p tcp --dport 80 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
iptables -I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

ip6tables -I OUTPUT -m tcp -p tcp --dport 80 -j NFQUEUE --queue-num 0
ip6tables -I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
