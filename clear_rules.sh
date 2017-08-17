#!/bin/sh

iptables -D OUTPUT -m tcp -p tcp --dport 80 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
iptables -D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

ip6tables -D OUTPUT -m tcp -p tcp --dport 80 -j NFQUEUE --queue-num 0
ip6tables -D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
