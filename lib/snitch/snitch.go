package snitch

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/r3boot/go-snitch/lib/kernel"
)

func GetConnRequest(packet gopacket.Packet) (r ConnRequest, err error) {
	var (
		srcip       net.IP
		dstip       net.IP
		procSrcIp   string
		procDstIp   string
		ipLayer     gopacket.Layer
		ip4Header   *layers.IPv4
		ip6Header   *layers.IPv6
		protoHeader gopacket.Layer
		tcpHeader   *layers.TCP
		udpHeader   *layers.UDP
	)

	netinfo := kernel.Process{}
	srcport := "0"
	dstport := "0"
	proto := PROTO_UNKNOWN
	ipver := PROTO_UNKNOWN

	ipLayer = packet.Layer(layers.LayerTypeIPv4)
	ip4Header, _ = ipLayer.(*layers.IPv4)
	if ip4Header != nil && ip4Header.Version == 4 {
		srcip = ip4Header.SrcIP
		dstip = ip4Header.DstIP
		ipver = PROTO_IPV4
	} else { // IPv6
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		ip6Header, _ = ipLayer.(*layers.IPv6)
		if ip6Header != nil && ip6Header.Version == 6 {
			srcip = ip6Header.SrcIP
			dstip = ip6Header.DstIP
			ipver = PROTO_IPV6
		} else {
			return ConnRequest{}, fmt.Errorf("Failed to parse IP header: %v\n", packet)
		}
	}

	protoHeader = packet.Layer(layers.LayerTypeTCP)
	if protoHeader != nil {
		tcpHeader = protoHeader.(*layers.TCP)
		srcport = strings.Split(tcpHeader.SrcPort.String(), "(")[0]
		dstport = strings.Split(tcpHeader.DstPort.String(), "(")[0]
		proto = PROTO_TCP
	} else {
		protoHeader = packet.Layer(layers.LayerTypeUDP)
		if protoHeader != nil {
			udpHeader = protoHeader.(*layers.UDP)
			srcport = strings.Split(udpHeader.SrcPort.String(), "(")[0]
			dstport = strings.Split(udpHeader.DstPort.String(), "(")[0]
			proto = PROTO_UDP
		}
	}

	procSrcIp = kernel.ConvertIP(srcip)
	procDstIp = kernel.ConvertIP(dstip)

	switch ipver {
	case PROTO_IPV4:
		{
			switch proto {
			case PROTO_TCP:
				{
					netinfo = kernel.Tcp(procSrcIp, procDstIp, srcport, dstport)
				}
			case PROTO_UDP:
				{
					netinfo = kernel.Udp(procSrcIp, procDstIp, srcport, dstport)
				}
			}
		}
	case PROTO_IPV6:
		{
			switch proto {
			case PROTO_TCP:
				{
					netinfo = kernel.Tcp6(procSrcIp, procDstIp, srcport, dstport)
				}
			case PROTO_UDP:
				{
					netinfo = kernel.Udp6(procSrcIp, procDstIp, srcport, dstport)
				}
			}
		}
	}

	if netinfo.Pid == "" {
		return ConnRequest{}, fmt.Errorf("No pid found in netinfo")
	}

	exeFile := fmt.Sprintf("/proc/%s/exe", netinfo.Pid)
	cmd, err := os.Readlink(exeFile)
	if err != nil {
		return ConnRequest{}, fmt.Errorf("%v", err)
	}

	return ConnRequest{
		Dstip:   dstip.String(),
		Port:    dstport,
		Proto:   proto,
		Pid:     netinfo.Pid,
		Command: cmd,
		Cmdline: netinfo.Cmdline,
		User:    netinfo.User,
	}, nil

}
