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
		srcport     string
		dstport     string
		procSrcIp   string
		procDstIp   string
		proto       string
		ipLayer     gopacket.Layer
		ip4Header   *layers.IPv4
		ip6Header   *layers.IPv6
		protoHeader gopacket.Layer
		tcpHeader   *layers.TCP
		udpHeader   *layers.UDP
		isIPv4      bool
		isIPv6      bool
		isTCP       bool
		isUDP       bool
		netinfo     kernel.Process
	)

	ipLayer = packet.Layer(layers.LayerTypeIPv4)
	ip4Header, _ = ipLayer.(*layers.IPv4)
	if ip4Header != nil && ip4Header.Version == 4 {
		fmt.Printf("Is ipv4\n")
		srcip = ip4Header.SrcIP
		dstip = ip4Header.DstIP
		isIPv4 = true
	} else { // IPv6
		fmt.Printf("Is ipv6\n")
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		ip6Header, _ = ipLayer.(*layers.IPv6)
		if ip6Header != nil && ip6Header.Version == 6 {
			srcip = ip6Header.SrcIP
			dstip = ip6Header.DstIP
			isIPv6 = true
		} else {
			return ConnRequest{}, fmt.Errorf("Failed to parse IP header: %v\n", packet)
		}
	}

	fmt.Printf("here\n")

	srcport = "0"
	dstport = "0"
	proto = "UNDEFINED"

	protoHeader = packet.Layer(layers.LayerTypeTCP)
	if protoHeader != nil {
		tcpHeader = protoHeader.(*layers.TCP)
		srcport = strings.Split(tcpHeader.SrcPort.String(), "(")[0]
		dstport = strings.Split(tcpHeader.DstPort.String(), "(")[0]
		isTCP = true
		proto = "tcp"
	} else {
		protoHeader = packet.Layer(layers.LayerTypeUDP)
		if protoHeader != nil {
			udpHeader = protoHeader.(*layers.UDP)
			srcport = strings.Split(udpHeader.SrcPort.String(), "(")[0]
			dstport = strings.Split(udpHeader.DstPort.String(), "(")[0]
			isUDP = true
			proto = "udp"
		}
	}

	procSrcIp = kernel.ConvertIP(srcip)
	procDstIp = kernel.ConvertIP(dstip)

	if isTCP {
		if isIPv4 {
			netinfo = kernel.Tcp(procSrcIp, procDstIp, srcport, dstport)
		} else if isIPv6 {
			netinfo = kernel.Tcp6(procSrcIp, procDstIp, srcport, dstport)
		}
	} else if isUDP {
		if isIPv4 {
			netinfo = kernel.Udp(procSrcIp, procDstIp, srcport, dstport)
		} else if isIPv6 {
			netinfo = kernel.Udp6(procSrcIp, procDstIp, srcport, dstport)
		}
	}

	exeFile := fmt.Sprintf("/proc/%s/exe", netinfo.Pid)
	cmd, err := os.Readlink(exeFile)
	if err != nil {
		return ConnRequest{}, fmt.Errorf("%v", err)
	}

	return ConnRequest{
		SrcIp:   srcip.String(),
		DstIp:   dstip.String(),
		SrcPort: srcport,
		DstPort: dstport,
		Proto:   proto,
		Pid:     netinfo.Pid,
		Command: cmd,
		Cmdline: netinfo.Cmdline,
		User:    netinfo.User,
	}, nil

}
