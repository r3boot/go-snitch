package snitch

import (
	"fmt"
	"net"
	"time"

	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/r3boot/go-snitch/lib/common"
	"github.com/r3boot/go-snitch/lib/kernel"
)

func (s *Engine) Disable() {
	if s.useFtrace {
		if err := s.ftrace.Disable(); err != nil {
			fmt.Fprintf(os.Stderr, "Snitch.Disable: failed to disable procmon: %v", err)
		}
	}
}

func (s *Engine) ProcessPacket(packet gopacket.Packet) (common.ConnRequest, error) {
	var (
		srcport, dstport uint16
	)

	proto := s.GetProto(packet)
	ipver := s.GetIPVer(packet)

	srcip, dstip := s.GetIPAddrs(packet)

	switch proto {
	case common.PROTO_TCP:
		srcport, dstport = s.GetTCPPorts(packet)
	case common.PROTO_UDP:
		srcport, dstport = s.GetUDPPorts(packet)
	default:
		return common.ConnRequest{}, fmt.Errorf("Snitch.ProcessPacket: Unknown protocol: %d", proto)
	}

	pid, user := kernel.GetPIDAndUser(ipver, proto, srcip, dstip, srcport, dstport)
	if pid == "0" {
		return common.ConnRequest{}, fmt.Errorf("Snitch.ProcessPacket: PID not found")
	}

	command := ""
	cmdLine := ""
	if s.useFtrace {
		command, cmdLine = s.ftrace.GetCmdline(pid)

		if command == "UNKNOWN" {
			// Program started before ftrace probe was running?
			command, cmdLine = kernel.GetCmdLineViaProc(pid)
		}
	} else {
		command, cmdLine = kernel.GetCmdLineViaProc(pid)
	}

	return common.ConnRequest{
		Destination: dstip.String(),
		Port:        fmt.Sprintf("%d", dstport),
		Proto:       proto,
		Pid:         fmt.Sprintf("%s", pid),
		Command:     command,
		Cmdline:     cmdLine,
		User:        user,
		Timestamp:   time.Now(),
	}, nil
}

func (s *Engine) GetProto(packet gopacket.Packet) int {
	if packet.Layer(layers.LayerTypeTCP) != nil {
		return common.PROTO_TCP
	} else if packet.Layer(layers.LayerTypeUDP) != nil {
		return common.PROTO_UDP
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		return common.PROTO_ICMP
	} else if packet.Layer(layers.LayerTypeICMPv6) != nil {
		return common.PROTO_ICMP6
	}

	return common.PROTO_UNKNOWN
}

func (s *Engine) GetTCPPorts(packet gopacket.Packet) (uint16, uint16) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if tcpLayer == nil {
		return 0, 0
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	return uint16(tcp.SrcPort), uint16(tcp.DstPort)
}

func (s *Engine) GetUDPPorts(packet gopacket.Packet) (uint16, uint16) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if udpLayer == nil {
		return 0, 0
	}

	udp, _ := udpLayer.(*layers.UDP)

	return uint16(udp.SrcPort), uint16(udp.DstPort)
}

func (s *Engine) GetICMPv4Code(packet gopacket.Packet) (int, string) {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

	if icmpLayer == nil {
		return -1, ""
	}

	icmp, _ := icmpLayer.(*layers.ICMPv4)

	return int(icmp.TypeCode.Code()), icmp.TypeCode.String()
}

func (s *Engine) GetICMPv6Code(packet gopacket.Packet) (int, string) {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv6)

	if icmpLayer == nil {
		return -1, ""
	}

	icmp, _ := icmpLayer.(*layers.ICMPv6)

	return int(icmp.TypeCode.Code()), icmp.TypeCode.String()
}

func (s *Engine) GetIPVer(packet gopacket.Packet) int {
	if packet.Layer(layers.LayerTypeIPv4) != nil {
		return common.PROTO_IPV4
	} else if packet.Layer(layers.LayerTypeIPv6) != nil {
		return common.PROTO_IPV6
	}

	return common.PROTO_UNKNOWN
}

func (s *Engine) GetIPAddrs(packet gopacket.Packet) (net.IP, net.IP) {
	switch s.GetIPVer(packet) {
	case common.PROTO_IPV4:
		{
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				return net.IP{}, net.IP{}
			}
			ip, _ := ipLayer.(*layers.IPv4)
			return ip.SrcIP, ip.DstIP
		}
	case common.PROTO_IPV6:
		{
			ipLayer := packet.Layer(layers.LayerTypeIPv6)
			if ipLayer == nil {
				return net.IP{}, net.IP{}
			}
			ip, _ := ipLayer.(*layers.IPv6)
			return ip.SrcIP, ip.DstIP
		}
	}

	return net.IP{}, net.IP{}
}
