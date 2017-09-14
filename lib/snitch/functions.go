package snitch

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"os"

	"github.com/r3boot/go-snitch/lib/kernel"
)

func (s *Snitch) Disable() {
	if s.useFtrace {
		if err := s.procMon.Disable(); err != nil {
			fmt.Fprintf(os.Stderr, "Snitch.Disable: failed to disable procmon: %v", err)
		}
	}
}

func (s *Snitch) ProcessPacket(packet gopacket.Packet) (ConnRequest, error) {
	var (
		srcport, dstport uint16
	)

	proto := s.GetProto(packet)
	ipver := s.GetIPVer(packet)

	srcip, dstip := s.GetIPAddrs(packet)

	switch proto {
	case PROTO_TCP:
		srcport, dstport = s.GetTCPPorts(packet)
	case PROTO_UDP:
		srcport, dstport = s.GetUDPPorts(packet)
	default:
		return ConnRequest{}, fmt.Errorf("Snitch.ProcessPacket: Unknown protocol: %d", proto)
	}

	pid, user := kernel.GetPIDAndUser(ipver, proto, srcip, dstip, srcport, dstport)
	if pid == "0" {
		return ConnRequest{}, fmt.Errorf("Snitch.ProcessPacket: PID not found")
	}

	command := ""
	cmdLine := ""
	if s.useFtrace {
		command, cmdLine = s.procMon.GetCmdline(pid)

		if command == "UNKNOWN" {
			// Program started before ftrace probe was running?
			command, cmdLine = kernel.GetCmdLineViaProc(pid)
		}
	} else {
		command, cmdLine = kernel.GetCmdLineViaProc(pid)
	}

	return ConnRequest{
		Dstip:     dstip.String(),
		Port:      fmt.Sprintf("%d", dstport),
		Proto:     proto,
		Pid:       fmt.Sprintf("%s", pid),
		Command:   command,
		Cmdline:   cmdLine,
		User:      user,
		Timestamp: time.Now(),
	}, nil
}

func (s *Snitch) GetProto(packet gopacket.Packet) int {
	if packet.Layer(layers.LayerTypeTCP) != nil {
		return PROTO_TCP
	} else if packet.Layer(layers.LayerTypeUDP) != nil {
		return PROTO_UDP
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		return PROTO_ICMP
	} else if packet.Layer(layers.LayerTypeICMPv6) != nil {
		return PROTO_ICMP6
	}

	return PROTO_UNKNOWN
}

func (s *Snitch) GetTCPPorts(packet gopacket.Packet) (uint16, uint16) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if tcpLayer == nil {
		return 0, 0
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	return uint16(tcp.SrcPort), uint16(tcp.DstPort)
}

func (s *Snitch) GetUDPPorts(packet gopacket.Packet) (uint16, uint16) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if udpLayer == nil {
		return 0, 0
	}

	udp, _ := udpLayer.(*layers.UDP)

	return uint16(udp.SrcPort), uint16(udp.DstPort)
}

func (s *Snitch) GetICMPv4Code(packet gopacket.Packet) (int, string) {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

	if icmpLayer == nil {
		return -1, ""
	}

	icmp, _ := icmpLayer.(*layers.ICMPv4)

	return int(icmp.TypeCode.Code()), icmp.TypeCode.String()
}

func (s *Snitch) GetICMPv6Code(packet gopacket.Packet) (int, string) {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv6)

	if icmpLayer == nil {
		return -1, ""
	}

	icmp, _ := icmpLayer.(*layers.ICMPv6)

	return int(icmp.TypeCode.Code()), icmp.TypeCode.String()
}

func (s *Snitch) GetIPVer(packet gopacket.Packet) int {
	if packet.Layer(layers.LayerTypeIPv4) != nil {
		return PROTO_IPV4
	} else if packet.Layer(layers.LayerTypeIPv6) != nil {
		return PROTO_IPV6
	}

	return PROTO_UNKNOWN
}

func (s *Snitch) GetIPAddrs(packet gopacket.Packet) (net.IP, net.IP) {
	switch s.GetIPVer(packet) {
	case PROTO_IPV4:
		{
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				return net.IP{}, net.IP{}
			}
			ip, _ := ipLayer.(*layers.IPv4)
			return ip.SrcIP, ip.DstIP
		}
	case PROTO_IPV6:
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
