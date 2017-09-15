package snitch

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/r3boot/go-snitch/lib/datastructures"
)

func (s *Engine) Disable() {
	if s.useFtrace {
		if err := s.ftrace.Disable(); err != nil {
			fmt.Fprintf(os.Stderr, "Snitch.Disable: failed to disable procmon: %v", err)
		}
	}
}

func (s *Engine) DumpPacket(packet gopacket.Packet) string {
	var srcport, dstport uint16

	proto := s.GetProto(packet)
	ipver := s.GetIPVer(packet)
	srcip, dstip := s.GetIPAddrs(packet)
	switch proto {
	case datastructures.PROTO_TCP:
		srcport, dstport = s.GetTCPPorts(packet)
	case datastructures.PROTO_UDP:
		srcport, dstport = s.GetUDPPorts(packet)
	}

	return fmt.Sprintf("%s %s %s:%d -> %s:%d",
		datastructures.ProtoToStringMap[ipver],
		datastructures.ProtoToStringMap[proto],
		srcip.String(), srcport,
		dstip.String(), dstport)
}

func (s *Engine) ProcessPacket(packet gopacket.Packet) (datastructures.ConnRequest, error) {
	var (
		srcport, dstport uint16
	)

	proto := s.GetProto(packet)
	ipver := s.GetIPVer(packet)

	srcip, dstip := s.GetIPAddrs(packet)

	switch proto {
	case datastructures.PROTO_TCP:
		srcport, dstport = s.GetTCPPorts(packet)
	case datastructures.PROTO_UDP:
		srcport, dstport = s.GetUDPPorts(packet)
	default:
		return datastructures.ConnRequest{}, fmt.Errorf("Snitch.ProcessPacket: Unknown protocol: %d", proto)
	}

	pid, user, err := s.procfs.GetPIDAndUser(ipver, proto, srcip, dstip, srcport, dstport)
	if err != nil {
		return datastructures.ConnRequest{}, fmt.Errorf("Snitch.ProcessPacket: %v", err)
	}

	command := ""
	cmdLine := ""
	if s.useFtrace {
		command, cmdLine, err = s.ftrace.GetCmdline(pid)
		if err != nil {
			// Program started before ftrace probe was running?
			log.Warningf("Snitch.ProcessPacket: %v", err)
			command, cmdLine, err = s.procfs.GetCmdLineViaProc(pid)
			if err != nil {
				return datastructures.ConnRequest{}, fmt.Errorf("Snitch.ProcessPacket: %v", err)
			}
		}
	} else {
		command, cmdLine, err = s.procfs.GetCmdLineViaProc(pid)
		if err != nil {
			return datastructures.ConnRequest{}, fmt.Errorf("Snitch.ProcessPacket: %v", err)
		}
	}

	return datastructures.ConnRequest{
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

func (s *Engine) GetProto(packet gopacket.Packet) datastructures.Proto {
	if packet.Layer(layers.LayerTypeTCP) != nil {
		return datastructures.PROTO_TCP
	} else if packet.Layer(layers.LayerTypeUDP) != nil {
		return datastructures.PROTO_UDP
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		return datastructures.PROTO_ICMP
	} else if packet.Layer(layers.LayerTypeICMPv6) != nil {
		return datastructures.PROTO_ICMP6
	}

	return datastructures.PROTO_UNKNOWN
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

func (s *Engine) GetIPVer(packet gopacket.Packet) datastructures.Proto {
	if packet.Layer(layers.LayerTypeIPv4) != nil {
		return datastructures.PROTO_IPV4
	} else if packet.Layer(layers.LayerTypeIPv6) != nil {
		return datastructures.PROTO_IPV6
	}

	return datastructures.PROTO_UNKNOWN
}

func (s *Engine) GetIPAddrs(packet gopacket.Packet) (net.IP, net.IP) {
	switch s.GetIPVer(packet) {
	case datastructures.PROTO_IPV4:
		{
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				return net.IP{}, net.IP{}
			}
			ip, _ := ipLayer.(*layers.IPv4)
			return ip.SrcIP, ip.DstIP
		}
	case datastructures.PROTO_IPV6:
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
