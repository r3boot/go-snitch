package procfs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/r3boot/go-snitch/lib/datastructures"
)

func (p *ProcFS) getData(ipver, proto datastructures.Proto) ([]string, error) {
	proc_t := "UNKNOWN"

	switch ipver {
	case datastructures.PROTO_IPV4:
		{
			switch proto {
			case datastructures.PROTO_TCP:
				proc_t = PROC_TCP
			case datastructures.PROTO_UDP:
				proc_t = PROC_UDP
			default:
				return nil, fmt.Errorf("ProcFS.getData: Unknown protocol %d", proto)
			}
		}
	case datastructures.PROTO_IPV6:
		{
			switch proto {
			case datastructures.PROTO_TCP:
				proc_t = PROC_TCP6
			case datastructures.PROTO_UDP:
				proc_t = PROC_UDP6
			default:
				return nil, fmt.Errorf("ProcFS.getData: Unknown protocol %d", proto)
			}
		}
	default:
		return nil, fmt.Errorf("ProcFS.getData: Unknown ipver: %d", ipver)
	}

	data, err := ioutil.ReadFile(proc_t)
	if err != nil {
		return nil, fmt.Errorf("ProcFS.getData: Failed to read proc data: %v", err)
	}

	lines := strings.Split(string(data), "\n")

	// Return lines without Header line and blank line on the end
	return lines[1 : len(lines)-1], nil

}

func (p *ProcFS) hexToDec(h string) (string, error) {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		return "", fmt.Errorf("ProcFS.hexToDec failed to convert to int: %v", err)
	}

	return fmt.Sprintf("%d", d), nil
}

func (p *ProcFS) ConvertIP(ip net.IP) string {
	var (
		rawip  string
		result string
	)

	if strings.Contains(ip.String(), ".") {
		// ipv4
		rawip = hex.EncodeToString(ip.To4())
		result = strings.ToUpper(rawip[6:8] + rawip[4:6] + rawip[2:4] + rawip[0:2])
	} else {
		for i := 0; i < len(ip); i += 4 {
			result += fmt.Sprintf("%02X%02X%02X%02X", ip[i+3], ip[i+2], ip[i+1], ip[i])
		}
	}

	return result
}

func (p *ProcFS) findPid(inode string) (string, error) {
	// Loop through all fd dirs of process on /proc to compare the inode and
	// get the pid.
	pid := "0"

	d, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		return "", fmt.Errorf("ProcFS.findPid: failed to glob proc entries: %v", err)
	}

	re := regexp.MustCompile(inode)
	for _, item := range d {
		path, _ := os.Readlink(item)
		out := re.FindString(path)
		if len(out) != 0 {
			pid = strings.Split(item, "/")[2]
		}
	}
	return pid, nil
}

func (p *ProcFS) GetCmdLineViaProc(pid string) (string, string, error) {
	exeFile := fmt.Sprintf("/proc/%s/exe", pid)
	cmd, err := os.Readlink(exeFile)
	if err != nil {
		return "", "", fmt.Errorf("ProcFS.GetCmdLineViaProc: readlink failed: %v", err)
	}

	exe := fmt.Sprintf("/proc/%s/cmdline", pid)
	data, _ := ioutil.ReadFile(exe)
	cmdline := bytes.Join(bytes.Split(data, []byte("\x00")), []byte(" "))

	return cmd, string(cmdline), nil
}

func (p *ProcFS) getUser(uid string) (string, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return "", fmt.Errorf("ProcFS.getUser: Failed to lookup username for %d: %v", err)
	}

	return u.Username, nil
}

func (p *ProcFS) removeEmpty(array []string) []string {
	// remove empty data from line
	var new_array []string
	for _, i := range array {
		if i != "" {
			new_array = append(new_array, i)
		}
	}
	return new_array
}

func (p *ProcFS) GetPIDAndUser(ipver, proto datastructures.Proto, srcip, dstip net.IP, srcport, dstport uint16) (string, string, error) {
	var err error

	sip := p.ConvertIP(srcip)
	dip := p.ConvertIP(dstip)

	sport := fmt.Sprintf("%d", srcport)
	dport := fmt.Sprintf("%d", dstport)

	data, err := p.getData(ipver, proto)
	if err != nil {
		return "", "", fmt.Errorf("ProcFS.GetPidAndUser: %v", err)
	}

	for _, line := range data {
		if len(line) == 0 {
			continue
		}

		// local ip and port
		line_array := p.removeEmpty(strings.Split(strings.TrimSpace(line), " "))

		ip_port := strings.Split(line_array[1], ":")
		ip := ip_port[0]
		port, err := p.hexToDec(ip_port[1])
		if err != nil {
			return "", "", fmt.Errorf("ProcFS.GetPidAndUser: %v", err)
		}

		// foreign ip and port
		fip_port := strings.Split(line_array[2], ":")
		fip := fip_port[0]
		fport, err := p.hexToDec(fip_port[1])
		if err != nil {
			return "", "", fmt.Errorf("ProcFS.GetPidAndUser: %v", err)
		}

		if ip == sip && fip == dip && port == sport && fport == dport {
			user, err := p.getUser(line_array[7])
			if err != nil {
				return "", "", fmt.Errorf("ProcFS.GetPidAndUser: %v", err)
			}

			pid, err := p.findPid(line_array[9])
			if err != nil {
				return "", "", fmt.Errorf("ProcFS.GetPidAndUser: %v", err)
			}

			return pid, user, nil
		} else {
			continue
		}
	}

	return "", "", fmt.Errorf("ProcFS.GetPidAndUser: Did not find information about connection")
}
