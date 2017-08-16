package kernel

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
)

const (
	PROC_TCP  = "/proc/net/tcp"
	PROC_UDP  = "/proc/net/udp"
	PROC_TCP6 = "/proc/net/tcp6"
	PROC_UDP6 = "/proc/net/udp6"
)

type Process struct {
	User    string
	Pid     string
	Cmdline string
}

func getData(t string) []string {
	// Get data from tcp or udp file.

	var proc_t string

	if t == "tcp" {
		proc_t = PROC_TCP
	} else if t == "udp" {
		proc_t = PROC_UDP
	} else if t == "tcp6" {
		proc_t = PROC_TCP6
	} else if t == "udp6" {
		proc_t = PROC_UDP6
	} else {
		fmt.Printf("%s is a invalid type, tcp and udp only!\n", t)
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(proc_t)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	lines := strings.Split(string(data), "\n")

	// Return lines without Header line and blank line on the end
	return lines[1 : len(lines)-1]

}

func hexToDec(h string) string {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return fmt.Sprintf("%d", d)
}

func ConvertIP(ip net.IP) string {
	var (
		rawip  string
		result string
		i      int
	)

	if strings.Contains(ip.String(), ".") {
		// ipv4
		rawip = hex.EncodeToString(ip.To4())
		result = strings.ToUpper(rawip[6:8] + rawip[4:6] + rawip[2:4] + rawip[0:2])
	} else {
		for i = 0; i < len(ip); i += 4 {
			result += fmt.Sprintf("%02X%02X%02X%02X", ip[i+3], ip[i+2], ip[i+1], ip[i])
		}
	}

	return result
}

func findPid(inode string) string {
	// Loop through all fd dirs of process on /proc to compare the inode and
	// get the pid.

	pid := "-"

	d, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	re := regexp.MustCompile(inode)
	for _, item := range d {
		path, _ := os.Readlink(item)
		out := re.FindString(path)
		if len(out) != 0 {
			pid = strings.Split(item, "/")[2]
		}
	}
	return pid
}

func getCmdline(pid string) string {
	exe := fmt.Sprintf("/proc/%s/cmdline", pid)
	data, _ := ioutil.ReadFile(exe)
	command := bytes.Join(bytes.Split(data, []byte("\x00")), []byte(" "))
	return string(command)
}

func getUser(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return "UNKNOWN"
	}

	return u.Username
}

func removeEmpty(array []string) []string {
	// remove empty data from line
	var new_array []string
	for _, i := range array {
		if i != "" {
			new_array = append(new_array, i)
		}
	}
	return new_array
}

func netstat(t string, srcip string, dstip string, srcport string, dstport string) Process {
	// Return a array of Process with Name, Ip, Port, State .. etc
	// Require Root acess to get information about some processes.

	data := getData(t)

	for _, line := range data {
		if len(line) == 0 {
			continue
		}

		// local ip and port
		line_array := removeEmpty(strings.Split(strings.TrimSpace(line), " "))

		ip_port := strings.Split(line_array[1], ":")
		ip := ip_port[0]
		port := hexToDec(ip_port[1])

		// foreign ip and port
		fip_port := strings.Split(line_array[2], ":")
		fip := fip_port[0]
		fport := hexToDec(fip_port[1])

		if ip == srcip && fip == dstip && port == srcport && fport == dstport {
			user := getUser(line_array[7])
			pid := findPid(line_array[9])
			return Process{
				User:    user,
				Pid:     pid,
				Cmdline: getCmdline(pid),
			}
		} else {
			continue
		}
	}

	return Process{}

}

func Tcp(srcip string, dstip string, srcport string, dstport string) Process {
	// Get a slice of Process type with TCP data
	data := netstat("tcp", srcip, dstip, srcport, dstport)
	return data
}

func Udp(srcip string, dstip string, srcport string, dstport string) Process {
	// Get a slice of Process type with UDP data
	data := netstat("udp", srcip, dstip, srcport, dstport)
	return data
}

func Tcp6(srcip string, dstip string, srcport string, dstport string) Process {
	// Get a slice of Process type with TCP6 data
	data := netstat("tcp6", srcip, dstip, srcport, dstport)
	return data
}

func Udp6(srcip string, dstip string, srcport string, dstport string) Process {
	// Get a slice of Process type with UDP6 data
	data := netstat("udp6", srcip, dstip, srcport, dstport)
	return data
}
