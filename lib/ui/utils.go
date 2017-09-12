package ui

import (
	"fmt"
	"bufio"
	"context"
	"net"
	"os"
	"regexp"
	"time"
)

func GetIANAName(proto int, port string) (string, error) {
	result := ""

	fd, err := os.Open("/etc/services")
	if err != nil {
		return result, fmt.Errorf("GetIANAName os.Open failed: %v", err)
	}
	defer fd.Close()

	protoName, ok := ProtoNameMap[proto]
	if !ok {
		return result, fmt.Errorf("GetIANAName ProtoNameMap lookup failed")
	}

	reLine := regexp.MustCompile(fmt.Sprintf("^([a-z0-9-_]+)\\ +%s/%s$", port, protoName))

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		value := reLine.FindStringSubmatch(scanner.Text())
		if len(value) > 0 {
			return value[1], nil
		}
	}

	return result, fmt.Errorf("GetIANAName port name not found")
}

func GetRDNSEntry(dstip string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	names, err := net.DefaultResolver.LookupAddr(ctx, dstip)
	defer cancel()

	if err == nil && len(names) > 0 {
		return names[0][:len(names[0])-1], nil
	} else {
		return dstip, nil
	}

	return dstip, fmt.Errorf("GetRDNSEntry: Function failed")
}
