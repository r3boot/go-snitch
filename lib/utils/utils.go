package utils

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/r3boot/go-snitch/lib/datastructures"
)

func Which(binary string) (string, error) {
	for _, path := range strings.Split(os.Getenv("PATH"), ":") {
		absPath := path + "/" + binary
		_, err := os.Stat(absPath)
		if err == nil {
			return absPath, nil
		}
	}

	return "", fmt.Errorf("Which: %s not found in PATH", binary)
}

func WriteToFile(path string, value []byte) error {
	var (
		fs         os.FileInfo
		fd         *os.File
		numWritten int
		err        error
	)

	if fs, err = os.Stat(path); err != nil {
		return err
	}

	if fs.IsDir() {
		return fmt.Errorf("WriteToFile: stat " + path + ": is a directory")
	}

	if fd, err = os.OpenFile(path, os.O_WRONLY, 0644); err != nil {
		return fmt.Errorf("WriteToFile: %v", err)
	}
	defer fd.Close()

	if numWritten, err = fd.Write(value); err != nil {
		return fmt.Errorf("WriteToFile: %v", err)
	}

	if numWritten != 1 {
		return fmt.Errorf("WriteToFile: write " + path + ": corrupt write")
	}

	return nil
}

func GetIANAName(proto datastructures.Proto, port string) (string, error) {
	result := ""

	fd, err := os.Open("/etc/services")
	if err != nil {
		return result, fmt.Errorf("GetIANAName os.Open failed: %v", err)
	}
	defer fd.Close()

	protoName, ok := datastructures.ProtoToStringMap[proto]
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
