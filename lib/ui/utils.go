package ui

import (
	"fmt"

	"bufio"
	"context"
	"github.com/mattn/go-gtk/gtk"
	"net"
	"os"
	"regexp"
	"time"
	"unsafe"
)

func ObjectToLabel(builder *gtk.Builder, name string) *gtk.Label {
	return &gtk.Label{
		*(*gtk.Label)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func ObjectToComboBoxText(builder *gtk.Builder, name string) *gtk.ComboBoxText {
	return &gtk.ComboBoxText{
		*(*gtk.ComboBoxText)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func ObjectToMenuItem(builder *gtk.Builder, name string) *gtk.MenuItem {
	return &gtk.MenuItem{
		Item: *(*gtk.MenuItem)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

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
	names, err := net.DefaultResolver.LookupAddr(ctx, r.Dstip)
	defer cancel()

	if err == nil && len(names) > 0 {
		return names[0][:len(names[0])-1]
	} else {
		return dstip
	}
}

func GetRuleId(cmd string, rules map[int]*Rule) int {
	for key, value := range rules {
		if value.Command == cmd {
			return key
		}
	}

	return -1
}
