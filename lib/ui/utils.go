package ui

import (
	"fmt"

	"bufio"
	"context"
	"net"
	"os"
	"regexp"
	"time"
	"unsafe"

	"github.com/mattn/go-gtk/gtk"
)

func ObjectToWindow(builder *gtk.Builder, name string) *gtk.Window {
	return &gtk.Window{
		Bin: *(*gtk.Bin)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func ObjectToDialog(builder *gtk.Builder, name string) *gtk.Dialog {
	return &gtk.Dialog{
		Window: *(*gtk.Window)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func ObjectToLabel(builder *gtk.Builder, name string) *gtk.Label {
	return &gtk.Label{
		Misc: *(*gtk.Misc)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func ObjectToComboBoxText(builder *gtk.Builder, name string) *gtk.ComboBoxText {
	return &gtk.ComboBoxText{
		ComboBox: *(*gtk.ComboBox)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func ObjectToMenuItem(builder *gtk.Builder, name string) *gtk.MenuItem {
	return &gtk.MenuItem{
		Item: *(*gtk.Item)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func ObjectToEntry(builder *gtk.Builder, name string) *gtk.Entry {
	return &gtk.Entry{
		Widget: *(*gtk.Widget)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func ObjectToRadioButton(builder *gtk.Builder, name string) *gtk.RadioButton {
	return &gtk.RadioButton{
		CheckButton: *(*gtk.CheckButton)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func ObjectToTreeView(builder *gtk.Builder, name string) *gtk.TreeView {
	return &gtk.TreeView{
		Container: *(*gtk.Container)(unsafe.Pointer(&builder.GetObject(name).Object)),
	}
}

func NewTreeViewColumn(name string, id int) *gtk.TreeViewColumn {
	renderer := gtk.NewCellRendererText()
	return gtk.NewTreeViewColumnWithAttributes(name, renderer, "text", id)
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
	names, err := net.DefaultResolver.LookupAddr(ctx, dstip)
	defer cancel()

	if err == nil && len(names) > 0 {
		return names[0][:len(names[0])-1], nil
	} else {
		return dstip, nil
	}

	return dstip, fmt.Errorf("GetRDNSEntry: Function failed")
}

func GetRuleId(cmd string, rules map[int]*Rule) int {
	for key, value := range rules {
		if value.Command == cmd {
			return key
		}
	}

	return -1
}
