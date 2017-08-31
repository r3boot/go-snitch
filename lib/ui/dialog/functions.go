package dialog

import (
	"fmt"
	"github.com/mattn/go-gtk/gdk"
	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/go-snitch/lib/ui"
	"os"
	"path"
	"strings"
	"time"
)

func (dw *DialogWindow) getAction() string {
	return dw.comboAction.GetActiveText()
}

func (dw *DialogWindow) getScope() string {
	return dw.comboScope.GetActiveText()
}

func (dw *DialogWindow) Show() {
	gdk.ThreadsEnter()
	dw.window.ShowAll()
	gdk.ThreadsLeave()
}

func (dw *DialogWindow) SetValues(r snitch.ConnRequest) {
	appname := fmt.Sprintf(
		"%s wants to connect to the network",
		path.Base(strings.Split(r.Command, " ")[0]))

	protoName, ok := ui.ProtoNameMap[r.Proto]
	if !ok {
		protoName = "UNKNOWN"
	}

	port := "UNKNOWN"
	portName, err := ui.GetIANAName(r.Proto, r.Port)
	if err == nil {
		port = fmt.Sprintf("%s/%s (%s)", protoName, r.Port, portName)
	} else {
		port = fmt.Sprintf("%s/%s", protoName, r.Port)
	}

	destip := ui.GetRDNSEntry(r.Dstip)

	cmdline := r.Cmdline
	if len(cmdline) > 44 {
		cmdline = cmdline[:41] + "..."
	}

	dw.labelHeader.SetText(appname)
	dw.labelCmdline.SetText(cmdline)
	dw.labelIp.SetText(destip)
	dw.labelPort.SetText(port)
	dw.labelPid.SetText(r.Pid)
	dw.labelUser.SetText(r.User)

	dw.comboAction.SetActive(ACTION_SESSION)
	dw.comboScope.SetActive(SCOPE_USER)
	dw.comboDuration.SetActive(DURATION_FOREVER)
}
