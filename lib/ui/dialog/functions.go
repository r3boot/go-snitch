package dialog

import (
	"fmt"
	"path"
	"strings"

	"github.com/mattn/go-gtk/gdk"

	"os"

	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/go-snitch/lib/ui"
)

func (dw *DialogWindow) getAction() ui.Action {
	return ui.IntToActionMap[dw.comboAction.GetActive()]
}

func (dw *DialogWindow) getScope() ui.Scope {
	return ui.IntToScopeMap[dw.comboScope.GetActive()]
}

func (dw *DialogWindow) Show() {
	gdk.ThreadsEnter()
	dw.window.Show()
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

	destip, err := ui.GetRDNSEntry(r.Dstip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetRDNSEntry failed: %v\n", err)
	}

	cmdline := r.Cmdline
	if len(cmdline) > 44 {
		cmdline = cmdline[:41] + "..."
	}

	dw.labelHeader.SetText(appname)
	dw.labelCmdline.SetText(cmdline)
	dw.labelDestination.SetText(destip)
	dw.labelPort.SetText(port)
	dw.labelPid.SetText(r.Pid)
	dw.labelUser.SetText(r.User)

	dw.comboAction.SetActive(ui.ActionToIntMap[ui.ACTION_SESSION])
	dw.comboScope.SetActive(ui.ScopeToIntMap[ui.SCOPE_USER])
	dw.comboDuration.SetActive(ui.DurationToIntMap[ui.DURATION_24H])
}
