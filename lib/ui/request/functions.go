package request

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/go-snitch/lib/ui"
)

func (rw *RequestWindow) getScope() ui.Scope {
	return ui.Scope(rw.comboScope.CurrentIndex())
}

func (rw *RequestWindow) getUser() ui.User {
	return ui.User(rw.comboUser.CurrentIndex())
}

func (rw *RequestWindow) getDuration() ui.Duration {
	return ui.Duration(rw.comboDuration.CurrentIndex())
}

func (rw *RequestWindow) Show() {
	rw.window.Show()
}

func (rw *RequestWindow) Hide() {
	rw.window.Hide()
}

func (rw *RequestWindow) setValues(r snitch.ConnRequest) {
	header := fmt.Sprintf("<font size='3'><b>%s wants to connect to the network</b></font>",
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

	destination, err := ui.GetRDNSEntry(r.Dstip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetRDNSEntry failed: %v\n", err)
		destination = r.Dstip
	}

	rw.labelHeader.SetText(header)
	rw.labelCommand.SetText(r.Cmdline)
	rw.labelDestination.SetText(destination)
	rw.labelPort.SetText(port)
	rw.labelPid.SetText(r.Pid)
	rw.labelUser.SetText(r.User)

	rw.comboScope.SetCurrentIndex(ui.ScopeToIntMap[ui.SCOPE_SESSION])
	rw.comboUser.SetCurrentIndex(0)
	rw.comboDuration.SetCurrentIndex(ui.DurationToIntMap[ui.DURATION_1D])
}

func (rw *RequestWindow) getValues() Response {
	response := Response{
		Scope:    rw.getScope(),
		User:     rw.getUser(),
		Duration: rw.getDuration(),
	}
	return response
}

func (rw *RequestWindow) HandleRequest(r snitch.ConnRequest) Response {
	rw.setValues(r)
	rw.Show()
	return <-rw.responseChan
}

func (r Response) Dump() {
	fmt.Printf("Scope: %s\n", r.Scope.String())
	fmt.Printf("User: %s\n", r.User.String())
	fmt.Printf("Duration: %s\n", r.Duration.String())
	fmt.Printf("Action: %s\n", r.Action.String())
}
