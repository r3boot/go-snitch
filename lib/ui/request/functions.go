package request

import (
	"fmt"
	"path"
	"strings"

	"github.com/r3boot/go-snitch/lib/datastructures"
	"github.com/r3boot/go-snitch/lib/utils"
)

func (rw *RequestWindow) getScope() datastructures.Scope {
	return datastructures.Scope(rw.comboScope.CurrentIndex())
}

func (rw *RequestWindow) getUser() datastructures.User {
	return datastructures.User(rw.comboUser.CurrentIndex())
}

func (rw *RequestWindow) getDuration() datastructures.Duration {
	return datastructures.Duration(rw.comboDuration.CurrentIndex())
}

func (rw *RequestWindow) Show() {
	rw.window.Show()
}

func (rw *RequestWindow) Hide() {
	rw.window.Hide()
}

func (rw *RequestWindow) setValues(r datastructures.ConnRequest) {
	rw.curConnRequest = r

	header := fmt.Sprintf("<font size='3'><b>%s wants to connect to the network</b></font>",
		path.Base(strings.Split(r.Command, " ")[0]))

	protoName, ok := datastructures.ProtoToStringMap[r.Proto]
	if !ok {
		protoName = "UNKNOWN"
	}

	port := "UNKNOWN"
	portName, err := utils.GetIANAName(r.Proto, r.Port)
	if err == nil {
		port = fmt.Sprintf("%s/%s (%s)", protoName, r.Port, portName)
	} else {
		port = fmt.Sprintf("%s/%s", protoName, r.Port)
	}

	destination, err := utils.GetRDNSEntry(r.Destination)
	if err != nil {
		log.Warningf("setValues: %v", err)
		destination = r.Destination
	}

	rw.labelHeader.SetText(header)
	rw.labelCommand.SetText(r.Cmdline)
	rw.labelDestination.SetText(destination)
	rw.labelPort.SetText(port)
	rw.labelPid.SetText(r.Pid)
	rw.labelUser.SetText(r.User)

	rw.comboScope.SetCurrentIndex(int(datastructures.SCOPE_SESSION))
	rw.comboUser.SetCurrentIndex(0)
	rw.comboDuration.SetCurrentIndex(int(datastructures.DURATION_1D))
}

func (rw *RequestWindow) getValues() datastructures.Response {
	response := datastructures.Response{}
	response.User = rw.getUser()
	response.Duration = datastructures.DurationToValueMap[rw.getDuration()]
	response.Scope = rw.getScope()

	return response
}

func (rw *RequestWindow) HandleRequest(r datastructures.ConnRequest) datastructures.Response {
	log.Debugf("Got new request")
	rw.setValues(r)
	rw.Show()
	return <-rw.responseChan
}
