package common

import (
	"fmt"
	"time"
)

func (r ConnRequest) String() string {
	response := fmt.Sprintf("ConnRequest:\n")
	response += fmt.Sprintf("Destination: %s\n", r.Destination)
	response += fmt.Sprintf("Port: %s\n", r.Port)
	response += fmt.Sprintf("Proto: %s\n", ProtoToStringMap[r.Proto])
	response += fmt.Sprintf("Command: %s\n", r.Command)
	response += fmt.Sprintf("Cmdline: %s\n", r.Cmdline)
	response += fmt.Sprintf("Pid: %s\n", r.Pid)
	response += fmt.Sprintf("User: %s\n", r.User)
	response += fmt.Sprintf("Timestamp: %s\n", r.Timestamp.Format(time.RFC3339))
	response += fmt.Sprintf("Duration: %s\n", r.Duration)
	return response
}
