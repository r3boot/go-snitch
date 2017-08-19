package snitch

const (
	DROP_CONN_ONCE      int = 0
	DROP_CONN_SESSION   int = 1
	DROP_CONN_ALWAYS    int = 2
	ACCEPT_CONN_ONCE    int = 3
	ACCEPT_CONN_SESSION int = 4
	ACCEPT_CONN_ALWAYS  int = 5
	DROP_APP_ONCE       int = 6
	DROP_APP_SESSION    int = 7
	DROP_APP_ALWAYS     int = 8
	ACCEPT_APP_ONCE     int = 9
	ACCEPT_APP_SESSION  int = 10
	ACCEPT_APP_ALWAYS   int = 11
	UNKNOWN             int = 12
)

type ConnRequest struct {
	SrcIp   string
	DstIp   string
	SrcPort string
	DstPort string
	Proto   string
	Pid     string
	Command string
	Cmdline string
	User    string
}
