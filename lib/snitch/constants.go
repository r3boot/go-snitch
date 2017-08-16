package snitch

const (
	DROP_CONN_ONCE = iota
	DROP_CONN_SESSION
	DROP_CONN_ALWAYS
	ACCEPT_CONN_ONCE
	ACCEPT_CONN_SESSION
	ACCEPT_CONN_ALWAYS
	DROP_APP_ONCE
	DROP_APP_SESSION
	DROP_APP_ALWAYS
	ACCEPT_APP_ONCE
	ACCEPT_APP_SESSION
	ACCEPT_APP_ALWAYS
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
