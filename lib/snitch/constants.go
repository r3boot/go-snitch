package snitch

const (
	DROP_CONN_ONCE_USER      int = 0
	DROP_CONN_SESSION_USER   int = 1
	DROP_CONN_ALWAYS_USER    int = 2
	ACCEPT_CONN_ONCE_USER    int = 3
	ACCEPT_CONN_SESSION_USER int = 4
	ACCEPT_CONN_ALWAYS_USER  int = 5
	DROP_APP_ONCE_USER       int = 6
	DROP_APP_SESSION_USER    int = 7
	DROP_APP_ALWAYS_USER     int = 8
	ACCEPT_APP_ONCE_USER     int = 9
	ACCEPT_APP_SESSION_USER  int = 10
	ACCEPT_APP_ALWAYS_USER   int = 11

	DROP_CONN_ONCE_SYSTEM      int = 20
	DROP_CONN_SESSION_SYSTEM   int = 21
	DROP_CONN_ALWAYS_SYSTEM    int = 22
	ACCEPT_CONN_ONCE_SYSTEM    int = 23
	ACCEPT_CONN_SESSION_SYSTEM int = 24
	ACCEPT_CONN_ALWAYS_SYSTEM  int = 25
	DROP_APP_ONCE_SYSTEM       int = 26
	DROP_APP_SESSION_SYSTEM    int = 27
	DROP_APP_ALWAYS_SYSTEM     int = 28
	ACCEPT_APP_ONCE_SYSTEM     int = 29
	ACCEPT_APP_SESSION_SYSTEM  int = 30
	ACCEPT_APP_ALWAYS_SYSTEM   int = 31

	UNKNOWN int = 99
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
