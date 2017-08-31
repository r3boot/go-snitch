package ipc

import (
	"fmt"
	"github.com/godbus/dbus"
	"github.com/r3boot/go-snitch/lib/snitch"
	"os"
)

func (bus UiBus) GetVerdict(r snitch.ConnRequest) (int, *dbus.Error) {
	// Check if we have a session rule
	sessionVerdict, err := sessionCache.GetVerdict(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sessionCache: Failed to get verdict: %v\n", err)
		os.Exit(1)
	}

	if sessionVerdict != snitch.UNKNOWN {
		fmt.Printf("Verdict by session rule\n")
		return int(sessionVerdict), nil
	}

	dw.SetValues(r)
	dw.Show()

	response := <-dw.Verdict

	switch response {
	case snitch.DROP_CONN_SESSION_USER:
		{
			sessionCache.AddRule(r, snitch.DROP_CONN_ONCE_USER)
		}
	case snitch.DROP_CONN_SESSION_SYSTEM:
		{
			sessionCache.AddRule(r, snitch.DROP_CONN_ONCE_SYSTEM)
		}
	case snitch.ACCEPT_CONN_SESSION_USER:
		{
			sessionCache.AddRule(r, snitch.ACCEPT_CONN_ONCE_USER)
		}
	case snitch.ACCEPT_CONN_SESSION_SYSTEM:
		{
			sessionCache.AddRule(r, snitch.ACCEPT_CONN_ONCE_SYSTEM)
		}
	case snitch.DROP_APP_SESSION_USER:
		{
			sessionCache.AddRule(r, snitch.DROP_APP_ONCE_USER)
		}
	case snitch.DROP_APP_SESSION_SYSTEM:
		{
			sessionCache.AddRule(r, snitch.DROP_APP_ONCE_SYSTEM)
		}
	case snitch.ACCEPT_APP_SESSION_USER:
		{
			sessionCache.AddRule(r, snitch.ACCEPT_APP_ONCE_USER)
		}
	case snitch.ACCEPT_APP_SESSION_SYSTEM:
		{
			sessionCache.AddRule(r, snitch.ACCEPT_APP_ONCE_SYSTEM)
		}
	}

	return response, nil
}
