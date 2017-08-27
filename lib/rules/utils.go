package rules

import (
	"github.com/r3boot/go-snitch/lib/snitch"
)

func DialogVerdictToString(verdict int) string {
	switch verdict {
	case snitch.DROP_CONN_ONCE_USER:
		{
			return "DROP_CONN_ONCE_USER"
		}
	case snitch.DROP_CONN_SESSION_USER:
		{
			return "DROP_CONN_SESSION_USER"
		}
	case snitch.DROP_CONN_ALWAYS_USER:
		{
			return "DROP_CONN_ALWAYS_USER"
		}
	case snitch.ACCEPT_CONN_ONCE_USER:
		{
			return "ACCEPT_CONN_ONCE_USER"
		}
	case snitch.ACCEPT_CONN_SESSION_USER:
		{
			return "ACCEPT_CONN_SESSION_USER"
		}
	case snitch.ACCEPT_CONN_ALWAYS_USER:
		{
			return "ACCEPT_CONN_ALWAYS_USER"
		}
	case snitch.DROP_APP_ONCE_USER:
		{
			return "DROP_APP_ONCE_USER"
		}
	case snitch.DROP_APP_SESSION_USER:
		{
			return "DROP_APP_SESSION_USER"
		}
	case snitch.DROP_APP_ALWAYS_USER:
		{
			return "DROP_APP_ALWAYS_USER"
		}
	case snitch.ACCEPT_APP_ONCE_USER:
		{
			return "ACCEPT_APP_ONCE_USER"
		}
	case snitch.ACCEPT_APP_SESSION_USER:
		{
			return "ACCEPT_APP_SESSION_USER"
		}
	case snitch.ACCEPT_APP_ALWAYS_USER:
		{
			return "ACCEPT_APP_ALWAYS_USER"
		}
	case snitch.DROP_CONN_ONCE_SYSTEM:
		{
			return "DROP_CONN_ONCE_SYSTEM"
		}
	case snitch.DROP_CONN_SESSION_SYSTEM:
		{
			return "DROP_CONN_SESSION_SYSTEM"
		}
	case snitch.DROP_CONN_ALWAYS_SYSTEM:
		{
			return "DROP_CONN_ALWAYS_SYSTEM"
		}
	case snitch.ACCEPT_CONN_ONCE_SYSTEM:
		{
			return "ACCEPT_CONN_ONCE_SYSTEM"
		}
	case snitch.ACCEPT_CONN_SESSION_SYSTEM:
		{
			return "ACCEPT_CONN_SESSION_SYSTEM"
		}
	case snitch.ACCEPT_CONN_ALWAYS_SYSTEM:
		{
			return "ACCEPT_CONN_ALWAYS_SYSTEM"
		}
	case snitch.DROP_APP_ONCE_SYSTEM:
		{
			return "DROP_APP_ONCE_SYSTEM"
		}
	case snitch.DROP_APP_SESSION_SYSTEM:
		{
			return "DROP_APP_SESSION_SYSTEM"
		}
	case snitch.DROP_APP_ALWAYS_SYSTEM:
		{
			return "DROP_APP_ALWAYS_SYSTEM"
		}
	case snitch.ACCEPT_APP_ONCE_SYSTEM:
		{
			return "ACCEPT_APP_ONCE_SYSTEM"
		}
	case snitch.ACCEPT_APP_SESSION_SYSTEM:
		{
			return "ACCEPT_APP_SESSION_SYSTEM"
		}
	case snitch.ACCEPT_APP_ALWAYS_SYSTEM:
		{
			return "ACCEPT_APP_ALWAYS_SYSTEM"
		}
	default:
		{
			return "UNKNOWN VERDICT"
		}
	}
}
