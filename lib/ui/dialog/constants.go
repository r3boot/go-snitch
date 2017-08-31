package dialog

import (
	"github.com/mattn/go-gtk/gtk"
	"time"
)

type Scope string
type Action string
type Duration string

const (
	SCOPE_USER   Scope = "for this user"
	SCOPE_SYSTEM Scope = "system wide"

	ACTION_ONCE    Action = "only once"
	ACTION_SESSION Action = "for this session"
	ACTION_FOREVER Action = "forever"

	DURATION_5M      Duration = "5m"
	DURATION_1H      Duration = "1h"
	DURATION_8H      Duration = "8h"
	DURATION_24H     Duration = "24h"
	DURATION_FOREVER Duration = "forever"
)

type DialogWindow struct {
	window               *gtk.Dialog
	labelHeader          *gtk.Label
	labelCmdline         *gtk.Label
	labelIp              *gtk.Label
	labelPort            *gtk.Label
	labelPid             *gtk.Label
	labelUser            *gtk.Label
	labelPortName        *gtk.Label
	comboAction          *gtk.ComboBoxText
	comboScope           *gtk.ComboBoxText
	comboDuration        *gtk.ComboBoxText
	whitelistResponseMap map[Action]map[Scope]int
	blacklistResponseMap map[Action]map[Scope]int
	allowResponseMap     map[Action]map[Scope]int
	denyResponseMap      map[Action]map[Scope]int
	durationMap          map[string]time.Duration
	Verdict              chan int
}
