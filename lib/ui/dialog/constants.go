package dialog

import (
	"time"

	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/ui"
)

type DialogWindow struct {
	window               *gtk.Window
	labelHeader          *gtk.Label
	labelCmdline         *gtk.Label
	labelDestination     *gtk.Label
	labelPort            *gtk.Label
	labelPid             *gtk.Label
	labelUser            *gtk.Label
	labelPortName        *gtk.Label
	comboAction          *gtk.ComboBoxText
	comboScope           *gtk.ComboBoxText
	comboDuration        *gtk.ComboBoxText
	whitelistResponseMap map[ui.Action]map[ui.Scope]int
	blacklistResponseMap map[ui.Action]map[ui.Scope]int
	allowResponseMap     map[ui.Action]map[ui.Scope]int
	denyResponseMap      map[ui.Action]map[ui.Scope]int
	durationMap          map[ui.Duration]time.Duration
	Verdict              chan int
}
