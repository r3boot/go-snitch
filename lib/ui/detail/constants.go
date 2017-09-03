package detail

import (
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
)

type ManageDetailDialog struct {
	window           *gtk.Window
	dbus             *ipc.IPCService
	cache            *rules.SessionCache
	rule             rules.RuleDetail
	commandLabel     *gtk.Label
	destinationEntry *gtk.Entry
	portEntry        *gtk.Entry
	userEntry        *gtk.Entry
	systemRadio      *gtk.RadioButton
	userRadio        *gtk.RadioButton
	actionCombo      *gtk.ComboBoxText
	durationCombo    *gtk.ComboBoxText
}
