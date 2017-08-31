package detail

import (
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
	"github.com/r3boot/go-snitch/lib/ui/manage"
)

type ManageDetailWindow struct {
	window         *gtk.Window
	dbus           *ipc.IPCService
	manageWindow   *manage.ManageWindow
	cache          *rules.SessionCache
	rule           rules.RuleDetail
	commandLabel   *gtk.Label
	dstipLabel     *gtk.Entry
	portLabel      *gtk.Entry
	userLabelEntry *gtk.Entry
	radioSystem    *gtk.RadioButton
	radioUser      *gtk.RadioButton
	actionLabel    *gtk.ComboBoxText
}
