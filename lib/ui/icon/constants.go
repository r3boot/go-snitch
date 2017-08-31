package icon

import (
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/ui"
	"github.com/r3boot/go-snitch/lib/ui/dialog"
)

type StatusIcon struct {
	icon         *gtk.StatusIcon
	Dialog       *dialog.DialogWindow
	ManageWindow *ui.ManageWindow
	DetailWindow *ui.ManageDetailWindow
	curState     bool
	menu         *gtk.Menu
	itemEnable   *gtk.MenuItem
	itemDisable  *gtk.MenuItem
}
