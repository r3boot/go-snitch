package icon

import (
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/ui/detail"
	"github.com/r3boot/go-snitch/lib/ui/dialog"
	"github.com/r3boot/go-snitch/lib/ui/manage"
)

type StatusIcon struct {
	icon            *gtk.StatusIcon
	Dialog          *dialog.DialogWindow
	ManageWindow    *manage.ManageWindow
	DetailDialog    *detail.ManageDetailDialog
	curState        bool
	menu            *gtk.Menu
	enableMenuItem  *gtk.MenuItem
	disableMenuItem *gtk.MenuItem
	manageMenuItem  *gtk.MenuItem
}
