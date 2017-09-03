package icon

import (
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/ui/dialog"
)

func NewStatusIcon() *StatusIcon {
	si := &StatusIcon{}

	si.menu = gtk.NewMenu()

	si.enableMenuItem = gtk.NewMenuItemWithMnemonic("_Enable")
	si.menu.Add(si.enableMenuItem)

	si.disableMenuItem = gtk.NewMenuItemWithMnemonic("_Disable")
	si.menu.Add(si.disableMenuItem)

	separator := gtk.NewSeparatorMenuItem()
	si.menu.Add(separator)

	si.manageMenuItem = gtk.NewMenuItemWithMnemonic("_Manage")
	si.menu.Add(si.manageMenuItem)

	si.icon = gtk.NewStatusIconFromIconName("security-high")
	si.icon.SetTitle("Go-Snitch")

	si.menu.ShowAll()

	si.Dialog = dialog.NewDialogWindow()

	si.initCallbacks()

	return si
}
