package ui

import (
	"fmt"

	_ "github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
)

func NewStatusIcon() *StatusIcon {
	si := &StatusIcon{
		icon: gtk.NewStatusIconFromIconName("security-high"),
	}

	si.Dialog = NewDialogWindow()

	si.menu = gtk.NewMenu()

	si.itemEnable = gtk.NewMenuItemWithLabel("Enable")
	si.itemEnable.Connect("activate", si.EnableFirewall)
	si.menu.Append(si.itemEnable)

	si.itemDisable = gtk.NewMenuItemWithLabel("Disable")
	si.itemDisable.Connect("activate", si.DisableFirewall)
	si.menu.Append(si.itemDisable)

	menuSeparator := gtk.NewSeparatorMenuItem()
	si.menu.Append(menuSeparator)

	menuEdit := gtk.NewMenuItemWithLabel("Edit ruleset")
	menuEdit.Connect("activate", func() {
		si.EditRuleset()
	})
	si.menu.Append(menuEdit)
	si.menu.ShowAll()

	si.icon.Connect("popup-menu", func(ctx *glib.CallbackContext) {
		if si.curState {
			si.itemEnable.SetSensitive(false)
			si.itemDisable.SetSensitive(true)
		} else {
			si.itemEnable.SetSensitive(true)
			si.itemDisable.SetSensitive(false)
		}

		fmt.Printf("Showing popup\n")

		si.menu.Popup(nil, nil, gtk.StatusIconPositionMenu, si.icon, uint(ctx.Args(0)), uint32(ctx.Args(1)))
	})

	return si
}

func (si *StatusIcon) EnableFirewall() {
	si.curState = true
}

func (si *StatusIcon) DisableFirewall() {
	si.curState = false
}

func (si *StatusIcon) EditRuleset() {
	si.detailWindow = NewManageDetailWindow()
	si.manageWindow = NewManageWindow(si.detailWindow)

	si.manageWindow.Show()
}
