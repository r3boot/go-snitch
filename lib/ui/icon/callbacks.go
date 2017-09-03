package icon

import (
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
)

func (si *StatusIcon) initCallbacks() {
	si.icon.Connect("popup-menu", si.OnPopupMenu)
	si.enableMenuItem.Connect("activate", si.OnMenuEnableClicked)
	si.disableMenuItem.Connect("activate", si.OnMenuDisableClicked)
	si.manageMenuItem.Connect("activate", si.OnMenuManageClicked)
}

func (si *StatusIcon) OnPopupMenu(ctx *glib.CallbackContext) {
	if si.curState {
		si.enableMenuItem.SetSensitive(false)
		si.disableMenuItem.SetSensitive(true)
	} else {
		si.enableMenuItem.SetSensitive(true)
		si.disableMenuItem.SetSensitive(false)
	}

	si.menu.Popup(nil, nil, gtk.StatusIconPositionMenu, si.icon, uint(ctx.Args(0)), uint32(ctx.Args(1)))
}

func (si *StatusIcon) OnMenuEnableClicked(ctx *glib.CallbackContext) {
	si.curState = true
}

func (si *StatusIcon) OnMenuDisableClicked(ctx *glib.CallbackContext) {
	si.curState = false
}

func (si *StatusIcon) OnMenuManageClicked(ctx *glib.CallbackContext) {
	si.ManageWindow.Show()
}
