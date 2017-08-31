package icon

import (
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
	"unsafe"
)

func (si *StatusIcon) initCallbacks(builder *gtk.Builder) {
	si.icon = &gtk.StatusIcon{
		*(*gtk.StatusIcon)(
			unsafe.Pointer(&builder.GetObject("StatusIcon").Object)),
	}

	builder.ConnectSignalsFull(func(builder *gtk.Builder, obj *glib.GObject,
		sig, handler string, conn *glib.GObject, flags glib.ConnectFlags,
		user_data interface{}) {
		switch handler {
		case "OnMenuEnableClicked":
			obj.SignalConnect(sig, si.OnMenuEnableClicked, user_data, flags)
		case "OnMenuDisableClicked":
			obj.SignalConnect(sig, si.OnMenuDisableClicked, user_data, flags)
		case "OnMenuManageClicked":
			obj.SignalConnect(sig, si.OnMenuManageClicked, user_data, flags)
		}
	}, nil)
}

func (si *StatusIcon) OnPopupMenu(ctx glib.CallbackContext) {
	if si.curState {
		si.itemEnable.SetSensitive(false)
		si.itemDisable.SetSensitive(true)
	} else {
		si.itemEnable.SetSensitive(true)
		si.itemDisable.SetSensitive(false)
	}
}

func (si *StatusIcon) OnMenuEnableClicked(ctx glib.CallbackContext) {
	si.curState = true
}

func (si *StatusIcon) OnMenuDisableClicked(ctx glib.CallbackContext) {
	si.curState = false
}

func (si *StatusIcon) OnMenuManageClicked(ctx glib.CallbackContext) {
	si.ManageWindow.Show()
}
