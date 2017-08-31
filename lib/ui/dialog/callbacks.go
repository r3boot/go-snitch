package dialog

import (
	"fmt"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/snitch"
	"unsafe"
)

func (dw *DialogWindow) initCallbacks(builder *gtk.Builder) {
	dw.window = &gtk.Dialog{
		Window: *(*gtk.Dialog)(
			unsafe.Pointer(&builder.GetObject("DialogWindow").Object)),
	}

	builder.ConnectSignalsFull(func(builder *gtk.Builder, obj *glib.GObject,
		sig, handler string, conn *glib.GObject, flags glib.ConnectFlags,
		user_data interface{}) {
		switch handler {
		case "OnWhitelistAppClicked":
			obj.SignalConnect(sig, dw.OnWhitelistAppClicked, user_data, flags)
		case "OnBlockAppClicked":
			obj.SignalConnect(sig, dw.OnBlockAppClicked, user_data, flags)
		case "OnAllowClicked":
			obj.SignalConnect(sig, dw.OnAllowClicked, user_data, flags)
		case "OnDenyClicked":
			obj.SignalConnect(sig, dw.OnDenyClicked, user_data, flags)
		case "OnClose":
			obj.SignalConnect(sig, dw.OnClose, user_data, flags)
		}
	}, nil)
}

func (dw *DialogWindow) OnWhitelistAppClicked(ctx glib.CallbackContext) {
	dw.Verdict <- dw.whitelistResponseMap[dw.getAction()][dw.getScope()]
	dw.OnClose(ctx)
}

func (dw *DialogWindow) OnBlockAppClicked(ctx glib.CallbackContext) {
	dw.Verdict <- dw.blacklistResponseMap[dw.getAction()][dw.getScope()]
	dw.OnClose(ctx)
}

func (dw *DialogWindow) OnAllowClicked(ctx glib.CallbackContext) {
	dw.Verdict <- dw.allowResponseMap[dw.getAction()][dw.getScope()]
	dw.OnClose(ctx)
}

func (dw *DialogWindow) OnDenyClicked(ctx glib.CallbackContext) {
	dw.Verdict <- dw.denyResponseMap[dw.getAction()][dw.getScope()]
	dw.OnClose(ctx)
}

func (dw *DialogWindow) OnClose(ctx glib.CallbackContext) {
	dw.window.Hide()
}
