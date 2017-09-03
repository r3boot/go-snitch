package dialog

import (
	"fmt"

	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
)

func (dw *DialogWindow) initCallbacks(builder *gtk.Builder) {
	builder.ConnectSignalsFull(func(builder *gtk.Builder, obj *glib.GObject,
		sig, handler string, conn *glib.GObject, flags glib.ConnectFlags,
		user_data interface{}) {
		switch handler {
		case "OnButtonWhitelistClicked":
			obj.SignalConnect(sig, dw.OnButtonWhitelistClicked, user_data, flags)
		case "OnButtonBlockClicked":
			obj.SignalConnect(sig, dw.OnButtonBlockClicked, user_data, flags)
		case "OnButtonAllowClicked":
			obj.SignalConnect(sig, dw.OnButtonAllowClicked, user_data, flags)
		case "OnButtonDenyClicked":
			obj.SignalConnect(sig, dw.OnButtonDenyClicked, user_data, flags)
		case "OnClose":
			obj.SignalConnect(sig, dw.OnClose, user_data, flags)
		}
	}, nil)
}

func (dw *DialogWindow) OnButtonWhitelistClicked(ctx *glib.CallbackContext) {
	fmt.Printf("action: %s; scope: %s\n", dw.getAction(), dw.getScope())
	dw.Verdict <- dw.whitelistResponseMap[dw.getAction()][dw.getScope()]
	dw.OnClose(ctx)
}

func (dw *DialogWindow) OnButtonBlockClicked(ctx *glib.CallbackContext) {
	dw.Verdict <- dw.blacklistResponseMap[dw.getAction()][dw.getScope()]
	dw.OnClose(ctx)
}

func (dw *DialogWindow) OnButtonAllowClicked(ctx *glib.CallbackContext) {
	dw.Verdict <- dw.allowResponseMap[dw.getAction()][dw.getScope()]
	dw.OnClose(ctx)
}

func (dw *DialogWindow) OnButtonDenyClicked(ctx *glib.CallbackContext) {
	dw.Verdict <- dw.denyResponseMap[dw.getAction()][dw.getScope()]
	dw.OnClose(ctx)
}

func (dw *DialogWindow) OnClose(ctx *glib.CallbackContext) {
	dw.window.Hide()
}
