package main

import (
	"fmt"
	"os"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/rules"
	// "github.com/r3boot/go-snitch/lib/ui"
	"github.com/r3boot/go-snitch/lib/ui/icon"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
)

func main() {
	glib.ThreadInit(nil)
	gdk.ThreadsInit()
	gdk.ThreadsEnter()
	gtk.Init(nil)

	sessionCache := rules.NewSessionCache()

	icon := icon.NewStatusIcon()

	bus, err := ipc.NewIPCService(icon.Dialog, sessionCache)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: ", err)
		os.Exit(1)
	}

	/*
		icon.DetailWindow = ui.NewManageDetailWindow(dbusUi)
		icon.ManageWindow = ui.NewManageWindow(dbusUi)

		icon.ManageWindow.SetDetailWindow(icon.DetailWindow)
		icon.ManageWindow.SetSessionCache(sessionCache)

		icon.DetailWindow.SetManageWindow(icon.ManageWindow)
		icon.DetailWindow.SetSessionCache(sessionCache)
	*/

	gtk.Main()
	gdk.ThreadsLeave()
}
