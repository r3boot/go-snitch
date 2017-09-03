package main

import (
	"fmt"
	"os"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/detail"
	"github.com/r3boot/go-snitch/lib/ui/icon"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
	"github.com/r3boot/go-snitch/lib/ui/manage"
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

	icon.DetailDialog = detail.NewManageDetailDialog(bus)
	icon.ManageWindow = manage.NewManageWindow(bus, icon.DetailDialog, sessionCache)

	// icon.ManageWindow.SetDetailWindow(icon.DetailDialog)
	// icon.ManageWindow.SetSessionCache(sessionCache)

	icon.DetailDialog.SetSessionCache(sessionCache)

	gtk.Main()
	gdk.ThreadsLeave()
}
