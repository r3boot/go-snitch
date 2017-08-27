package main

import (
	"fmt"
	"os"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui"
)

func main() {
	var (
		dbusUi *ui.DBusUi
		err    error
	)

	glib.ThreadInit(nil)
	gdk.ThreadsInit()
	gdk.ThreadsEnter()
	gtk.Init(nil)

	sessionCache := rules.NewSessionCache()

	icon := ui.NewStatusIcon()

	dbusUi = &ui.DBusUi{}
	if err = dbusUi.Connect(icon.Dialog, sessionCache); err != nil {
		fmt.Fprintf(os.Stderr, "dbusServer:", err)
		os.Exit(1)
	}

	icon.DetailWindow = ui.NewManageDetailWindow(dbusUi)
	icon.ManageWindow = ui.NewManageWindow(dbusUi)

	icon.ManageWindow.SetDetailWindow(icon.DetailWindow)
	icon.ManageWindow.SetSessionCache(sessionCache)

	icon.DetailWindow.SetManageWindow(icon.ManageWindow)
	icon.DetailWindow.SetSessionCache(sessionCache)

	gtk.Main()
	gdk.ThreadsLeave()
}
