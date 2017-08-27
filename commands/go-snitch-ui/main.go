package main

import (
	"fmt"
	"os"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

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

	icon := ui.NewStatusIcon()

	dbusUi = &ui.DBusUi{}
	if err = dbusUi.Connect(icon.Dialog); err != nil {
		fmt.Fprintf(os.Stderr, "dbusServer:", err)
		os.Exit(1)
	}

	icon.DetailWindow = ui.NewManageDetailWindow()
	icon.ManageWindow = ui.NewManageWindow(dbusUi, icon.DetailWindow)

	gtk.Main()
	gdk.ThreadsLeave()
}
