package main

import (
	"fmt"
	"os"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/dbus"

	"github.com/r3boot/go-snitch/lib/ui"
)

func main() {
	var (
		dbusServer *dbus.DBusServer
		err        error
	)

	glib.ThreadInit(nil)
	gdk.ThreadsInit()
	gdk.ThreadsEnter()
	gtk.Init(nil)

	icon := ui.NewStatusIcon()
	// ui.NewStatusIcon()

	dbusServer = &dbus.DBusServer{}
	if err = dbusServer.Connect(icon.Dialog); err != nil {
		fmt.Fprintf(os.Stderr, "dbusServer:", err)
		os.Exit(1)
	}

	gtk.Main()
	gdk.ThreadsLeave()
}
