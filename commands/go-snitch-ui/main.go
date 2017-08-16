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
		dialog     *ui.DialogWindow
		err        error
	)

	glib.ThreadInit(nil)
	gdk.ThreadsInit()
	gdk.ThreadsEnter()
	gtk.Init(nil)

	dialog = ui.NewDialogWindow()

	dbusServer = &dbus.DBusServer{}
	if err = dbusServer.Connect(dialog); err != nil {
		fmt.Fprintf(os.Stderr, "dbusServer:", err)
		os.Exit(1)
	}

	gtk.Main()
}
