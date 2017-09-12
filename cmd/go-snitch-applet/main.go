package main

import (
	"fmt"
	"os"

	"github.com/therecipe/qt/widgets"

	"github.com/r3boot/go-snitch/lib/ipc/handleripc"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/request"
	"github.com/r3boot/go-snitch/lib/ui/systray"
)

func main() {
	widgets.NewQApplication(len(os.Args), os.Args)

	rw := request.NewRequestWindow()
	sessionCache := rules.NewSessionCache()

	_, err := handleripc.NewHandlerIPCService(rw, sessionCache)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: ", err)
		os.Exit(1)
	}

	systray.NewSystray()

	widgets.QApplication_Exec()
}
