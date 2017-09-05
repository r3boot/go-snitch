package main

import (
	"fmt"
	"os"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
	"github.com/r3boot/go-snitch/lib/ui/request"
	"github.com/therecipe/qt/widgets"
)

func main() {
	widgets.NewQApplication(len(os.Args), os.Args)

	rw := request.NewRequestWindow()

	sessionCache := rules.NewSessionCache()

	_, err := ipc.NewIPCService(rw, sessionCache)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: ", err)
		os.Exit(1)
	}

	widgets.QApplication_Exec()
}
