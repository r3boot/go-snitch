package main

import (
	"fmt"
	"os"

	"github.com/therecipe/qt/widgets"

	"github.com/r3boot/go-snitch/lib/ipc/manageipc"
	"github.com/r3boot/go-snitch/lib/ui/manage"
)

func main() {
	widgets.NewQApplication(len(os.Args), os.Args)

	ipc, err := manageipc.NewManageIPCService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	mw := manage.NewManageWindow(ipc)
	mw.Show()

	widgets.QApplication_Exec()
}
