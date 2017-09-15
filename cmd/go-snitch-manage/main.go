package main

import (
	"flag"
	"os"

	"github.com/therecipe/qt/widgets"

	"github.com/r3boot/go-snitch/lib/ipc/manageipc"
	"github.com/r3boot/go-snitch/lib/logger"
	"github.com/r3boot/go-snitch/lib/ui/manage"
)

const (
	D_DEBUG     bool = false
	D_TIMESTAMP bool = false
)

var (
	log          *logger.Logger
	manageIpc    *manageipc.ManageIPCService
	manageWindow *manage.ManageWindow

	useDebug     = flag.Bool("d", D_DEBUG, "Use debug output")
	useTimestamp = flag.Bool("t", D_TIMESTAMP, "Use timestamp in output")
)

func init() {
	var err error

	flag.Parse()

	// Initialize logging framework
	log = logger.NewLogger(*useTimestamp, *useDebug)

	// Initialize Qt application
	widgets.NewQApplication(len(os.Args), os.Args)

	// Initialize IPC framework
	manageIpc, err = manageipc.NewManageIPCService(log)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}

	manageWindow = manage.NewManageWindow(log, manageIpc)
}

func main() {
	manageWindow.Show()

	widgets.QApplication_Exec()
}
