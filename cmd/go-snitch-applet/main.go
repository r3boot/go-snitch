package main

import (
	"flag"
	"os"

	"github.com/therecipe/qt/widgets"

	"github.com/r3boot/go-snitch/lib/ipc/handleripc"
	"github.com/r3boot/go-snitch/lib/logger"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/request"
	"github.com/r3boot/go-snitch/lib/ui/systray"
)

const (
	D_DEBUG     bool = false
	D_TIMESTAMP bool = false
)

var (
	log           *logger.Logger
	requestWindow *request.RequestWindow
	sessionCache  *rules.SessionCache

	useDebug     = flag.Bool("d", D_DEBUG, "Use debug output")
	useTimestamp = flag.Bool("t", D_TIMESTAMP, "Use timestamp in output")
)

func init() {
	var err error

	flag.Parse()

	// Initialize logging framework
	log = logger.NewLogger(*useTimestamp, *useDebug)

	// Initialize Qt framework
	widgets.NewQApplication(len(os.Args), os.Args)

	// Create new window for handling dbus requests
	requestWindow = request.NewRequestWindow(log)

	sessionCache = rules.NewSessionCache(log)

	// Initialize DBUS service used to communicate with daemon
	_, err = handleripc.NewHandlerIPCService(log, requestWindow, sessionCache)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Initialize system tray. Ignore returned object since we dont use it
	systray.NewSystray(log)
}

func main() {
	// Run Qt application
	widgets.QApplication_Exec()
}
