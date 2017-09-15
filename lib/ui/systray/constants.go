package systray

import (
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"

	"github.com/r3boot/go-snitch/lib/logger"
)

type Systray struct {
	trayicon         *widgets.QSystemTrayIcon
	iconEnabled      *gui.QIcon
	iconDisabled     *gui.QIcon
	popupMenuEnable  *widgets.QAction
	popupMenuDisable *widgets.QAction
	popupMenuManage  *widgets.QAction
}

var (
	log *logger.Logger
)
