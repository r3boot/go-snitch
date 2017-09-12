package systray

import (
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

type Systray struct {
	trayicon         *widgets.QSystemTrayIcon
	iconEnabled      *gui.QIcon
	iconDisabled     *gui.QIcon
	popupMenuEnable  *widgets.QAction
	popupMenuDisable *widgets.QAction
	popupMenuManage  *widgets.QAction
}
