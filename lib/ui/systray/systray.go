package systray

import (
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"

	"github.com/r3boot/go-snitch/lib/logger"
)

func NewSystray(l *logger.Logger) *Systray {

	log = l

	st := &Systray{}

	widget := widgets.NewQWidget(nil, 0)
	widgetLayout := widgets.NewQVBoxLayout()
	widget.SetLayout(widgetLayout)

	st.iconEnabled = gui.NewQIcon5(":qml/enabled.png")
	st.iconDisabled = gui.NewQIcon5(":qml/disabled.png")

	st.trayicon = widgets.NewQSystemTrayIcon(nil)
	st.trayicon.SetIcon(st.iconEnabled)

	systrayMenu := widgets.NewQMenu(nil)

	st.popupMenuEnable = systrayMenu.AddAction("&Enable")
	st.popupMenuDisable = systrayMenu.AddAction("&Disable")
	systrayMenu.AddSeparator()
	st.popupMenuManage = systrayMenu.AddAction("&Manage")

	st.trayicon.SetContextMenu(systrayMenu)

	st.initCallbacks()

	st.trayicon.Show()

	return st
}
