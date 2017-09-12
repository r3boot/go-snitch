package detail

import (
	"github.com/r3boot/go-snitch/lib/ui/ipc"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/widgets"
)

func NewManageDetailDialog(dbus *ipc.IPCService) *ManageDetailDialog {
	dw := &DetailWindow{
		dbus: dbus,
	}

	// QMainWindow
	dw.window = widgets.NewQMainWindow(nil, 0)
	dw.window.SetWindowModality(core.Qt__ApplicationModal)

	// QVBoxLayout for top/bottom divider
	vboxWidget := widgets.NewQWidget(nil, 0)
	vbox := widgets.NewQVBoxLayout2(vboxWidget)

	headerHboxWidget := widgets.NewQWidget(nil, 0)
	headerHbox := widgets.NewQHBoxLayout2(headerHboxWidget)
	vbox.AddWidget(headerHboxWidget, 0, core.Qt__AlignLeft)

	// QLabel for command
	commandHeaderLabel := widgets.NewQLabel2("Edit settings for:", nil, 0)
	headerHbox.AddWidget(commandHeaderLabel, 0, core.Qt__AlignLeft)

	commandLabel := widgets.NewQLabel2("UNSET", nil, 0)
	headerHbox.AddWidget(commandLabel, 0, core.Qt__AlignLeft)

	// QHBoxLayout for the two main frames
	mainHboxWidget := widgets.NewQWidget(nil, 0)
	mainHbox := widgets.NewQHBoxLayout2(mainHboxWidget)
	vbox.AddWidget(mainHboxWidget, 0, core.Qt__AlignLeft)

	// QFrame for the left pane
	frameLeft := widgets.NewQFrame(nil, 0)
	frameLeft.SetFrameStyle(int(widgets.QFrame__Box) | int(widgets.QFrame__Raised))
	mainHbox.AddWidget(frameLeft, 0, core.Qt__AlignLeft)

	// QGridLayout for left pane
	leftLayout := widgets.NewQGridLayout(frameLeft)

	// QLabel + QLineEdit for destination
	destinationHeaderLabel := widgets.NewQLabel2("Destination:", nil, 0)
	leftLayout.AddWidget(destinationHeaderLabel, 1, 0, core.Qt__AlignLeft)

	dw.entryDestination = widgets.NewQLineEdit(nil)
	leftLayout.AddWidget(dw.entryDestination, 1, 1, core.Qt__AlignLeft)

	// QLabel + QLineEdit for port
	portHeaderLabel := widgets.NewQLabel2("Port:", nil, 0)
	leftLayout.AddWidget(portHeaderLabel, 2, 0, core.Qt__AlignLeft)

	dw.entryPort = widgets.NewQLineEdit(nil)
	leftLayout.AddWidget(dw.entryPort, 2, 1, core.Qt__AlignLeft)

	protoHeaderLabel := widgets.NewQLabel2("Proto:", nil, 0)
	leftLayout.AddWidget(protoHeaderLabel, 3, 0, core.Qt__AlignLeft)

	dw.comboProto = widgets.NewQComboBox(nil)
	comboProtoItems := []string{"tcp", "udp"}
	dw.comboProto.AddItems(comboProtoItems)
	leftLayout.AddWidget(dw.comboProto, 3, 1, core.Qt__AlignLeft)

	// QFrame for right pane
	frameRight := widgets.NewQFrame(nil, 0)
	frameRight.SetFrameStyle(int(widgets.QFrame__Box) | int(widgets.QFrame__Raised))
	mainHbox.AddWidget(frameRight, 0, core.Qt__AlignLeft)

	// QGridLayout for right pane
	rightLayout := widgets.NewQGridLayout(frameRight)

	scopeHeaderLabel := widgets.NewQLabel2("Scope:", nil, 0)
	rightLayout.AddWidget(scopeHeaderLabel, 0, 0, core.Qt__AlignLeft)

	// QLabel for scope
	scopeGridWidget := widgets.NewQWidget(nil, 0)
	scopeGrid := widgets.NewQGridLayout(scopeGridWidget)

	// QRadioButtons + QLineEdit for scope
	dw.radioSystem = widgets.NewQRadioButton(nil)
	scopeGrid.AddWidget(dw.radioSystem, 0, 0, core.Qt__AlignLeft)

	dw.labelSystem = widgets.NewQLabel2("System-wide", nil, 0)
	scopeGrid.AddWidget(dw.labelSystem, 0, 1, core.Qt__AlignLeft)

	dw.radioUser = widgets.NewQRadioButton(nil)
	scopeGrid.AddWidget(dw.radioUser, 1, 0, core.Qt__AlignLeft)

	dw.entryUser = widgets.NewQLineEdit(nil)
	scopeGrid.AddWidget(dw.entryUser, 1, 1, core.Qt__AlignLeft)

	rightLayout.AddWidget(scopeGridWidget, 0, 1, core.Qt__AlignLeft)

	// QLabel + QComboBox for duration
	durationHeaderLabel := widgets.NewQLabel2("Duration:", nil, 0)
	rightLayout.AddWidget(durationHeaderLabel, 1, 0, core.Qt__AlignLeft)

	dw.comboDuration = widgets.NewQComboBox(nil)
	durationComboItems := []string{"5 minutes", "1 hour", "8 hours", "1 day", "forever"}
	dw.comboDuration.AddItems(durationComboItems)
	rightLayout.AddWidget(dw.comboDuration, 1, 1, core.Qt__AlignLeft)

	// QLabel + QComboBox for action
	actionHeaderLabeL := widgets.NewQLabel2("Action:", nil, 0)
	rightLayout.AddWidget(actionHeaderLabeL, 2, 0, core.Qt__AlignLeft)

	dw.comboAction = widgets.NewQComboBox(nil)
	actionComboItems := []string{"accept", "reject"}
	dw.comboAction.AddItems(actionComboItems)
	rightLayout.AddWidget(dw.comboAction, 2, 1, core.Qt__AlignLeft)

	// Button box for Save + Delete
	buttonHboxWidget := widgets.NewQWidget(nil, 0)
	buttonHbox := widgets.NewQHBoxLayout2(buttonHboxWidget)
	vbox.AddWidget(buttonHboxWidget, 0, core.Qt__AlignRight)

	dw.buttonSave = widgets.NewQPushButton2("Save", nil)
	buttonHbox.AddWidget(dw.buttonSave, 0, core.Qt__AlignCenter)

	dw.buttonDelete = widgets.NewQPushButton2("Delete", nil)
	buttonHbox.AddWidget(dw.buttonDelete, 0, core.Qt__AlignCenter)

	dw.window.SetCentralWidget(vboxWidget)

	dw.initCallbacks()

	return dw
}
