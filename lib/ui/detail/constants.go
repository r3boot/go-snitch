package detail

import (
	"github.com/r3boot/go-snitch/lib/ui/ipc"
	"github.com/therecipe/qt/widgets"
)

type DetailWindow struct {
	dbus             *ipc.IPCService
	window           *widgets.QMainWindow
	entryDestination *widgets.QLineEdit
	entryPort        *widgets.QLineEdit
	comboProto       *widgets.QComboBox
	buttonSave       *widgets.QPushButton
	buttonDelete     *widgets.QPushButton
	radioSystem      *widgets.QRadioButton
	labelSystem      *widgets.QLabel
	radioUser        *widgets.QRadioButton
	entryUser        *widgets.QLineEdit
	comboDuration    *widgets.QComboBox
	comboAction      *widgets.QComboBox
}
