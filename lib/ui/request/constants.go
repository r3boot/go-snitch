package request

import (
	"github.com/therecipe/qt/widgets"

	"github.com/r3boot/go-snitch/lib/datastructures"
	"github.com/r3boot/go-snitch/lib/logger"
)

type RequestWindow struct {
	window           *widgets.QMainWindow
	labelHeader      *widgets.QLabel
	labelCommand     *widgets.QLabel
	labelDestination *widgets.QLabel
	labelPort        *widgets.QLabel
	labelPid         *widgets.QLabel
	labelUser        *widgets.QLabel
	comboScope       *widgets.QComboBox
	comboUser        *widgets.QComboBox
	comboDuration    *widgets.QComboBox
	buttonWhitelist  *widgets.QPushButton
	buttonBlock      *widgets.QPushButton
	buttonAllow      *widgets.QPushButton
	buttonDeny       *widgets.QPushButton
	responseChan     chan datastructures.Response
}


var (
	log *logger.Logger
)
