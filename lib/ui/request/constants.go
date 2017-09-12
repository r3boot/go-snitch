package request

import (
	"github.com/r3boot/go-snitch/lib/ui"
	"github.com/therecipe/qt/widgets"
)

type Choice int

const (
	CHOICE_WHITELIST Choice = 0
	CHOICE_BLOCK     Choice = 1
	CHOICE_ALLOW     Choice = 2
	CHOICE_DENY      Choice = 3
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
	responseChan     chan Response
}

type Response struct {
	Scope    ui.Scope
	User     ui.User
	Duration ui.Duration
	Action   ui.Action
}
