package ui

import (
	"github.com/mattn/go-gtk/gtk"
)

const (
	WINDOW_WIDTH  int = 450
	WINDOW_HEIGHT int = 300
)

type DialogWindow struct {
	window        *gtk.Window
	actioncombo   *gtk.ComboBoxText
	labelHeader   *gtk.Label
	labelCmdline  *gtk.Label
	labelIp       *gtk.Label
	labelPort     *gtk.Label
	labelPid      *gtk.Label
	labelUser     *gtk.Label
	labelPortName *gtk.Label
	Verdict       chan int
}
