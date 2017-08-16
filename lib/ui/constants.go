package ui

import (
	"github.com/mattn/go-gtk/gtk"
)

const (
	WINDOW_WIDTH  int = 400
	WINDOW_HEIGHT int = 200
)

type DialogWindow struct {
	window      *gtk.Window
	actioncombo *gtk.ComboBoxText
	labelHeader *gtk.Label
	labelBody   *gtk.Label
	Verdict     chan int
}
