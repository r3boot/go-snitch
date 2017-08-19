package ui

import (
	"github.com/mattn/go-gtk/gtk"
)

const (
	WINDOW_WIDTH   int = 450
	WINDOW_HEIGHT  int = 300
	MAX_CACHE_SIZE int = 16384

	ACTION_ONCE    int = 0
	ACTION_SESSION int = 1
	ACTION_ALWAYS  int = 2

	APPLY_USER   int = 0
	APPLY_SYSTEM int = 1
)

var actionOptions = map[int]string{
	ACTION_ONCE:    "Once",
	ACTION_SESSION: "Until Quit",
	ACTION_ALWAYS:  "Forever",
}

var applyOptions = map[int]string{
	APPLY_USER:   "for this user",
	APPLY_SYSTEM: "system-wide",
}

type DialogWindow struct {
	window        *gtk.Window
	actioncombo   *gtk.ComboBoxText
	applycombo    *gtk.ComboBoxText
	labelHeader   *gtk.Label
	labelCmdline  *gtk.Label
	labelIp       *gtk.Label
	labelPort     *gtk.Label
	labelPid      *gtk.Label
	labelUser     *gtk.Label
	labelPortName *gtk.Label
	Verdict       chan int
}
