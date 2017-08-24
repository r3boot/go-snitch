package ui

import (
	"github.com/r3boot/go-snitch/lib/rules"

	"github.com/mattn/go-gtk/gtk"
)

const (
	WINDOW_WIDTH  int = 450
	WINDOW_HEIGHT int = 300

	MANAGE_WINDOW_WIDTH  int = 750
	MANAGE_WINDOW_HEIGHT int = 500

	MANAGE_DETAIL_WIDTH  int = 400
	MANAGE_DETAIL_HEIGHT int = 250

	MAX_CACHE_SIZE int = 16384

	ACTION_ONCE    int = 0
	ACTION_SESSION int = 1
	ACTION_ALWAYS  int = 2

	APPLY_USER   int = 0
	APPLY_SYSTEM int = 1

	ACTION_ACCEPT int = 0
	ACTION_DROP   int = 1
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

type ManageWindow struct {
	window       *gtk.Window
	ruleSet      map[string]rules.RuleItem
	ruleTreeview *gtk.TreeView
	ruleStore    *gtk.TreeStore
	detail       *ManageDetailWindow
}

type ManageDetailWindow struct {
	window         *gtk.Window
	commandLabel   *gtk.Label
	dstipLabel     *gtk.Entry
	portLabel      *gtk.Entry
	userLabelEntry *gtk.Entry
	radioSystem    *gtk.RadioButton
	radioUser      *gtk.RadioButton
	actionLabel    *gtk.ComboBoxText
}

type StatusIcon struct {
	icon         *gtk.StatusIcon
	Dialog       *DialogWindow
	manageWindow *ManageWindow
	detailWindow *ManageDetailWindow
	curState     bool
	menu         *gtk.Menu
	itemEnable   *gtk.MenuItem
	itemDisable  *gtk.MenuItem
}
