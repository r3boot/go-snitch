package ui

import (
	"time"

	"github.com/godbus/dbus"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/rules"
)

const (
	WINDOW_WIDTH  int = 450
	WINDOW_HEIGHT int = 300

	MANAGE_WINDOW_WIDTH  int = 810
	MANAGE_WINDOW_HEIGHT int = 500

	MANAGE_DETAIL_WIDTH  int = 400
	MANAGE_DETAIL_HEIGHT int = 250

	MAX_CACHE_SIZE int = 16384

	RULE_DB      int = 0
	RULE_SESSION int = 1

	ACTION_ONCE    int = 0
	ACTION_SESSION int = 1
	ACTION_ALWAYS  int = 2

	APPLY_USER   int = 0
	APPLY_SYSTEM int = 1

	ACTION_ACCEPT int = 0
	ACTION_DROP   int = 1

	UI_NAME   string          = "net.as65342.GoSnitch.Ui"
	UI_PATH   dbus.ObjectPath = "/net/as65342/GoSnitch/Ui"
	UI_PATH_S string          = "/net/as65342/GoSnitch/Ui"

	DAEMON_NAME   string          = "net.as65342.GoSnitch.Daemon"
	DAEMON_PATH   dbus.ObjectPath = "/net/as65342/GoSnitch/Daemon"
	DAEMON_PATH_S string          = "/net/as65342/GoSnitch/Daemon"
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
	dbus         *DBusUi
	cache        *rules.SessionCache
	ruleset      map[int]*Rule
	ruleTreeview *gtk.TreeView
	ruleStore    *gtk.TreeStore
	detailWindow *ManageDetailWindow
}

type ManageDetailWindow struct {
	window         *gtk.Window
	dbus           *DBusUi
	manageWindow   *ManageWindow
	cache          *rules.SessionCache
	rule           rules.RuleDetail
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
	ManageWindow *ManageWindow
	DetailWindow *ManageDetailWindow
	curState     bool
	menu         *gtk.Menu
	itemEnable   *gtk.MenuItem
	itemDisable  *gtk.MenuItem
}

type ConnRule struct {
	Id        int
	Dstip     string
	Port      string
	Proto     int
	User      string
	Action    string
	Verdict   int
	Timestamp time.Time
	Duration  time.Duration
}

type Rule struct {
	Id        int
	Command   string
	User      string
	Action    string
	Verdict   int
	Timestamp time.Time
	RuleType  int
	Duration  time.Duration
	ConnRules map[int]*ConnRule
}

type DBusUi struct {
	conn   *dbus.Conn
	daemon dbus.BusObject
	cache  *rules.SessionCache
	dialog *DialogWindow
}

type Verdict int
