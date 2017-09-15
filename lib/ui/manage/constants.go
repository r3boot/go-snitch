package manage

import (
	"time"

	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"

	"github.com/r3boot/go-snitch/lib/datastructures"
	"github.com/r3boot/go-snitch/lib/ipc/manageipc"
	"github.com/r3boot/go-snitch/lib/logger"
)

const (
	COLUMN_COMMAND int = iota
	COLUMN_DESTINATION
	COLUMN_PORT
	COLUMN_PROTO
	COLUMN_USER
	COLUMN_DURATION
	COLUMN_ACTION
)

type RuleItem struct {
	Id          int
	Destination string
	Port        string
	Proto       datastructures.Proto
	User        string
	Timestamp   time.Time
	Duration    time.Duration
	Verdict     datastructures.Verdict
	RuleType    datastructures.RuleType
}

type RuleMeta struct {
	IsAppRule bool
	Rules     []RuleItem
}

type Ruleset map[string]RuleMeta

type ManageWindow struct {
	ipc             *manageipc.ManageIPCService
	ruleset         Ruleset
	window          *widgets.QMainWindow
	fileMenuEnable  *widgets.QAction
	fileMenuDisable *widgets.QAction
	fileMenuClose   *widgets.QAction
	ruleMenuAdd     *widgets.QAction
	ruleMenuEdit    *widgets.QAction
	ruleMenuDelete  *widgets.QAction
	helpMenuHelp    *widgets.QAction
	helpMenuAbout   *widgets.QAction
	treeviewRule    *widgets.QTreeView
	treeviewRoot    *gui.QStandardItem
}

var (
	log *logger.Logger
)
