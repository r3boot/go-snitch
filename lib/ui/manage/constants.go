package manage

import (
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui"
	"github.com/r3boot/go-snitch/lib/ui/detail"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
)

const (
	COLUMN_COMMAND = iota
	COLUMN_DESTINATION
	COLUMN_PORT
	COLUMN_PROTO
	COLUMN_USER
	COLUMN_DURATION
	COLUMN_ACTION
)

type ManageWindow struct {
	window          *gtk.Window
	dbus            *ipc.IPCService
	cache           *rules.SessionCache
	detailDialog    *detail.ManageDetailDialog
	ruleset         map[int]*ui.Rule
	fileMenuEnable  *gtk.MenuItem
	fileMenuDisable *gtk.MenuItem
	ruleMenuEdit    *gtk.MenuItem
	ruleMenuDelete  *gtk.MenuItem
	ruleTreeview    *gtk.TreeView
	treeviewExpand  map[string]bool
	ruleStore       *gtk.TreeStore
	contextMenu     *gtk.Menu
}
