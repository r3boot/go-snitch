package manage

import (
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/detail"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
	"github.com/r3boot/go-snitch/lib/ui"
	"time"
)

type ManageWindow struct {
	window           *gtk.Window
	dbus             *ipc.IPCService
	cache            *rules.SessionCache
	detailWindow     *detail.ManageDetailWindow
	ruleset          map[int]*ui.Rule
	fileMenuEnable   *gtk.MenuItem
	fileMenuDisable  *gtk.MenuItem
	manageMenuEdit   *gtk.MenuItem
	manageMenuDelete *gtk.MenuItem
	ruleTreeview     *gtk.TreeView
	treeviewExpand   map[string]bool
	ruleStore        *gtk.TreeStore
	contextMenu      *gtk.Menu
}
