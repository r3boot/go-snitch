package ui

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/rules"
)

func actionToString(action int) string {
	switch action {
	case ACTION_ACCEPT:
		{
			return "accept"
		}
	case ACTION_DROP:
		{
			return "reject"
		}
	}
	return "UNSET"
}

func NewManageWindow(dbus *DBusUi) *ManageWindow {
	mw := &ManageWindow{
		dbus:           dbus,
		treeviewExpand: make(map[string]bool),
	}
	mw.Create()
	return mw
}

func (mw *ManageWindow) Create() {
	mw.window = gtk.NewWindow(gtk.WINDOW_TOPLEVEL)
	mw.window.SetModal(true)
	mw.window.SetPosition(gtk.WIN_POS_CENTER)
	mw.window.SetTitle("Manage ruleset")
	mw.window.SetSizeRequest(MANAGE_WINDOW_WIDTH, MANAGE_WINDOW_HEIGHT)
	mw.window.Connect("delete-event", mw.Hide)

	scrollWin := gtk.NewScrolledWindow(nil, nil)

	mw.ruleTreeview = gtk.NewTreeView()
	mw.ruleStore = gtk.NewTreeStore(glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING)
	mw.ruleTreeview.SetModel(mw.ruleStore.ToTreeModel())

	colCommand := gtk.NewTreeViewColumnWithAttributes("Command", gtk.NewCellRendererText(), "text", 1)
	colCommand.SetSizing(gtk.TREE_VIEW_COLUMN_FIXED)
	colCommand.SetFixedWidth(250)
	mw.ruleTreeview.AppendColumn(colCommand)

	colDestination := gtk.NewTreeViewColumnWithAttributes("Destination", gtk.NewCellRendererText(), "text", 2)
	colDestination.SetSizing(gtk.TREE_VIEW_COLUMN_FIXED)
	colDestination.SetFixedWidth(250)
	mw.ruleTreeview.AppendColumn(colDestination)

	colPort := gtk.NewTreeViewColumnWithAttributes("Port", gtk.NewCellRendererText(), "text", 3)
	colPort.SetSizing(gtk.TREE_VIEW_COLUMN_FIXED)
	colPort.SetFixedWidth(50)
	mw.ruleTreeview.AppendColumn(colPort)

	mw.ruleTreeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("Proto", gtk.NewCellRendererText(), "text", 4))

	mw.ruleTreeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("User", gtk.NewCellRendererText(), "text", 5))

	mw.ruleTreeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("Duration", gtk.NewCellRendererText(), "text", 6))

	mw.ruleTreeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("Action", gtk.NewCellRendererText(), "text", 7))

	mw.ruleTreeview.Connect("row_activated", mw.TreeViewActivate)
	scrollWin.Add(mw.ruleTreeview)

	mw.window.Add(scrollWin)
}

func (mw *ManageWindow) fetchRules() map[int]*Rule {
	dbRules, err := mw.dbus.GetRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dbus: Failed to retrieve rules: %v\n", err)
	}

	ruleset := make(map[int]*Rule)

	for _, item := range dbRules {
		ruleId := getRuleId(item.Cmd, ruleset)
		if ruleId == -1 {
			newRuleId := len(ruleset)
			ruleset[newRuleId] = &Rule{
				Command:   item.Cmd,
				RuleType:  RULE_DB,
				ConnRules: make(map[int]*ConnRule),
			}
			ruleId = newRuleId
		}

		if item.Dstip != "" {
			cmdRuleId := getRuleId(item.Cmd, ruleset)
			if cmdRuleId == -1 {
				ruleset[ruleId] = &Rule{
					RuleType:  RULE_DB,
					ConnRules: make(map[int]*ConnRule),
				}
				cmdRuleId = len(ruleset[cmdRuleId].ConnRules)
			}

			connRuleId := len(ruleset[cmdRuleId].ConnRules)
			if _, ok := ruleset[cmdRuleId].ConnRules[connRuleId]; !ok {
				ruleset[cmdRuleId].ConnRules[connRuleId] = &ConnRule{}
			}

			ruleset[cmdRuleId].ConnRules[connRuleId].Id = item.Id
			ruleset[cmdRuleId].ConnRules[connRuleId].Dstip = item.Dstip
			ruleset[cmdRuleId].ConnRules[connRuleId].Port = item.Port
			ruleset[cmdRuleId].ConnRules[connRuleId].Proto = item.Proto
			ruleset[cmdRuleId].ConnRules[connRuleId].User = item.User
			ruleset[cmdRuleId].ConnRules[connRuleId].Action = VerdictToAction(item.Verdict)
			ruleset[cmdRuleId].ConnRules[connRuleId].Timestamp = item.Timestamp
			ruleset[cmdRuleId].ConnRules[connRuleId].Duration = item.Duration
		} else {
			ruleset[ruleId].Id = item.Id
			ruleset[ruleId].RuleType = RULE_DB
			ruleset[ruleId].User = item.User
			ruleset[ruleId].Action = VerdictToAction(item.Verdict)
			ruleset[ruleId].Timestamp = item.Timestamp
			ruleset[ruleId].Duration = item.Duration
		}
	}

	sessionRules, err := mw.cache.GetAllRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mw.fetchRules: Failed to load session rules: %v\n", err)
	}

	for _, item := range sessionRules {
		ruleId := getRuleId(item.Cmd, ruleset)
		if ruleId == -1 {
			newRuleId := len(ruleset)
			ruleset[newRuleId] = &Rule{
				Command:   item.Cmd,
				RuleType:  RULE_SESSION,
				ConnRules: make(map[int]*ConnRule),
			}
			ruleId = newRuleId
		}

		if item.Dstip != "" {
			cmdRuleId := getRuleId(item.Cmd, ruleset)
			if cmdRuleId == -1 {
				ruleset[ruleId] = &Rule{
					RuleType:  RULE_SESSION,
					ConnRules: make(map[int]*ConnRule),
				}
				cmdRuleId = len(ruleset[cmdRuleId].ConnRules)
			}

			connRuleId := len(ruleset[cmdRuleId].ConnRules)
			if _, ok := ruleset[cmdRuleId].ConnRules[connRuleId]; !ok {
				ruleset[cmdRuleId].ConnRules[connRuleId] = &ConnRule{}
			}

			ruleset[cmdRuleId].ConnRules[connRuleId].Id = item.Id
			ruleset[cmdRuleId].ConnRules[connRuleId].Dstip = item.Dstip
			ruleset[cmdRuleId].ConnRules[connRuleId].Port = item.Port
			ruleset[cmdRuleId].ConnRules[connRuleId].Proto = item.Proto
			ruleset[cmdRuleId].ConnRules[connRuleId].User = item.User
			ruleset[cmdRuleId].ConnRules[connRuleId].Action = ActionToAction(item.Verdict)
			ruleset[cmdRuleId].ConnRules[connRuleId].Verdict = item.Verdict
			ruleset[cmdRuleId].ConnRules[connRuleId].Timestamp = item.Timestamp
			ruleset[cmdRuleId].ConnRules[connRuleId].Duration = item.Duration
		} else {
			ruleset[ruleId].Id = item.Id
			ruleset[ruleId].RuleType = RULE_SESSION
			ruleset[ruleId].User = item.User
			ruleset[ruleId].Action = ActionToAction(item.Verdict)
			ruleset[ruleId].Verdict = item.Verdict
			ruleset[ruleId].Timestamp = item.Timestamp
			ruleset[ruleId].Duration = item.Duration
		}
	}
	return ruleset
}

func (mw *ManageWindow) ClearTreeStore() {
	mw.ruleStore.Clear()
}

func (mw *ManageWindow) LoadRules() {
	mw.ruleset = mw.fetchRules()

	mw.ClearTreeStore()

	for i := 0; i < len(mw.ruleset); i++ {
		rule := mw.ruleset[i]
		var iter gtk.TreeIter
		mw.ruleStore.Append(&iter, nil)
		mw.ruleStore.SetValue(&iter, 1, rule.Command)
		if len(rule.ConnRules) > 0 {
			for j := 0; j < len(rule.ConnRules); j++ {
				connRule := rule.ConnRules[j]
				var connIter gtk.TreeIter
				mw.ruleStore.Append(&connIter, &iter)
				mw.ruleStore.SetValue(&connIter, 2, connRule.Dstip)
				mw.ruleStore.SetValue(&connIter, 3, connRule.Port)
				mw.ruleStore.SetValue(&connIter, 4, protoToString(connRule.Proto))
				mw.ruleStore.SetValue(&connIter, 5, connRule.User)
				mw.ruleStore.SetValue(&connIter, 6, "0")
				mw.ruleStore.SetValue(&connIter, 7, connRule.Action)
			}
		} else {
			mw.ruleStore.SetValue(&iter, 5, rule.User)
			mw.ruleStore.SetValue(&iter, 6, "0")
			mw.ruleStore.SetValue(&iter, 7, rule.Action)
		}
	}
}

func (mw *ManageWindow) RestoreRowExpand() {
	fmt.Printf("mw.treeviewExpand: %v\n", mw.treeviewExpand)
	for path_s, expanded := range mw.treeviewExpand {
		if !expanded {
			continue
		}
		path := gtk.NewTreePathFromString(path_s)
		mw.ruleTreeview.ExpandRow(path, true)
	}
}

func (mw *ManageWindow) DeleteRowExpand(path string) {
	delete(mw.treeviewExpand, path)
}

func (mw *ManageWindow) ToggleRowExpand(path *gtk.TreePath) {
	if mw.ruleTreeview.RowExpanded(path) {
		mw.ruleTreeview.CollapseRow(path)
		mw.treeviewExpand[path.String()] = false
	} else {
		mw.ruleTreeview.ExpandRow(path, true)
		mw.treeviewExpand[path.String()] = true
	}
}

func (mw *ManageWindow) TreeViewActivate() {
	var path *gtk.TreePath
	var column *gtk.TreeViewColumn
	var id string
	var id_i int
	var connId string
	var connId_i int

	mw.ruleTreeview.GetCursor(&path, &column)
	tokens := strings.Split(path.String(), ":")
	if len(tokens) > 1 {
		id = tokens[0]
		id_i, _ = strconv.Atoi(id)
		connId = tokens[1]
		connId_i, _ = strconv.Atoi(connId)
	} else {
		id = tokens[0]
		id_i, _ = strconv.Atoi(id)
	}

	if len(mw.ruleset[id_i].ConnRules) > 0 && connId == "" {
		mw.ToggleRowExpand(path)
		return
	}

	detail := rules.RuleDetail{
		RowPath: gtk.NewTreePathFromString(id),
	}

	if connId == "" {
		detail.Id = mw.ruleset[id_i].Id
		detail.Command = mw.ruleset[id_i].Command
		detail.User = mw.ruleset[id_i].User
		detail.Duration = mw.ruleset[id_i].Duration
		detail.Action = mw.ruleset[id_i].Action
		detail.Verdict = mw.ruleset[id_i].Verdict
		detail.RuleType = mw.ruleset[id_i].RuleType
	} else {
		detail.Id = mw.ruleset[id_i].ConnRules[connId_i].Id
		detail.Command = mw.ruleset[id_i].Command
		detail.Dstip = mw.ruleset[id_i].ConnRules[connId_i].Dstip
		detail.Port = mw.ruleset[id_i].ConnRules[connId_i].Port
		detail.Proto = mw.ruleset[id_i].ConnRules[connId_i].Proto
		detail.User = mw.ruleset[id_i].ConnRules[connId_i].User
		detail.Duration = mw.ruleset[id_i].ConnRules[connId_i].Duration
		detail.Action = mw.ruleset[id_i].ConnRules[connId_i].Action
		detail.Verdict = mw.ruleset[id_i].ConnRules[connId_i].Verdict
		detail.RuleType = mw.ruleset[id_i].RuleType
	}

	mw.detailWindow.SetValues(detail)
	mw.detailWindow.Show()
}

func (mw *ManageWindow) SetDetailWindow(window *ManageDetailWindow) {
	mw.detailWindow = window
}

func (mw *ManageWindow) SetSessionCache(cache *rules.SessionCache) {
	mw.cache = cache
}

func (mw *ManageWindow) Show() {
	mw.LoadRules()
	mw.window.ShowAll()
}

func (mw *ManageWindow) Hide() bool {
	mw.window.Hide()
	return true
}
