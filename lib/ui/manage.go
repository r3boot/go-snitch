package ui

import (
	"strconv"
	"strings"

	"github.com/r3boot/go-snitch/lib/rules"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
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

func NewManageWindow(md *ManageDetailWindow) *ManageWindow {
	mw := &ManageWindow{
		detail: md,
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

	scrollWin := gtk.NewScrolledWindow(nil, nil)

	mw.ruleTreeview = gtk.NewTreeView()
	mw.ruleStore = gtk.NewTreeStore(glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING)
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

	mw.ruleTreeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("User", gtk.NewCellRendererText(), "text", 4))
	mw.ruleTreeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("Action", gtk.NewCellRendererText(), "text", 5))

	mw.ruleTreeview.Connect("row_activated", mw.TreeViewActivate)
	scrollWin.Add(mw.ruleTreeview)

	mw.window.Add(scrollWin)
}

func (mw *ManageWindow) LoadRules(rules map[string]rules.RuleItem) {
	mw.ruleSet = rules
	for i := 0; i <= len(mw.ruleSet); i++ {
		rule := mw.ruleSet[strconv.Itoa(i)]
		var iter gtk.TreeIter
		mw.ruleStore.Append(&iter, nil)
		mw.ruleStore.SetValue(&iter, 1, rule.Command)
		if rule.AppRule {
			if rule.Scope == "system" {
				mw.ruleStore.SetValue(&iter, 4, rule.Scope)
			} else {
				mw.ruleStore.SetValue(&iter, 4, rule.User)
			}
			mw.ruleStore.SetValue(&iter, 5, actionToString(rule.Action))
		} else {
			for j := 0; j < len(rule.Rules); j++ {
				conn := rule.Rules[strconv.Itoa(j)]
				var connIter gtk.TreeIter
				mw.ruleStore.Append(&connIter, &iter)
				mw.ruleStore.SetValue(&connIter, 2, conn.Ip)
				mw.ruleStore.SetValue(&connIter, 3, conn.Port)
				mw.ruleStore.SetValue(&connIter, 4, conn.User)
				mw.ruleStore.SetValue(&connIter, 5, actionToString(conn.Action))
			}
		}
	}
}

func (mw *ManageWindow) TreeViewActivate() {
	var path *gtk.TreePath
	var column *gtk.TreeViewColumn
	var id string
	var connId string
	mw.ruleTreeview.GetCursor(&path, &column)
	tokens := strings.Split(path.String(), ":")
	if mw.ruleTreeview.RowExpanded(path) {
		mw.ruleTreeview.CollapseRow(path)
	} else {
		mw.ruleTreeview.ExpandRow(path, true)
	}
	if len(tokens) > 1 {
		id = strings.Split(path.String(), ":")[0]
		connId = strings.Split(path.String(), ":")[1]
	} else {
		id = strings.Split(path.String(), ":")[0]
	}

	detail := rules.RuleDetail{}
	if mw.ruleSet[path.String()].AppRule == true {
		detail.AppRule = true
		detail.Command = mw.ruleSet[id].Command
		if mw.ruleSet[id].Scope == "system" {
			detail.User = mw.ruleSet[id].Scope
		} else {
			detail.User = mw.ruleSet[id].User
		}
		detail.Action = mw.ruleSet[id].Action
		mw.detail.SetValues(detail)
		mw.detail.Show()
	} else {
		if connId != "" {
			detail.AppRule = false
			detail.Command = mw.ruleSet[id].Command
			detail.Ip = mw.ruleSet[id].Rules[connId].Ip
			detail.Port = mw.ruleSet[id].Rules[connId].Port
			if mw.ruleSet[id].Rules[connId].Scope == "system" {
				detail.User = mw.ruleSet[id].Rules[connId].Scope
			} else {
				detail.User = mw.ruleSet[id].Rules[connId].User
			}
			detail.Action = mw.ruleSet[id].Rules[connId].Action
			mw.detail.SetValues(detail)
			mw.detail.Show()
		}
	}
}

func (mw *ManageWindow) Show() {
	gdk.ThreadsEnter()
	mw.window.ShowAll()
	gdk.ThreadsLeave()
}
