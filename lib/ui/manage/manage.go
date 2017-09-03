package manage

import (
	"fmt"
	"unsafe"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui"
	"github.com/r3boot/go-snitch/lib/ui/detail"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
)

func NewManageWindow(dbus *ipc.IPCService, detailDialog *detail.ManageDetailDialog, cache *rules.SessionCache) *ManageWindow {
	mw := &ManageWindow{
		dbus:           dbus,
		detailDialog:   detailDialog,
		cache:          cache,
		treeviewExpand: make(map[string]bool),
	}

	builder := gtk.NewBuilder()
	builder.AddFromString(GLADE_DATA)

	mw.window = ui.ObjectToWindow(builder, "ManageWindow")

	mw.ruleTreeview = ui.ObjectToTreeView(builder, "RuleTreeView")

	column := ui.NewTreeViewColumn("Application", COLUMN_COMMAND)
	column.SetMinWidth(250)
	mw.ruleTreeview.AppendColumn(column)

	column = ui.NewTreeViewColumn("Destination", COLUMN_DESTINATION)
	column.SetMinWidth(250)
	mw.ruleTreeview.AppendColumn(column)

	mw.ruleTreeview.AppendColumn(ui.NewTreeViewColumn("Port", COLUMN_PORT))
	mw.ruleTreeview.AppendColumn(ui.NewTreeViewColumn("Proto", COLUMN_PROTO))
	mw.ruleTreeview.AppendColumn(ui.NewTreeViewColumn("User", COLUMN_USER))
	mw.ruleTreeview.AppendColumn(ui.NewTreeViewColumn("Duration", COLUMN_DURATION))
	mw.ruleTreeview.AppendColumn(ui.NewTreeViewColumn("Action", COLUMN_ACTION))

	mw.ruleStore = gtk.NewTreeStore(glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING)
	mw.ruleTreeview.SetModel(mw.ruleStore.ToTreeModel())

	mw.ruleMenuEdit = ui.ObjectToMenuItem(builder, "RuleMenuEdit")
	mw.ruleMenuDelete = ui.ObjectToMenuItem(builder, "RuleMenuDelete")

	mw.contextMenu = gtk.NewMenu()

	menuEdit := gtk.NewMenuItemWithLabel("Edit")
	menuEdit.Connect("activate", mw.EditRule)
	mw.contextMenu.Add(menuEdit)

	menuDelete := gtk.NewMenuItemWithLabel("Delete")
	menuDelete.Connect("activate", mw.DeleteRule)
	mw.contextMenu.Add(menuDelete)

	mw.contextMenu.ShowAll()

	mw.initCallbacks(builder)

	return mw
}

func (mw *ManageWindow) OnTreeViewRowSelect() {

}

func (mw *ManageWindow) OnTreeViewRowUnselect() {
	fmt.Printf("OnTreeViewRowUnselect\n")

}

func (mw *ManageWindow) HandleRowClick(ctx *glib.CallbackContext) {
	arg := ctx.Args(0)
	event := *(**gdk.EventButton)(unsafe.Pointer(&arg))

	if gdk.EventType(event.Type) == gdk.BUTTON_PRESS && event.Button == 3 {

		path, detail := mw.GetRuleDetail()
		if detail == nil {
			return
		}

		selection := mw.ruleTreeview.GetSelection()
		selection.UnselectAll()
		selection.SelectPath(path)

		mw.contextMenu.Popup(nil, nil, nil, mw.ruleTreeview, uint(0), uint32(0))
	}
}

func (mw *ManageWindow) EditRule() {

}

func (mw *ManageWindow) DeleteRule() {

}

func (mw *ManageWindow) ClearTreeStore() {
	mw.ruleStore.Clear()
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
	path, detail := mw.GetRuleDetail()

	if detail == nil {
		mw.ToggleRowExpand(path)
		return
	}

	mw.detailDialog.SetValues(*detail)
	mw.detailDialog.Show()
}

func (mw *ManageWindow) SetDetailWindow(window *detail.ManageDetailDialog) {
	mw.detailDialog = window
}

func (mw *ManageWindow) SetSessionCache(cache *rules.SessionCache) {
	mw.cache = cache
}
