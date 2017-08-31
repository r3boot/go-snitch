package manage

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/ipc"
	"github.com/r3boot/go-snitch/lib/ui/detail"
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

func NewManageWindow(dbus *ipc.IPCService) *ManageWindow {
	mw := &ManageWindow{
		dbus:           dbus,
		treeviewExpand: make(map[string]bool),
	}

	builder := gtk.NewBuilder()
	builder.AddFromString(GLADE_DATA)

	mw.ruleStore = gtk.NewTreeStore(glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING)
	mw.ruleTreeview.SetModel(mw.ruleStore.ToTreeModel())

	mw.contextMenu = gtk.NewMenu()

	menuEdit := gtk.NewMenuItemWithLabel("Edit")
	menuEdit.Connect("activate", mw.EditRule)
	mw.contextMenu.Add(menuEdit)

	menuDelete := gtk.NewMenuItemWithLabel("Delete")
	menuDelete.Connect("activate", mw.DeleteRule)
	mw.contextMenu.Add(menuDelete)

	mw.contextMenu.ShowAll()

	return mw
}

func (mw *ManageWindow) OnTreeViewRowSelect() {

}

func (mw *ManageWindow) OnTreeViewRowUnselect() {
	fmt.Printf("OnTreeViewRowUnselect\n")

}

func (mw *ManageWindow) OnFileMenuEnable() {
	fmt.Printf("File Menu Enable\n")
}

func (mw *ManageWindow) OnFileMenuDisable() {

}

func (mw *ManageWindow) OnManageMenuEdit() {
	_, detail := mw.GetRuleDetail()
	if detail == nil {
		return
	}
	mw.detailWindow.SetValues(*detail)
	mw.detailWindow.Show()
}

func (mw *ManageWindow) OnManageMenuDelete() {
	mw.DeleteRule()
}

func (mw *ManageWindow) OnHelpMenuHelp() {
	fmt.Printf("Help Menu Help\n")
}

func (mw *ManageWindow) OnHelpMenuAbout() {
	fmt.Printf("Help Menu About\n")
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

	mw.detailWindow.SetValues(*detail)
	mw.detailWindow.Show()
}

func (mw *ManageWindow) SetDetailWindow(window *detail.ManageDetailWindow) {
	mw.detailWindow = window
}

func (mw *ManageWindow) SetSessionCache(cache *rules.SessionCache) {
	mw.cache = cache
}
