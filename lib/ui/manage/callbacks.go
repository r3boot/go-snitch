package manage

import (
	"fmt"
	"os"

	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/ui"
)

func (mw *ManageWindow) initCallbacks(builder *gtk.Builder) {
	builder.ConnectSignalsFull(func(builder *gtk.Builder, obj *glib.GObject,
		sig, handler string, conn *glib.GObject, flags glib.ConnectFlags,
		user_data interface{}) {
		switch handler {
		case "OnClose":
			obj.SignalConnect(sig, mw.OnClose, user_data, flags)
		case "OnFileMenuEnable":
			obj.SignalConnect(sig, mw.OnFileMenuEnable, user_data, flags)
		case "OnFileMenuDisable":
			obj.SignalConnect(sig, mw.OnFileMenuDisable, user_data, flags)
		case "OnRuleMenuAdd":
			obj.SignalConnect(sig, mw.OnRuleMenuAdd, user_data, flags)
		case "OnRuleMenuEdit":
			obj.SignalConnect(sig, mw.OnRuleMenuEdit, user_data, flags)
		case "OnRuleMenuDelete":
			obj.SignalConnect(sig, mw.OnRuleMenuDelete, user_data, flags)
		case "OnHelpMenuHelp":
			obj.SignalConnect(sig, mw.OnHelpMenuGetHelp, user_data, flags)
		case "OnHelpMenuAbout":
			obj.SignalConnect(sig, mw.OnHelpMenuAbout, user_data, flags)
		case "OnTreeViewCursorChanged":
			obj.SignalConnect(sig, mw.OnTreeViewCursorChanged, user_data, flags)
		case "OnTreeViewRowActivated":
			obj.SignalConnect(sig, mw.OnTreeViewRowActivated, user_data, flags)
		}
	}, nil)
}

func (mw *ManageWindow) OnClose(ctx *glib.CallbackContext) bool {
	mw.window.Hide()
	return true
}

func (mw *ManageWindow) OnFileMenuEnable(ctx *glib.CallbackContext) {
	fmt.Printf("File Menu Enable\n")
}

func (mw *ManageWindow) OnFileMenuDisable(ctx *glib.CallbackContext) {
	fmt.Printf("File Menu Disable\n")
}

func (mw *ManageWindow) OnRuleMenuAdd(ctx *glib.CallbackContext) {
	fmt.Printf("Rule Menu Add\n")
}

func (mw *ManageWindow) OnRuleMenuEdit(ctx *glib.CallbackContext) {
	_, detail := mw.GetRuleDetail()
	mw.detailDialog.SetValues(*detail)
	mw.detailDialog.Show()
}

func (mw *ManageWindow) OnRuleMenuDelete(ctx *glib.CallbackContext) {
	_, rule := mw.GetRuleDetail()
	switch rule.RuleType {
	case ui.RULE_DB:
		{
			if err := mw.dbus.DeleteRule(rule.Id); err != nil {
				fmt.Fprintf(os.Stderr, "mw.DeleteRule: %v\n", err)
				return
			}
		}
	case ui.RULE_SESSION:
		{
			mw.cache.DeleteRule(rule.Id)
		}
	}

	mw.LoadRules()
	mw.RestoreRowExpand()
}

func (mw *ManageWindow) OnHelpMenuGetHelp(ctx *glib.CallbackContext) {

}

func (mw *ManageWindow) OnHelpMenuAbout(ctx *glib.CallbackContext) {

}

func (mw *ManageWindow) OnTreeViewCursorChanged(ctx *glib.CallbackContext) {
	_, detail := mw.GetRuleDetail()
	if detail != nil {
		mw.ruleMenuEdit.SetSensitive(true)
		mw.ruleMenuDelete.SetSensitive(true)
	} else {
		mw.ruleMenuEdit.SetSensitive(false)
		mw.ruleMenuDelete.SetSensitive(false)
	}
}

func (mw *ManageWindow) OnTreeViewRowActivated(ctx *glib.CallbackContext) {
	path, detail := mw.GetRuleDetail()
	if detail != nil {
		mw.detailDialog.SetValues(*detail)
		mw.detailDialog.Show()
	} else {
		if mw.ruleTreeview.RowExpanded(path) {
			mw.ruleTreeview.CollapseRow(path)
		} else {
			mw.ruleTreeview.ExpandRow(path, true)
		}
	}
}
