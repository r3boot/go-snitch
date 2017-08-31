package manage

import (
	"fmt"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
	"github.com/r3boot/go-snitch/lib/ui"
	"os"
	"unsafe"
)

func (mw *ManageWindow) initCallbacks(builder *gtk.Builder) {
	mw.window = &gtk.Window{
		*(*gtk.Window)(
			unsafe.Pointer(&builder.GetObject("ManageWindow").Object)),
	}

	builder.ConnectSignalsFull(func(builder *gtk.Builder, obj *glib.GObject,
		sig, handler string, conn *glib.GObject, flags glib.ConnectFlags,
		user_data interface{}) {
		switch handler {
		case "OnFileMenuEnable":
			obj.SignalConnect(sig, mw.OnFileMenuEnable, user_data, flags)
		case "OnFileMenuDisable":
			obj.SignalConnect(sig, mw.OnFileMenuDisable, user_data, flags)
		case "OnClose":
			obj.SignalConnect(sig, mw.OnClose, user_data, flags)
		case "OnRuleMenuAdd":
			obj.SignalConnect(sig, mw.OnRuleMenuAdd, user_data, flags)
		case "OnRuleMenuEdit":
			obj.SignalConnect(sig, mw.OnRuleMenuEdit, user_data, flags)
		case "OnRuleMenuDelete":
			obj.SignalConnect(sig, mw.OnRuleMenuDelete, user_data, flags)
		case "OnHelpMenuGetHelp":
			obj.SignalConnect(sig, mw.OnHelpMenuGetHelp, user_data, flags)
		case "OnHelpMenuAbout":
			obj.SignalConnect(sig, mw.OnHelpMenuAbout, user_data, flags)
		}
	}, nil)
}

func (mw *ManageWindow) OnClose(ctx glib.CallbackContext) {
	mw.window.Hide()
}

func (mw *ManageWindow) OnFileMenuEnable(ctx glib.CallbackContext) {
	fmt.Printf("File Menu Enable\n")
}

func (mw *ManageWindow) OnFileMenuDisable(ctx glib.CallbackContext) {
	fmt.Printf("File Menu Disable\n")
}

func (mw *ManageWindow) OnRuleMenuAdd(ctx glib.CallbackContext) {
	fmt.Printf("Rule Menu Add\n")
}

func (mw *ManageWindow) OnRuleMenuEdit(ctx glib.CallbackContext) {
	_, detail := mw.GetRuleDetail()
	mw.detailWindow.SetValues(*detail)
	mw.detailWindow.Show()
}

func (mw *ManageWindow) OnRuleMenuDelete(ctx glib.CallbackContext) {
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

func (mw *ManageWindow) OnHelpMenuGetHelp(ctx glib.CallbackContext) {

}

func (mw *ManageWindow) OnHelpMenuAbout(ctx glib.CallbackContext) {

}

func (mw *ManageWindow) OnTreeViewRowActivated(ctx glib.CallbackContext) {

}

func (mw *ManageWindow) OnTreeViewCursorChanged(ctx glib.CallbackContext) {
	_, detail := mw.GetRuleDetail()
	if detail != nil {
		mw.manageMenuEdit.SetSensitive(true)
		mw.manageMenuDelete.SetSensitive(true)
	} else {
		mw.manageMenuEdit.SetSensitive(false)
		mw.manageMenuDelete.SetSensitive(false)
	}
}

func (mw *ManageWindow) OnTreeViewUnselectAll(ctx glib.CallbackContext) {
	mw.manageMenuEdit.SetSensitive(false)
	mw.manageMenuDelete.SetSensitive(false)
}

func (mw *ManageWindow) OnTreeViewButtonPressEvent(ctx glib.CallbackContext) {

}
