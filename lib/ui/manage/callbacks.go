package manage

import (
	"fmt"
)

func (mw *ManageWindow) initCallbacks() {
	mw.fileMenuEnable.ConnectTriggered(mw.OnFileMenuEnable)
	mw.fileMenuDisable.ConnectTriggered(mw.OnFileMenuDisable)
	mw.fileMenuClose.ConnectTriggered(mw.OnFileMenuClose)
	mw.ruleMenuAdd.ConnectTriggered(mw.OnRuleMenuAdd)
	mw.ruleMenuEdit.ConnectTriggered(mw.OnRuleMenuEdit)
	mw.ruleMenuDelete.ConnectTriggered(mw.OnRuleMenuDelete)
	mw.helpMenuHelp.ConnectTriggered(mw.OnHelpMenuHelp)
	mw.helpMenuAbout.ConnectTriggered(mw.OnHelpMenuAbout)
}

func (mw *ManageWindow) OnFileMenuEnable(clicked bool) {
	fmt.Printf("File Menu Enable\n")
}

func (mw *ManageWindow) OnFileMenuDisable(clicked bool) {
	fmt.Printf("File Menu Disable\n")
}

func (mw *ManageWindow) OnFileMenuClose(clicked bool) {
	mw.Hide()
}

func (mw *ManageWindow) OnRuleMenuAdd(clicked bool) {
	fmt.Printf("Rule Menu Add\n")
}

func (mw *ManageWindow) OnRuleMenuEdit(clicked bool) {
	fmt.Printf("Rule Menu Edit\n")
}

func (mw *ManageWindow) OnRuleMenuDelete(clicked bool) {
	fmt.Printf("OnRuleMenuDelete\n")
}

func (mw *ManageWindow) OnHelpMenuHelp(clicked bool) {
	fmt.Printf("OnHelpMenuHelp\n")
}

func (mw *ManageWindow) OnHelpMenuAbout(clicked bool) {
	fmt.Printf("OnHelpMenuAbout\n")
}
